#!/usr/bin/env bash

set -euo pipefail

if [[ $# -gt 1 || ( $# -eq 1 && "$1" != "--check" ) ]]; then
  echo "Usage: $0 [--check]" >&2
  exit 2
fi

for command in git http jq zip shasum; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Cannot release - missing required command: $command" >&2
    exit 1
  fi
done

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Cannot release - uncommitted changes found!" >&2
  exit 1
fi

VERSION="v$(sed -n 's/^const VERSION = "\([^" ]*\)"/\1/p' secrets-web.go)"
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Cannot release - missing or invalid VERSION constant in secrets-web.go!" >&2
  exit 1
fi
: "${GITHUB_RELEASE_TOKEN:?Set GITHUB_RELEASE_TOKEN before releasing}"

# Catch an unchanged VERSION before building; the GitHub API still creates the tag.
REMOTE_TAG=$(git ls-remote --tags origin "refs/tags/$VERSION")
if [[ -n "$REMOTE_TAG" ]]; then
  echo "Cannot release $VERSION - tag already exists. Bump VERSION first." >&2
  exit 1
fi

if [[ "${1:-}" == "--check" ]]; then
  echo "Release prerequisites OK for $VERSION"
  exit 0
fi

# Prepare and verify artifacts before creating a permanent remote tag.
for platform in linux freebsd openbsd darwin windows; do
  suffix=""
  [[ "$platform" == "windows" ]] && suffix=".exe"
  file="bin/${platform}_amd64/secrets-web${suffix}"
  if [[ ! -s "$file" ]]; then
    echo "Cannot release - missing or empty binary: $file" >&2
    exit 1
  fi
done

read -rp "Enter changelog to release version $VERSION: " CHANGELOG
if [[ -z "$CHANGELOG" ]]; then
  echo "Cannot release - changelog cannot be empty!" >&2
  exit 1
fi

rm -rf dist
mkdir -p dist
for file in bin/*/*; do
  [[ -f "$file" ]] || continue
  DIST_FILE_BASE="$(basename "$file")-$(basename "$(dirname "$file")")"
  DIST_FILE_NAME="$DIST_FILE_BASE-$VERSION.zip"
  zip -q -j "dist/$DIST_FILE_NAME" "$file"
  (cd dist && shasum -a 512 "$DIST_FILE_NAME" > "$DIST_FILE_NAME.sha512")
done

git push
SHA=$(git rev-parse HEAD)
if ! http --check-status -b POST "https://api.github.com/repos/jarmo/secrets-web/git/refs" Authorization:"Bearer $GITHUB_RELEASE_TOKEN" ref="refs/tags/$VERSION" sha="$SHA"; then
  echo "Cannot release $VERSION: GitHub rejected the tag. If it already exists, bump VERSION first." >&2
  exit 1
fi

RESPONSE=$(http --check-status -b POST "https://api.github.com/repos/jarmo/secrets-web/releases" Authorization:"Bearer $GITHUB_RELEASE_TOKEN" tag_name="$VERSION" draft:=true name="secrets-web $VERSION" body="$CHANGELOG")
RELEASE_ID=$(echo "$RESPONSE" | jq -er .id)

for file in dist/*; do
  http --check-status -b POST "https://uploads.github.com/repos/jarmo/secrets-web/releases/$RELEASE_ID/assets?name=$(basename "$file")" Authorization:"Bearer $GITHUB_RELEASE_TOKEN" Content-Type:application/octet-stream "@$file" > /dev/null
done

RESPONSE=$(http --check-status -b PATCH "https://api.github.com/repos/jarmo/secrets-web/releases/$RELEASE_ID" Authorization:"Bearer $GITHUB_RELEASE_TOKEN" draft:=false)

echo "Release done:"
echo "$RESPONSE" | jq -r .html_url
