#!/usr/bin/env bash

set -euo pipefail

if [[ $(git status --porcelain | wc -c) -ne 0 ]]; then
  echo "Cannot release - uncommitted changes found!"
  exit 1
fi

VERSION="v$(sed -n 's/^const VERSION = "\([^" ]*\)"/\1/p' secrets-web.go)"
if [[ "$VERSION" == "v" ]]; then
  echo "Cannot release - missing VERSION constant in secrets-web.go!" >&2
  exit 1
fi
: "${GITHUB_RELEASE_TOKEN:?Set GITHUB_RELEASE_TOKEN before releasing}"

git push
SHA=$(git rev-parse HEAD)
if ! http --check-status -b POST "https://api.github.com/repos/jarmo/secrets-web/git/refs" Authorization:"token $GITHUB_RELEASE_TOKEN" ref="refs/tags/$VERSION" sha="$SHA"; then
  echo "Cannot release $VERSION: GitHub rejected the tag. If it already exists, bump VERSION in secrets-web.go first." >&2
  exit 1
fi

read -rp "Enter changelog to release version $VERSION: " CHANGELOG
RESPONSE=$(http --check-status -b POST "https://api.github.com/repos/jarmo/secrets-web/releases" Authorization:"token $GITHUB_RELEASE_TOKEN" tag_name="$VERSION" draft:=true name="secrets-web $VERSION" body="$CHANGELOG")
RELEASE_ID=$(echo "$RESPONSE" | jq -er .id)

rm -rf dist
mkdir -p dist

for file in `find bin -type f`; do
  DIST_FILE_BASE=`echo $file | awk -F "/" '{name=$3 "-" $2; print name}'`
  DIST_FILE_PATH=dist/$DIST_FILE_BASE-$VERSION.zip
  zip -j $DIST_FILE_PATH $file
  shasum -a 512 $DIST_FILE_PATH > $DIST_FILE_PATH.sha512
done

for file in `ls -d dist/*`; do
  http --check-status -b POST "https://uploads.github.com/repos/jarmo/secrets-web/releases/$RELEASE_ID/assets?name=`basename $file`" Authorization:"token $GITHUB_RELEASE_TOKEN" @$file > /dev/null
done

RESPONSE=`http --check-status -b PATCH "https://api.github.com/repos/jarmo/secrets-web/releases/$RELEASE_ID" Authorization:"token $GITHUB_RELEASE_TOKEN" draft:=false`

echo "Release done:"
echo $RESPONSE | jq -r .html_url
