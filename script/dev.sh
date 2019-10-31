#!/bin/bash

runApp() {
  if [[ -f tmp/dev.pid ]]; then
    kill `cat tmp/dev.pid` 2>/dev/null || echo "Process not running"
  fi
  make assets && go run secrets-web.go serve --config tmp/config.json --cert dev --cert-priv-key dev --port 8080 --pid tmp/dev.pid &
}

runApp
fswatch --event Created --event Removed --event Updated -r -e "/generated" -e "/vendor" -e ".md" -e ".git/" -e "todo" -e ".sh" -e "bin/" -e ".tmp" -e ".mod" . | while read -r path; do echo "Changed: $path"; runApp; done
