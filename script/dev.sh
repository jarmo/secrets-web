#!/usr/bin/env bash

runApp() {
  if [[ -f tmp/dev.pid ]]; then
    kill `cat tmp/dev.pid` 2>/dev/null || echo "Process not running"
  fi
  make dev_run &
}

runApp
fswatch -l 0.1 -o --event Created --event Removed --event Updated -r -e "/generated" -e "/vendor" -e "README.md" -e ".git/" -e "todo" -e "/script" -e "bin/" -e "/tmp" -e "go\\.mod" . | while read -r path; do echo "Changed: $path"; runApp; done
