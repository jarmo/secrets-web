#!/usr/env/bin bash

set -o pipefail
go test -mod=vendor -v ./... | grep -v "no test files" | grep -v "=== RUN" | grep -v "\[GIN\]" | sed ''/PASS/s//$(printf "\033[32mPASS\033[0m")/'' | sed ''/FAIL/s//$(printf "\033[31mFAIL\033[0m")/''
