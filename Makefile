BINARY = secrets-web
GOARCH = amd64
GO_BUILD = GOARCH=${GOARCH} go build -mod=vendor
PREFIX ?= ${GOPATH}

all: clean test linux darwin windows

clean:
	rm -rf bin/

vendor:
	go mod vendor

linux: vendor
	GOOS=linux ${GO_BUILD} -o bin/linux_${GOARCH}/${BINARY}

darwin: vendor
	GOOS=darwin ${GO_BUILD} -o bin/darwin_${GOARCH}/${BINARY}

windows: vendor
	GOOS=windows ${GO_BUILD} -o bin/windows_${GOARCH}/${BINARY}.exe

test: vendor
	script/run_tests.sh

install:
	cp -Rf bin/ "${PREFIX}/bin"

dev:
	chokidar "**/*.go" "assets/**/*" "templates/**/*" -i "generated/assets.go" --initial -c "/usr/bin/pkill -f secrets-web; go-assets-builder -p generated -o generated/assets.go assets templates && go run secrets-web.go serve"

.PHONY: all test clean vendor linux darwin windows install dev
