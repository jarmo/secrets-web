BINARY = secrets-web
GOARCH = amd64
GO_BUILD = GOARCH=${GOARCH} go build -mod=vendor
PREFIX ?= ${GOPATH}

all: clean assets test linux darwin windows

clean:
	rm -rf bin/

vendor:
	go mod vendor
	go mod tidy

assets: vendor
	go-assets-builder -p generated -o generated/assets.go assets templates/views

linux: assets
	GOOS=linux ${GO_BUILD} -o bin/linux_${GOARCH}/${BINARY}

darwin: assets
	GOOS=darwin ${GO_BUILD} -o bin/darwin_${GOARCH}/${BINARY}

windows: assets
	GOOS=windows ${GO_BUILD} -o bin/windows_${GOARCH}/${BINARY}.exe

test: assets
	script/run_tests.sh

install:
	cp -Rf bin/ "${PREFIX}/bin"

dev:
	script/dev.sh

dev_run: assets
	go run secrets-web.go serve --config tmp/conf-dev.json --cert none --cert-priv-key none --port 8080 --pid tmp/dev.pid

release: all
	script/release.sh

.PHONY: all test clean release vendor assets linux darwin windows install dev dev_run
