BINARY = secrets-web
GOARCH = amd64
GO_BUILD = GOARCH=${GOARCH} go build -mod=vendor
PREFIX ?= ${GOPATH}

all: clean vendor test linux darwin windows

clean:
	rm -rf bin/
	rm -rf generated/assets.go

vendor: assets
	go mod vendor
	go mod tidy

assets:
	go-assets-builder -p generated -o generated/assets.go assets templates/views

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
	script/dev.sh

dev_run: vendor
	go run secrets-web.go serve --config tmp/conf-dev.json --cert none --cert-priv-key none --port 8080 --pid tmp/dev.pid

release: all
	script/release.sh

.PHONY: all test clean release vendor assets linux darwin windows install dev dev_run
