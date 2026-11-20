BINARY = secrets-web
INSTALL_DIR ?= $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)
GOARCH = amd64
GO_BUILD = GOARCH=${GOARCH} go build -mod=vendor

all: clean vendor test linux freebsd openbsd darwin windows

clean:
	rm -rf bin/
	rm -rf generated/assets.go

vendor: assets
	go mod tidy
	go mod vendor

assets:
	go run -mod=mod script/generate_assets.go assets templates/views

linux: vendor
	GOOS=linux ${GO_BUILD} -o bin/linux_${GOARCH}/${BINARY}

freebsd: vendor
	GOOS=freebsd ${GO_BUILD} -o bin/freebsd_${GOARCH}/${BINARY}

openbsd: vendor
	GOOS=openbsd ${GO_BUILD} -o bin/openbsd_${GOARCH}/${BINARY}

darwin: vendor
	GOOS=darwin ${GO_BUILD} -o bin/darwin_${GOARCH}/${BINARY}

windows: vendor
	GOOS=windows ${GO_BUILD} -o bin/windows_${GOARCH}/${BINARY}.exe

test: vendor
	script/run_tests.sh

install: vendor
	install -d "$(INSTALL_DIR)"
	go build -mod=vendor -o "$(INSTALL_DIR)/$(BINARY)" .

dev:
	script/dev.sh

dev_run: vendor
	XDG_CONFIG_HOME=$(CURDIR)/tmp go run secrets-web.go serve --cert none --cert-priv-key none --port 8080 --pid tmp/dev.pid

release: all
	script/release.sh

.PHONY: all clean vendor assets linux freebsd openbsd darwin windows test install dev dev_run release
