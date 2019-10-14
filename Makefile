BINARY = secrets-web
GOARCH = amd64
GO_BUILD = GOARCH=${GOARCH} go build -mod=vendor
PREFIX ?= ${GOPATH}

all: clean assets test linux darwin windows

clean:
	rm -rf bin/

vendor:
	go mod vendor

assets: vendor
	go-assets-builder -p generated -o generated/assets.go assets templates

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
	chokidar "**/*.go" "assets/**/*" "templates/**/*" -i "generated/assets.go" -i "vendor/**/*.go" --initial -c "/usr/bin/pkill -f secrets-web; make assets && go run secrets-web.go serve --config tmp/config.json --cert dev --cert-priv-key dev"

.PHONY: all test clean vendor assets linux darwin windows install dev
