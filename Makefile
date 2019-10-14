BINARY = secrets-web
GOARCH = amd64
GO_BUILD = GOARCH=${GOARCH} go build -mod=vendor
PREFIX ?= ${GOPATH}

all: clean linux darwin windows

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

install:
	cp -Rf bin/ "${PREFIX}/bin"

dev:
	chokidar "secrets-web.go" "assets/**/*" "templates/**/*" --initial -c "/usr/bin/pkill go; go-assets-builder -o assets.go assets templates && go run *.go"

.PHONY: all clean vendor linux darwin windows install dev
