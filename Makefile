dev:
	chokidar "main.go" "assets/**/*" "templates/**/*" --initial -c "/usr/bin/pkill -f go; go-assets-builder -o assets.go assets templates && go run *.go"

.PHONY: dev
