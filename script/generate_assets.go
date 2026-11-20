package main

import (
	"log"
	"os"

	"github.com/jessevdk/go-assets"
)

func main() {
	generator := assets.Generator{PackageName: "generated"}

	for _, path := range os.Args[1:] {
		if err := generator.Add(path); err != nil {
			log.Fatal(err)
		}
	}

	if err := os.MkdirAll("generated", 0755); err != nil {
		log.Fatal(err)
	}

	output, err := os.Create("generated/assets.go")
	if err != nil {
		log.Fatal(err)
	}

	if err := generator.Write(output); err != nil {
		output.Close()
		log.Fatal(err)
	}

	if err := output.Close(); err != nil {
		log.Fatal(err)
	}
}
