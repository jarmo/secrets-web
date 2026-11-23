package main

import (
  "os"
  "github.com/jarmo/secrets-web/cli"
)

const VERSION = "2.1.0"

var version = "v" + VERSION

func main() {
  cli.Command("secrets-web " + version, os.Args[1:]).Execute()
}

