package main

import (
  "os"
  "github.com/jarmo/secrets-web/cli"
)

const VERSION = "1.4.1"

var version = "v" + VERSION

func main() {
  cli.Command("secrets-web " + version, os.Args[1:]).Execute()
}

