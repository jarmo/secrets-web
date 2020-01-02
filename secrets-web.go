package main

import (
  "os"
  "github.com/jarmo/secrets-web/cli"
)

const VERSION = "1.0.0"

func main() {
  cli.Command(VERSION, os.Args[1:]).Execute()
}

