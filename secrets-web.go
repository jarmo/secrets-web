package main

import (
  "os"
  "github.com/jarmo/secrets-web/cli"
)

const VERSION = "1.2.2"

func main() {
  cli.Command(VERSION, os.Args[1:]).Execute()
}

