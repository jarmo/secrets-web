package command

import (
  "fmt"
  "github.com/jarmo/secrets-web/storage/path"
)

type Initialize struct {
  ConfigurationPath string
  VaultPath string
  VaultAlias string
}

func (command Initialize) Execute() {
  path.Store(command.ConfigurationPath, command.VaultPath, command.VaultAlias)
  fmt.Println("Vault successfully initialized!")
}

