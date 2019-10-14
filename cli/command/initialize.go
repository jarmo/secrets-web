package command

import (
  "fmt"
  "github.com/jarmo/secrets/storage/path"
)

type Initialize struct {
  VaultsConfig string
  VaultPath string
  VaultAlias string
}

func (command Initialize) Execute() {
  configurationPath := path.Store(command.VaultPath, command.VaultAlias)
  fmt.Println(fmt.Sprintf("Vault successfully configured at %s and is ready to store your secrets!", configurationPath))
}

