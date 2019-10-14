package cli

import (
  "github.com/docopt/docopt-go"
  "github.com/jarmo/secrets-web/cli/command"
)

func Command(version string, args []string) command.Executable {
  arguments, _ := docopt.Parse(createUsage(), args, true, version, false)
  return createCommand(arguments)
}

func createUsage() string {
  return `secrets-web COMMAND [OPTIONS]

Usage:
  secrets-web initialize --vaults-config=CONFIG_PATH --path=VAULT_PATH --alias=VAULT_ALIAS
  secrets-web serve

Options:
  --vaults-config CONFIG_PATH     Vaults configuration path.
  --alias VAULT_ALIAS             Vault alias.
  --path VAULT_PATH               Vault path.
  -h --help                       Show this screen.
  -v --version                    Show version.`
}

func createCommand(arguments map[string]interface {}) command.Executable {
  vaultsConfig := argument(arguments, "--vaults-config")
  vaultAlias := argument(arguments, "--alias")
  vaultPath := argument(arguments, "--path")

  if arguments["initialize"].(bool) {
		return command.Initialize{VaultsConfig: vaultsConfig, VaultAlias: vaultAlias, VaultPath: vaultPath}
  } else if arguments["serve"].(bool) {
  	return command.Serve{}
  } else {
    return nil
  }
}

func argument(arguments map[string]interface {}, name string) string {
  if value, hasValue := arguments[name].(string); hasValue {
    return value
  } else {
    return ""
  }
}
