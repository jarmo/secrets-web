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
  secrets-web initialize --config=CONFIG_PATH --path=VAULT_PATH --alias=VAULT_ALIAS
  secrets-web serve --config=CONFIG_PATH --cert=CERT_PATH --cert-priv-key=CERT_PRIVATE_KEY_PATH [--host=HOST] [--port=PORT] [--pid=PID_PATH]

Options:
  --config CONFIG_PATH                      Configuration path for vaults.
  --alias VAULT_ALIAS                       Vault alias.
  --path VAULT_PATH                         Vault path.
  --cert CERT_PATH                          HTTPS certificate path.
  --cert-priv-key CERT_PRIVATE_KEY_PATH     HTTPS certificate private key path.
  --host HOST                               Host to bind to. Defaults to 0.0.0.0.
  --port PORT                               Port to listen on. Defaults to 9090.
  --pid PID_PATH                            Save PID to file.
  -h --help                                 Show this screen.
  -v --version                              Show version.`
}

func createCommand(arguments map[string]interface {}) command.Executable {
  configPath := argument(arguments, "--config")

  if arguments["initialize"].(bool) {
    vaultAlias := argument(arguments, "--alias")
    vaultPath := argument(arguments, "--path")
    return command.Initialize{ConfigurationPath: configPath, VaultAlias: vaultAlias, VaultPath: vaultPath}
  } else if arguments["serve"].(bool) {
    certificatePath := argument(arguments, "--cert")
    certificatePrivKeyPath := argument(arguments, "--cert-priv-key")
    host := argument(arguments, "--host")
    port := argument(arguments, "--port")
    pid := argument(arguments, "--pid")
    return command.Serve{ConfigurationPath: configPath, CertificatePath: certificatePath, CertificatePrivKeyPath: certificatePrivKeyPath, Host: host, Port: port, Pid: pid}
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
