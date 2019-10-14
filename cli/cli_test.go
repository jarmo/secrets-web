package cli

import (
  "testing"
  "github.com/jarmo/secrets-web/cli/command"
)

const version = "1.3.3.7"

func TestExecute_Initialize(t *testing.T) {
  configPath := "/vaults"
  vaultPath := "/foo/bar/baz"
  vaultAlias := "foo-bar"

  switch parsedCommand := Command(version, []string{"initialize", "--config", configPath, "--path", vaultPath, "--alias", vaultAlias}).(type) {
    case command.Initialize:
      if parsedCommand.ConfigurationPath !=  configPath {
        t.Fatalf("Expected config path to be '%v', but was '%v'", configPath, parsedCommand.ConfigurationPath)
      }
      if parsedCommand.VaultPath != vaultPath {
        t.Fatalf("Expected vault path to be '%v', but was '%v'", vaultPath, parsedCommand.VaultPath)
      }
      if parsedCommand.VaultAlias != vaultAlias {
        t.Fatalf("Expected VaultAlias to be '%v' but was: '%v'", vaultAlias, parsedCommand.VaultAlias)
      }
    default:
      t.Fatalf("Got unexpected command: %T", parsedCommand)
  }
}

func TestExecute_Serve(t *testing.T) {
  cert := "cert"
  certKey := "cert-key"

  switch parsedCommand := Command(version, []string{"serve", "--cert", cert, "--cert-priv-key", certKey}).(type) {
    case command.Serve:
      if parsedCommand.CertificatePath != cert {
        t.Fatalf("Expected certificate path to be '%v', but was '%v'", cert, parsedCommand.CertificatePath)
      }
      if parsedCommand.CertificatePrivKeyPath != certKey {
        t.Fatalf("Expected certificate private key path to be '%v', but was '%v'", certKey, parsedCommand.CertificatePrivKeyPath)
      }
    default:
      t.Fatalf("Got unexpected command: %T", parsedCommand)
  }
}
