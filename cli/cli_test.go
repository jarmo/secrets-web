package cli

import (
  "testing"
  "github.com/jarmo/secrets-web/cli/command"
)

const version = "1.3.3.7"

func TestCommand_Initialize(t *testing.T) {
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

func TestCommand_Serve(t *testing.T) {
  configPath := "config-path"
  cert := "cert"
  certKey := "cert-key"

  switch parsedCommand := Command(version, []string{"serve", "--config", configPath, "--cert", cert, "--cert-priv-key", certKey}).(type) {
    case command.Serve:
      if parsedCommand.ConfigurationPath != configPath {
        t.Fatalf("Expected configuration path to be '%v', but was '%v'", configPath, parsedCommand.ConfigurationPath)
      }
      if parsedCommand.CertificatePath != cert {
        t.Fatalf("Expected certificate path to be '%v', but was '%v'", cert, parsedCommand.CertificatePath)
      }
      if parsedCommand.CertificatePrivKeyPath != certKey {
        t.Fatalf("Expected certificate private key path to be '%v', but was '%v'", certKey, parsedCommand.CertificatePrivKeyPath)
      }
      if parsedCommand.Host != "" {
        t.Fatalf("Expected host to be not set, but was '%v'", parsedCommand.Host)
      }
      if parsedCommand.Port != "" {
        t.Fatalf("Expected port to be not set, but was '%v'", parsedCommand.Port)
      }
      if parsedCommand.Pid != "" {
        t.Fatalf("Expected pid to be not set, but was '%v'", parsedCommand.Pid)
      }
    default:
      t.Fatalf("Got unexpected command: %T", parsedCommand)
  }
}

func TestCommand_ServeWithHost(t *testing.T) {
  configPath := "config-path"
  cert := "cert"
  certKey := "cert-key"
  host := "1.2.3.4"

  switch parsedCommand := Command(version, []string{"serve", "--config", configPath, "--cert", cert, "--cert-priv-key", certKey, "--host", host}).(type) {
    case command.Serve:
      if parsedCommand.ConfigurationPath != configPath {
        t.Fatalf("Expected configuration path to be '%v', but was '%v'", configPath, parsedCommand.ConfigurationPath)
      }
      if parsedCommand.CertificatePath != cert {
        t.Fatalf("Expected certificate path to be '%v', but was '%v'", cert, parsedCommand.CertificatePath)
      }
      if parsedCommand.CertificatePrivKeyPath != certKey {
        t.Fatalf("Expected certificate private key path to be '%v', but was '%v'", certKey, parsedCommand.CertificatePrivKeyPath)
      }
      if parsedCommand.Host != host {
        t.Fatalf("Expected host to be '%v', but was '%v'", host, parsedCommand.Host)
      }
      if parsedCommand.Port != "" {
        t.Fatalf("Expected port to be not set, but was '%v'", parsedCommand.Port)
      }
      if parsedCommand.Pid != "" {
        t.Fatalf("Expected pid to be not set, but was '%v'", parsedCommand.Pid)
      }
    default:
      t.Fatalf("Got unexpected command: %T", parsedCommand)
  }
}

func TestCommand_ServeWithPort(t *testing.T) {
  configPath := "config-path"
  cert := "cert"
  certKey := "cert-key"
  port := "1234"

  switch parsedCommand := Command(version, []string{"serve", "--config", configPath, "--cert", cert, "--cert-priv-key", certKey, "--port", port}).(type) {
    case command.Serve:
      if parsedCommand.ConfigurationPath != configPath {
        t.Fatalf("Expected configuration path to be '%v', but was '%v'", configPath, parsedCommand.ConfigurationPath)
      }
      if parsedCommand.CertificatePath != cert {
        t.Fatalf("Expected certificate path to be '%v', but was '%v'", cert, parsedCommand.CertificatePath)
      }
      if parsedCommand.CertificatePrivKeyPath != certKey {
        t.Fatalf("Expected certificate private key path to be '%v', but was '%v'", certKey, parsedCommand.CertificatePrivKeyPath)
      }
      if parsedCommand.Port != port {
        t.Fatalf("Expected port to be '%v', but was '%v'", port, parsedCommand.Port)
      }
      if parsedCommand.Pid != "" {
        t.Fatalf("Expected pid to be not set, but was '%v'", parsedCommand.Pid)
      }
    default:
      t.Fatalf("Got unexpected command: %T", parsedCommand)
  }
}

func TestCommand_ServeWithPid(t *testing.T) {
  configPath := "config-path"
  cert := "cert"
  certKey := "cert-key"
  pid := "pid-path"

  switch parsedCommand := Command(version, []string{"serve", "--config", configPath, "--cert", cert, "--cert-priv-key", certKey, "--pid", pid}).(type) {
    case command.Serve:
      if parsedCommand.ConfigurationPath != configPath {
        t.Fatalf("Expected configuration path to be '%v', but was '%v'", configPath, parsedCommand.ConfigurationPath)
      }
      if parsedCommand.CertificatePath != cert {
        t.Fatalf("Expected certificate path to be '%v', but was '%v'", cert, parsedCommand.CertificatePath)
      }
      if parsedCommand.CertificatePrivKeyPath != certKey {
        t.Fatalf("Expected certificate private key path to be '%v', but was '%v'", certKey, parsedCommand.CertificatePrivKeyPath)
      }
      if parsedCommand.Port != "" {
        t.Fatalf("Expected port to be not set, but was '%v'", parsedCommand.Port)
      }
      if parsedCommand.Pid != pid {
        t.Fatalf("Expected pid to be '%v', but was '%v'", pid, parsedCommand.Pid)
      }
    default:
      t.Fatalf("Got unexpected command: %T", parsedCommand)
  }
}
