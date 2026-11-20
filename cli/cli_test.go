package cli

import (
  "testing"
  "github.com/jarmo/secrets-web/cli/command"
)

const version = "1.3.3.7"

func TestCommand_ServeWithoutConfig(t *testing.T) {
  parsedCommand := Command(version, []string{"serve", "--cert", "cert", "--cert-priv-key", "key"}).(command.Serve)
  if parsedCommand.ConfigurationPath != "" {
    t.Fatalf("Expected default configuration path, got %q", parsedCommand.ConfigurationPath)
  }
  if parsedCommand.MembersDirectory != "" {
    t.Fatalf("Expected default member directory, got %q", parsedCommand.MembersDirectory)
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

func TestCommand_ServeWithMembersDirectory(t *testing.T) {
  parsedCommand := Command(version, []string{
    "serve", "--config", "config-path", "--cert", "cert", "--cert-priv-key", "key", "--members-dir", "/private/members",
  }).(command.Serve)
  if parsedCommand.MembersDirectory != "/private/members" {
    t.Fatalf("Expected member directory, got %q", parsedCommand.MembersDirectory)
  }
}
