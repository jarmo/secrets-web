package command

import (
  "path/filepath"
  "testing"
)

func TestResolveStoragePaths(t *testing.T) {
  configHome := t.TempDir()
  t.Setenv("XDG_CONFIG_HOME", configHome)

  configPath, usersDirectory, err := resolveStoragePaths("", "")
  if err != nil {
    t.Fatal(err)
  }
  if expected := filepath.Join(configHome, "secrets", "config.json"); configPath != expected {
    t.Fatalf("Expected configuration path %q, got %q", expected, configPath)
  }
  if expected := filepath.Join(configHome, "secrets", "users"); usersDirectory != expected {
    t.Fatalf("Expected user directory %q, got %q", expected, usersDirectory)
  }

  configPath, usersDirectory, err = resolveStoragePaths("/custom/config.json", "")
  if err != nil {
    t.Fatal(err)
  }
  if configPath != "/custom/config.json" || usersDirectory != filepath.Join(configHome, "secrets", "users") {
    t.Fatalf("Unexpected paths: %q, %q", configPath, usersDirectory)
  }

  configPath, usersDirectory, err = resolveStoragePaths("", "/private/users")
  if err != nil {
    t.Fatal(err)
  }
  if configPath != filepath.Join(configHome, "secrets", "config.json") || usersDirectory != "/private/users" {
    t.Fatalf("Unexpected paths: %q, %q", configPath, usersDirectory)
  }
}

func TestResolveStoragePathsWithoutXDG(t *testing.T) {
  home := t.TempDir()
  t.Setenv("XDG_CONFIG_HOME", "")
  t.Setenv("HOME", home)

  configPath, usersDirectory, err := resolveStoragePaths("", "")
  if err != nil {
    t.Fatal(err)
  }
  expectedDirectory := filepath.Join(home, ".config", "secrets")
  if configPath != filepath.Join(expectedDirectory, "config.json") || usersDirectory != filepath.Join(expectedDirectory, "users") {
    t.Fatalf("Unexpected paths: %q, %q", configPath, usersDirectory)
  }
}

func TestResolveStoragePathsWithExplicitOverrides(t *testing.T) {
  t.Setenv("XDG_CONFIG_HOME", "")
  t.Setenv("HOME", "")
  t.Setenv("USERPROFILE", "")

  configPath, usersDirectory, err := resolveStoragePaths("/custom/config.json", "/custom/users")
  if err != nil {
    t.Fatal(err)
  }
  if configPath != "/custom/config.json" || usersDirectory != "/custom/users" {
    t.Fatalf("Unexpected paths: %q, %q", configPath, usersDirectory)
  }

  if _, _, err := resolveStoragePaths("", ""); err == nil {
    t.Fatal("Expected an error without an XDG or home directory")
  }
}

func TestTLSModeDoesNotDependOnExecutableLocation(t *testing.T) {
  for _, tc := range []struct {
    certificate, key string
    tls, valid       bool
  }{
    {"cert.pem", "key.pem", true, true},
    {"none", "none", false, true},
    {"none", "key.pem", false, false},
    {"cert.pem", "none", false, false},
    {"", "", false, false},
  } {
    enabled, err := useTLS(tc.certificate, tc.key)
    if (err == nil) != tc.valid || enabled != tc.tls {
      t.Fatalf("TLS selection for %q/%q: %v %v", tc.certificate, tc.key, enabled, err)
    }
  }
}

func TestDevelopmentHTTPCannotListenPublicly(t *testing.T) {
  err := serveUntilExit(Serve{CertificatePath: "none", CertificatePrivKeyPath: "none", Host: "0.0.0.0"})
  if err == nil {
    t.Fatal("Development HTTP accepted public binding")
  }
}
