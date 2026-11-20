package command

import (
  "path/filepath"
  "testing"
)

func TestResolveStoragePaths(t *testing.T) {
  configHome := t.TempDir()
  t.Setenv("XDG_CONFIG_HOME", configHome)

  configPath, membersDirectory, err := resolveStoragePaths("", "")
  if err != nil {
    t.Fatal(err)
  }
  if expected := filepath.Join(configHome, "secrets", "config.json"); configPath != expected {
    t.Fatalf("Expected configuration path %q, got %q", expected, configPath)
  }
  if expected := filepath.Join(configHome, "secrets", "members"); membersDirectory != expected {
    t.Fatalf("Expected member directory %q, got %q", expected, membersDirectory)
  }

  configPath, membersDirectory, err = resolveStoragePaths("/custom/config.json", "")
  if err != nil {
    t.Fatal(err)
  }
  if configPath != "/custom/config.json" || membersDirectory != filepath.Join(configHome, "secrets", "members") {
    t.Fatalf("Unexpected paths: %q, %q", configPath, membersDirectory)
  }

  configPath, membersDirectory, err = resolveStoragePaths("", "/private/members")
  if err != nil {
    t.Fatal(err)
  }
  if configPath != filepath.Join(configHome, "secrets", "config.json") || membersDirectory != "/private/members" {
    t.Fatalf("Unexpected paths: %q, %q", configPath, membersDirectory)
  }
}

func TestResolveStoragePathsWithoutXDG(t *testing.T) {
  home := t.TempDir()
  t.Setenv("XDG_CONFIG_HOME", "")
  t.Setenv("HOME", home)

  configPath, membersDirectory, err := resolveStoragePaths("", "")
  if err != nil {
    t.Fatal(err)
  }
  expectedDirectory := filepath.Join(home, ".config", "secrets")
  if configPath != filepath.Join(expectedDirectory, "config.json") || membersDirectory != filepath.Join(expectedDirectory, "members") {
    t.Fatalf("Unexpected paths: %q, %q", configPath, membersDirectory)
  }
}

func TestResolveStoragePathsWithExplicitOverrides(t *testing.T) {
  t.Setenv("XDG_CONFIG_HOME", "")
  t.Setenv("HOME", "")
  t.Setenv("USERPROFILE", "")

  configPath, membersDirectory, err := resolveStoragePaths("/custom/config.json", "/custom/members")
  if err != nil {
    t.Fatal(err)
  }
  if configPath != "/custom/config.json" || membersDirectory != "/custom/members" {
    t.Fatalf("Unexpected paths: %q, %q", configPath, membersDirectory)
  }

  if _, _, err := resolveStoragePaths("", ""); err == nil {
    t.Fatal("Expected an error without an XDG or home directory")
  }
}
