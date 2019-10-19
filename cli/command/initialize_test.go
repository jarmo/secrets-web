package command

import (
  "os"
  "io/ioutil"
  "testing"

  "github.com/jarmo/secrets/storage/path"
)

func TestInitialize_Execute(t *testing.T) {
  configPath := tempFilePath(t, "test-secrets-config")
  defer os.Remove(configPath)

  vaultPath := tempFilePath(t, "test-secrets-vault")
  defer os.Remove(vaultPath)

  Initialize{ConfigurationPath: configPath, VaultPath: vaultPath, VaultAlias: "vault-alias"}.Execute()

  actualVaultPath, err := path.Get(configPath, "vault-alias")
  if err != nil {
    t.Fatal(err)
  }

  if vaultPath != actualVaultPath {
    t.Fatalf("Expected vault path to be '%v', but was '%v'", vaultPath, actualVaultPath)
  }
}

func tempFilePath(t *testing.T, prefix string) string {
  path, err := ioutil.TempFile("", "test-secrets-vault")
  if err != nil {
    t.Fatal(err)
  }
  return path.Name()
}
