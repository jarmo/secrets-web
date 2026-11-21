package session

import (
  "crypto/ecdh"
  "net/url"

  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/secret"
  "github.com/jarmo/secrets/storage"
  "github.com/jarmo/secrets/storage/path"
)

type Vault struct {
  Alias string
  Path string
  Password []byte
  Secrets []secret.Secret
  UserKey *ecdh.PrivateKey
}

func (vault Vault) URL() string {
  if vault.UserKey != nil {
    return "/vaults/" + url.PathEscape(vault.Alias)
  }
  return "/secrets"
}

func (vault Vault) RedirectURL() string {
  if vault.UserKey != nil {
    return vault.URL()
  }
  return "/"
}

func (vault Vault) Save(secrets []secret.Secret) error {
  if vault.UserKey != nil {
    return storage.WriteForUser(vault.Path, vault.UserKey, secrets)
  }
  storage.Write(vault.Path, vault.Password, secrets)
  return nil
}

func CreateVault(configurationPath string, c *gin.Context) (Vault, error) {
  alias, password, err := Credentials(c.GetHeader("X-Credentials"))
  if err != nil {
    return Vault{}, err
  }
  vaultPath, err := path.Get(configurationPath, alias)
  if err != nil {
    return Vault{Alias: alias}, err
  }
  secrets, err := storage.Read(vaultPath, password)
  if err != nil {
    return Vault{Alias: alias}, err
  }
  return Vault{Alias: alias, Path: vaultPath, Password: password, Secrets: secrets}, nil
}

