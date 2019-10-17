package session

import (
  "encoding/base64"
  "errors"
  "strings"

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
}

const MaxAgeInSeconds = 15 * 60

func Create(configurationPath string, c *gin.Context) (Vault, error) {
  if decodedCredentialsHeader, err := base64.StdEncoding.DecodeString(c.GetHeader("X-Credentials")); err != nil {
    return Vault{}, errors.New("Invalid X-Credentials header")
  } else if len(decodedCredentialsHeader) == 0 {
    return Vault{}, errors.New("No X-Credentials header value")
  } else {
    credentials := strings.Split(string(decodedCredentialsHeader), ":")
    vaultAlias := credentials[0]

    if len(credentials) != 2 {
      return Vault{Alias: vaultAlias}, errors.New("Invalid X-Credentials header value")
    } else {
      password := credentials[1]
      if path, aliasErr := path.Get(configurationPath, vaultAlias); aliasErr != nil {
        return Vault{Alias: vaultAlias}, aliasErr
      } else {
        if secrets, vaultErr := storage.Read(path, []byte(password)); vaultErr != nil {
          return Vault{Alias: vaultAlias}, vaultErr
        } else {
          return Vault{Alias: vaultAlias, Path: path, Password: []byte(password), Secrets: secrets}, nil
        }
      }
    }
  }
}

