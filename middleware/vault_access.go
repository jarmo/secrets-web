package middleware

import (
  "net/http"

  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/storage"
  "github.com/jarmo/secrets/storage/path"
  "github.com/jarmo/secrets-web/session"
)

func VaultAccess(configurationPath string) gin.HandlerFunc {
  return func(c *gin.Context) {
    userSession := c.MustGet("userSession").(session.UserSession)
    alias := c.Param("alias")
    vaultPath, err := path.Get(configurationPath, alias)
    if err != nil {
      c.AbortWithStatus(http.StatusNotFound)
      return
    }
    secrets, err := storage.ReadForUser(vaultPath, userSession.PrivateKey)
    if err != nil {
      c.AbortWithStatus(http.StatusNotFound)
      return
    }
    c.Set("session", session.Vault{Alias: alias, Path: vaultPath, UserKey: userSession.PrivateKey, Secrets: secrets})
    c.Next()
  }
}
