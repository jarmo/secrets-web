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
    memberSession := c.MustGet("memberSession").(session.MemberSession)
    alias := c.Param("alias")
    vaultPath, err := path.Get(configurationPath, alias)
    if err != nil {
      c.AbortWithStatus(http.StatusNotFound)
      return
    }
    secrets, err := storage.ReadForMember(vaultPath, memberSession.PrivateKey)
    if err != nil {
      c.AbortWithStatus(http.StatusNotFound)
      return
    }
    c.Set("session", session.Vault{Alias: alias, Path: vaultPath, MemberKey: memberSession.PrivateKey, Secrets: secrets})
    c.Next()
  }
}
