package handlers

import (
  "net/http"

  "github.com/gin-contrib/sessions"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/storage"
  "github.com/jarmo/secrets/storage/path"
  "github.com/jarmo/secrets-web/middleware"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/templates"
)

func Vaults(configurationPath string) gin.HandlerFunc {
  return func(c *gin.Context) {
    userSession := c.MustGet("userSession").(session.UserSession)
    aliases, err := path.Aliases(configurationPath)
    if err != nil {
      c.Status(http.StatusInternalServerError)
      return
    }
    accessible := make([]string, 0, len(aliases))
    for _, alias := range aliases {
      vaultPath, err := path.Get(configurationPath, alias)
      if err != nil {
        continue
      }
      if _, err := storage.ReadForUser(vaultPath, userSession.PrivateKey); err == nil {
        accessible = append(accessible, alias)
      }
    }
    c.HTML(http.StatusOK, templates.Path("vaults"), gin.H{
      "username": userSession.Username,
      "vaults": accessible,
      "csrfToken": middleware.CsrfToken(sessions.Default(c)),
      "sessionMaxAgeInSeconds": session.MaxAgeInSeconds,
    })
  }
}

