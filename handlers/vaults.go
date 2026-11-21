package handlers

import (
  "crypto/ecdh"
  "net/http"
  "net/url"
  "os"
  "sort"

  "github.com/gin-contrib/sessions"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/storage"
  "github.com/jarmo/secrets/storage/path"
  "github.com/jarmo/secrets-web/middleware"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/templates"
)

func accessibleVaults(configurationPath string, privateKey *ecdh.PrivateKey) ([]string, error) {
  aliases, err := path.Aliases(configurationPath)
  if err != nil {
    if _, statError := os.Stat(configurationPath); os.IsNotExist(statError) {
      return nil, nil
    }
    return nil, err
  }
  accessible := make([]string, 0, len(aliases))
  for _, alias := range aliases {
    vaultPath, err := path.Get(configurationPath, alias)
    if err != nil {
      continue
    }
    if _, err := storage.ReadForUser(vaultPath, privateKey); err == nil {
      accessible = append(accessible, alias)
    }
  }
  sort.Strings(accessible)
  return accessible, nil
}

func VaultNavigation(configurationPath string) gin.HandlerFunc {
  return func(c *gin.Context) {
    current := c.MustGet("userSession").(session.UserSession)
    accessible, err := accessibleVaults(configurationPath, current.PrivateKey)
    if err != nil {
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }
    c.Set("accessibleVaults", accessible)
    c.Next()
  }
}

func Vaults(configurationPath string) gin.HandlerFunc {
  return func(c *gin.Context) {
    userSession := c.MustGet("userSession").(session.UserSession)
    accessible := c.GetStringSlice("accessibleVaults")
    if len(accessible) == 1 {
      c.Redirect(http.StatusSeeOther, "/vaults/"+url.PathEscape(accessible[0]))
      return
    }
    c.HTML(http.StatusOK, templates.Path("vaults"), gin.H{
      "username": userSession.Username,
      "vaults": accessible,
      "showVaultsLink": len(accessible) > 1,
      "csrfToken": middleware.CsrfToken(sessions.Default(c)),
      "sessionMaxAgeInSeconds": session.MaxAgeInSeconds,
    })
  }
}
