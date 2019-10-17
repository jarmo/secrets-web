package middleware

import (
  "net/http"

  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/templates"
)

func Authenticated(configurationPath string) gin.HandlerFunc {
  return func(c *gin.Context) {
    if sessionVault, err := session.CreateVault(configurationPath, c); err != nil {
      c.HTML(http.StatusForbidden, templates.Path("login"), gin.H{
        "sessionMaxAgeInSeconds": session.MaxAgeInSeconds,
        "csrfToken": CsrfToken(sessions.Default(c)),
      })
      c.AbortWithStatus(http.StatusForbidden)
    } else {
      c.Set("session", sessionVault)
    }
  }
}

