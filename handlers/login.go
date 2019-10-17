package handlers

import (
  "net/http"

  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/templates"
  "github.com/jarmo/secrets-web/redirect"
)

func Login(configurationPath string) gin.HandlerFunc {
  return func(c *gin.Context) {
    if vault, err := session.CreateVault(configurationPath, c); err != nil {
      c.HTML(http.StatusOK, templates.Path("login"), gin.H{
        "error": err,
        "user": vault.Alias,
      })
    } else {
      redirect.WithMessage(c, "/", "Logged in successfully")
    }
  }
}
