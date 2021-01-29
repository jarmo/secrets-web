package handlers

import (
  "net/http"

  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/vault"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/templates"
  "github.com/jarmo/secrets-web/redirect"
)

func Index(c *gin.Context) {
  filter := ""
  vaultSession := c.MustGet("session").(session.Vault)
  result := vault.List(vaultSession.Secrets, filter)

  c.HTML(http.StatusOK, templates.Path("index"), gin.H{
    "message": redirect.Message(c),
    "secrets": result,
  })
}

