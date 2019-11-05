package handlers

import (
  "net/http"

  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/vault"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/templates"
)

func List(c *gin.Context) {
  filter := c.DefaultQuery("filter", "")
  vaultSession := c.MustGet("session").(session.Vault)
  result := vault.List(vaultSession.Secrets, filter)

  c.HTML(http.StatusOK, templates.Path("_secrets"), gin.H{
    "secrets": result,
  })
}
