package handlers

import (
  "net/http"

  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "github.com/jarmo/secrets-web/middleware"
  "github.com/jarmo/secrets/vault"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/templates"
  "github.com/jarmo/secrets-web/redirect"
)

func Index(c *gin.Context) {
  renderVault(c, nil)
}

func renderVault(c *gin.Context, displayError error) {
  vaultSession := c.MustGet("session").(session.Vault)
  result := vault.List(vaultSession.Secrets, "")
  view := "index"
  if vaultSession.MemberKey != nil {
    view = "vault"
  }

  c.HTML(http.StatusOK, templates.Path(view), gin.H{
    "message": redirect.Message(c),
    "error": displayError,
    "secrets": result,
    "vaultPath": vaultSession.URL(),
    "member": vaultSession.MemberKey != nil,
    "alias": vaultSession.Alias,
    "csrfToken": middleware.CsrfToken(sessions.Default(c)),
    "sessionMaxAgeInSeconds": session.MaxAgeInSeconds,
  })
}

