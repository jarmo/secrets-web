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
  if vaultSession.UserKey != nil {
    view = "vault"
  }

  username := ""
  if current, ok := c.Get("userSession"); ok {
    username = current.(session.UserSession).Username
  }

  c.HTML(http.StatusOK, templates.Path(view), gin.H{
    "message": redirect.Message(c),
    "error": displayError,
    "secrets": result,
    "vaultPath": vaultSession.URL(),
    "user": vaultSession.UserKey != nil,
    "alias": vaultSession.Alias,
    "username": username,
    "showVaultsLink": len(c.GetStringSlice("accessibleVaults")) > 1,
    "csrfToken": middleware.CsrfToken(sessions.Default(c)),
    "sessionMaxAgeInSeconds": session.MaxAgeInSeconds,
  })
}

