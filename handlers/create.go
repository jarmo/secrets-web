package handlers

import (
  "net/http"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/vault"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/redirect"
)

func Create(c *gin.Context) {
  name := c.PostForm("name")
  value := c.PostForm("value")
  sessionVault := c.MustGet("session").(session.Vault)

  _, newSecrets := vault.Add(sessionVault.Secrets, name, value)
  if err := sessionVault.Save(newSecrets); err != nil {
    c.Status(http.StatusInternalServerError)
    return
  }
  redirect.WithMessage(c, sessionVault.RedirectURL(), "Added successfully")
}
