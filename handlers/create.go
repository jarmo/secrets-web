package handlers

import (
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/vault"
  "github.com/jarmo/secrets/storage"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/redirect"
)

func Create(c *gin.Context) {
  name := c.PostForm("name")
  value := c.PostForm("value")
  sessionVault := c.MustGet("session").(session.Vault)

  _, newSecrets := vault.Add(sessionVault.Secrets, name, value)
  storage.Write(sessionVault.Path, sessionVault.Password, newSecrets)
  redirect.WithMessage(c, "/", "Added successfully")
}
