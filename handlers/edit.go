package handlers

import (
  "net/http"

  "github.com/satori/go.uuid"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/vault"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/redirect"
)

func Edit(c *gin.Context) {
  id, _ := uuid.FromString(c.Param("id"))
  name := c.PostForm("name")
  value := c.PostForm("value")
  sessionVault := c.MustGet("session").(session.Vault)

  if _, newSecrets, err := vault.Edit(sessionVault.Secrets, id, name, value); err != nil {
    renderVault(c, err)
  } else {
    if err := sessionVault.Save(newSecrets); err != nil {
      c.Status(http.StatusInternalServerError)
      return
    }
    redirect.WithMessage(c, sessionVault.RedirectURL(), "Edited successfully")
  }
}
