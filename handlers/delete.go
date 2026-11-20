package handlers

import (
  "net/http"

  "github.com/satori/go.uuid"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/vault"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/redirect"
)

func Delete(c *gin.Context) {
  id, _ := uuid.FromString(c.Param("id"))
  sessionVault := c.MustGet("session").(session.Vault)

  if _, newSecrets, err := vault.Delete(sessionVault.Secrets, id); err != nil {
    renderVault(c, err)
  } else {
    if err := sessionVault.Save(newSecrets); err != nil {
      c.Status(http.StatusInternalServerError)
      return
    }
    redirect.WithMessage(c, sessionVault.RedirectURL(), "Deleted successfully")
  }
}
