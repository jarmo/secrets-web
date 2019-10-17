package handlers

import (
  "net/http"

  "github.com/satori/go.uuid"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/vault"
  "github.com/jarmo/secrets/storage"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/redirect"
  "github.com/jarmo/secrets-web/templates"
)

func Delete(c *gin.Context) {
  id, _ := uuid.FromString(c.Param("id"))
  sessionVault := c.MustGet("session").(session.Vault)

  if _, newSecrets, err := vault.Delete(sessionVault.Secrets, id); err != nil {
    c.HTML(http.StatusOK, templates.Path("index"), gin.H{
      "error": err,
    })
  } else {
    storage.Write(sessionVault.Path, sessionVault.Password, newSecrets)
    redirect.WithMessage(c, "/", "Deleted successfully")
  }
}
