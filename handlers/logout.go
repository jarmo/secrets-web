package handlers

import (
  "net/http"

  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets-web/session"
)

func Logout(active *session.MemberSessions) gin.HandlerFunc {
  return func(c *gin.Context) {
    if err := active.Logout(c); err != nil {
      c.Status(http.StatusInternalServerError)
      return
    }
    c.Status(http.StatusNoContent)
  }
}
