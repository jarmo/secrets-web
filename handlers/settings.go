package handlers

import (
  "net/http"

  "github.com/gin-contrib/sessions"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/member"
  "github.com/jarmo/secrets-web/middleware"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/templates"
)

func Settings(c *gin.Context) {
  memberSession := c.MustGet("memberSession").(session.MemberSession)
  c.HTML(http.StatusOK, templates.Path("settings"), gin.H{
    "username": memberSession.Username,
    "csrfToken": middleware.CsrfToken(sessions.Default(c)),
    "sessionMaxAgeInSeconds": session.MaxAgeInSeconds,
  })
}

func ChangeMemberPassword(membersDirectory string, active *session.MemberSessions) gin.HandlerFunc {
  return func(c *gin.Context) {
    c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
    if err := c.Request.ParseForm(); err != nil {
      c.String(http.StatusBadRequest, "Invalid request")
      return
    }

    currentPassword := c.PostForm("currentPassword")
    newPassword := c.PostForm("newPassword")
    confirmation := c.PostForm("confirmation")
    if currentPassword == "" {
      c.String(http.StatusBadRequest, "Current password is required")
      return
    }
    if len(newPassword) < 12 || len(newPassword) > 1024 {
      c.String(http.StatusBadRequest, "Password must be between 12 and 1024 bytes")
      return
    }
    if newPassword != confirmation {
      c.String(http.StatusBadRequest, "Passwords do not match")
      return
    }
    if currentPassword == newPassword {
      c.String(http.StatusBadRequest, "Choose a different password")
      return
    }

    memberSession := c.MustGet("memberSession").(session.MemberSession)
    if err := member.ChangePassword(membersDirectory, memberSession.Username, []byte(currentPassword), []byte(newPassword)); err != nil {
      c.String(http.StatusBadRequest, "Unable to change password. Check the current password.")
      return
    }
    if err := active.Logout(c); err != nil {
      c.Status(http.StatusInternalServerError)
      return
    }
    c.Status(http.StatusNoContent)
  }
}
