package handlers

import (
  "net/http"

  "github.com/gin-contrib/sessions"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/user"
  "github.com/jarmo/secrets-web/middleware"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/templates"
)

func Settings(c *gin.Context) {
  userSession := c.MustGet("userSession").(session.UserSession)
  c.HTML(http.StatusOK, templates.Path("settings"), gin.H{
    "username": userSession.Username,
    "showVaultsLink": len(c.GetStringSlice("accessibleVaults")) > 1,
    "csrfToken": middleware.CsrfToken(sessions.Default(c)),
    "sessionMaxAgeInSeconds": session.MaxAgeInSeconds,
  })
}

func ChangeUserPassword(usersDirectory string, active *session.UserSessions) gin.HandlerFunc {
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
    if err := user.ValidatePassword([]byte(newPassword)); err != nil {
      c.String(http.StatusBadRequest, err.Error())
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

    userSession := c.MustGet("userSession").(session.UserSession)
    if err := user.ChangePassword(usersDirectory, userSession.Username, []byte(currentPassword), []byte(newPassword)); err != nil {
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
