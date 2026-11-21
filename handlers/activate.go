package handlers

import (
  "net/http"

  "github.com/gin-contrib/sessions"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/user"
  "github.com/jarmo/secrets-web/middleware"
  "github.com/jarmo/secrets-web/templates"
)

func ActivationForm(c *gin.Context) {
  showActivation(c, http.StatusOK, "", false)
}

func Activate(usersDirectory string) gin.HandlerFunc {
  return func(c *gin.Context) {
    c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
    if err := c.Request.ParseForm(); err != nil {
      showActivation(c, http.StatusBadRequest, "Invalid request", false)
      return
    }
    username := c.PostForm("username")
    setupCode := c.PostForm("setupCode")
    password := c.PostForm("password")
    confirmation := c.PostForm("confirmation")
    if username == "" || setupCode == "" || password == "" {
      showActivation(c, http.StatusBadRequest, "All fields are required", false)
      return
    }
    if password != confirmation {
      showActivation(c, http.StatusBadRequest, "Passwords do not match", false)
      return
    }
    if err := user.ValidatePassword([]byte(password)); err != nil {
      showActivation(c, http.StatusBadRequest, err.Error(), false)
      return
    }
    if err := user.Activate(usersDirectory, username, setupCode, []byte(password)); err != nil {
      showActivation(c, http.StatusBadRequest, "Unable to activate account. Check the username and setup code.", false)
      return
    }
    showActivation(c, http.StatusOK, "", true)
  }
}

func showActivation(c *gin.Context, status int, message string, activated bool) {
  c.HTML(status, templates.Path("activate"), gin.H{
    "csrfToken": middleware.CsrfToken(sessions.Default(c)),
    "error": message,
    "activated": activated,
  })
}
