package handlers

import (
  "net/http"
  "os"

  "github.com/gin-contrib/sessions"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/user"
  "github.com/jarmo/secrets-web/middleware"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/templates"
  "github.com/jarmo/secrets-web/redirect"
)

func Login(configurationPath, usersDirectory string, active *session.UserSessions) gin.HandlerFunc {
  return func(c *gin.Context) {
    username, password, err := session.Credentials(c.GetHeader("X-Credentials"))
    if err != nil {
      showLoginError(c)
      return
    }

    account, err := user.Load(usersDirectory, username)
    if err == nil {
      privateKey, err := account.Unlock(password)
      if err != nil {
        showLoginError(c)
        return
      }
      if err := active.Login(c, account, privateKey); err != nil {
        showLoginError(c)
        return
      }
      c.Status(http.StatusNoContent)
      return
    }
    if !os.IsNotExist(err) {
      showLoginError(c)
      return
    }

    if _, err := session.CreateVault(configurationPath, c); err != nil {
      showLoginError(c)
    } else {
      redirect.WithMessage(c, "/", "Logged in successfully")
    }
  }
}

func showLoginError(c *gin.Context) {
  c.HTML(http.StatusUnauthorized, templates.Path("login"), gin.H{
    "error": "Invalid username or password",
    "authPage": true,
    "csrfToken": middleware.CsrfToken(sessions.Default(c)),
    "sessionMaxAgeInSeconds": session.MaxAgeInSeconds,
  })
}
