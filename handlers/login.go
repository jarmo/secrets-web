package handlers

import (
  "encoding/base64"
  "net/http"
  "os"
  "strings"

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
    credentials, err := base64.StdEncoding.DecodeString(c.GetHeader("X-Credentials"))
    parts := strings.SplitN(string(credentials), ":", 2)
    if err != nil || len(parts) != 2 || parts[0] == "" || parts[1] == "" {
      showLoginError(c)
      return
    }

    account, err := user.Load(usersDirectory, parts[0])
    if err == nil {
      privateKey, err := account.Unlock([]byte(parts[1]))
      if err != nil {
        showLoginError(c)
        return
      }
      if err := active.Login(c, account, privateKey); err != nil {
        c.Status(http.StatusInternalServerError)
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
