package middleware

import (
  "net/http"
  "encoding/base64"
  "crypto/subtle"

  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "github.com/jarmo/secrets/crypto"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/templates"
)

func CsrfToken(session sessions.Session) string {
  csrfToken := session.Get("csrfToken")
  if csrfToken == nil {
    newCsrfToken := base64.StdEncoding.EncodeToString(crypto.GenerateRandomBytes(128))
    session.Set("csrfToken", newCsrfToken)
    session.Save()
    return newCsrfToken
  } else {
    if value, ok := csrfToken.(string); ok && value != "" {
      return value
    }
    newCsrfToken := base64.StdEncoding.EncodeToString(crypto.GenerateRandomBytes(128))
    session.Set("csrfToken", newCsrfToken)
    session.Save()
    return newCsrfToken
  }
}

func CsrfProtection() gin.HandlerFunc {
  return func(c *gin.Context) {
    request := c.Request
    if request.Method != "HEAD" && request.Method != "GET" {
      token := CsrfToken(sessions.Default(c))
      if subtle.ConstantTimeCompare([]byte(token), []byte(c.GetHeader("X-Csrf-Token"))) != 1 {
        c.HTML(http.StatusPreconditionFailed, templates.Path("login"), gin.H{
          "sessionMaxAgeInSeconds": session.MaxAgeInSeconds,
          "csrfToken": token,
        })
        c.AbortWithStatus(http.StatusPreconditionFailed)
        return
      }
    }
    c.Next()
  }
}

