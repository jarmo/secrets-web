package middleware

import (
  "net/http"
  "encoding/base64"

  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "github.com/jarmo/secrets/crypto"
  "github.com/jarmo/secrets-web/session"
)

func CsrfToken(session sessions.Session) string {
  csrfToken := session.Get("csrfToken")
  if csrfToken == nil {
    newCsrfToken := base64.StdEncoding.EncodeToString(crypto.GenerateRandomBytes(128))
    session.Set("csrfToken", newCsrfToken)
    session.Save()
    return newCsrfToken
  } else {
    return csrfToken.(string)
  }
}

func CsrfProtection() gin.HandlerFunc {
  return func(c *gin.Context) {
    request := c.Request
    if request.Method != "HEAD" && request.Method != "GET" {
      token := CsrfToken(sessions.Default(c))
      if token != c.GetHeader("X-Csrf-Token") {
        c.HTML(http.StatusForbidden, "/templates/login.tmpl", gin.H{
          "sessionMaxAgeInSeconds": session.MaxAgeInSeconds,
          "csrfToken": token,
        })
        c.AbortWithStatus(http.StatusForbidden)
        return
      }
    }
    c.Next()
  }
}

