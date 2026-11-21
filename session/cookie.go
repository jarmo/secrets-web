package session

import (
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "github.com/gin-contrib/sessions/cookie"
  "github.com/jarmo/secrets/crypto"
  "net/http"
)

func CreateCookie(prodModeEnabled bool) gin.HandlerFunc {
  sessionStore := cookie.NewStore(crypto.GenerateRandomBytes(64), crypto.GenerateRandomBytes(32))
  sessionStore.Options(sessions.Options{
    Path: "/",
    HttpOnly: true,
    SameSite: http.SameSiteLaxMode,
    Secure: prodModeEnabled,
    MaxAge: MaxAgeInSeconds,
  })

  return sessions.Sessions("secrets", sessionStore)
}
