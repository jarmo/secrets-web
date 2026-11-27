package router

import (
  "html"
  "net/http"
  "net/url"
  "regexp"
  "testing"
)

func TestLoginWithExpiredCsrfCookie(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  for _, login := range []struct {
    username string
    password string
    status int
  }{
    {"bob", fixture.userPassword, http.StatusNoContent},
    {"production", "vault-owner-password", http.StatusSeeOther},
  } {
    t.Run(login.username, func(t *testing.T) {
      _, staleToken := fixture.csrf()
      credentials := url.Values{"username": {login.username}, "password": {login.password}}.Encode()
      rejected := fixture.send("POST", "/login", credentials, "", staleToken)
      if rejected.Code != http.StatusPreconditionFailed {
        t.Fatalf("Login with expired cookie: %d", rejected.Code)
      }
      cookie := rejected.Header().Get("Set-Cookie")
      token := regexp.MustCompile(`name="x-csrf-token" content="([^"]+)"`).FindStringSubmatch(rejected.Body.String())
      if cookie == "" || len(token) != 2 || html.UnescapeString(token[1]) == staleToken {
        t.Fatal("Missing fresh CSRF cookie or token")
      }
      if result := fixture.send("POST", "/login", credentials, cookie, html.UnescapeString(token[1])); result.Code != login.status {
        t.Fatalf("Login with refreshed CSRF token: %d", result.Code)
      }
    })
  }
}
