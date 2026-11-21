package router

import (
  "net/http"
  "strings"
  "testing"

  "github.com/jarmo/secrets/user"
)

func TestSessionStatusAndAutomaticRefreshScript(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  if result := fixture.send("GET", "/session/status", "", "", ""); result.Code != http.StatusUnauthorized {
    t.Fatalf("Unauthenticated session status: %d", result.Code)
  }

  csrfCookie, csrfToken := fixture.csrf()
  cookie := fixture.login(csrfCookie, csrfToken)
  status := fixture.send("GET", "/session/status", "", cookie, "")
  if status.Code != http.StatusNoContent {
    t.Fatalf("Authenticated session status: %d", status.Code)
  }
  if status.Header().Get("Set-Cookie") != "" {
    t.Fatal("Session status check refreshed the cookie")
  }
  if cacheControl := status.Header().Get("Cache-Control"); !strings.Contains(cacheControl, "no-store") {
    t.Fatalf("Session status can be cached: %q", cacheControl)
  }

  for _, page := range []string{"/vaults", "/vaults/production", "/settings"} {
    response := fixture.send("GET", page, "", cookie, "")
    if response.Code != http.StatusOK {
      t.Fatalf("Page %s: %d", page, response.Code)
    }
    if !strings.Contains(response.Body.String(), "/public/assets/js/session_expiration.js") {
      t.Fatalf("Page %s has no session expiration check", page)
    }
  }

  if err := user.ChangePassword(fixture.usersDirectory, "bob", []byte(fixture.userPassword), []byte("different valid password 456")); err != nil {
    t.Fatal(err)
  }
  if result := fixture.send("GET", "/session/status", "", cookie, ""); result.Code != http.StatusUnauthorized {
    t.Fatalf("Password change did not invalidate session status: %d", result.Code)
  }
}
