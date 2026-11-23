package router

import (
  "encoding/base64"
  "net/http"
  "net/http/httptest"
  "net/url"
  "strings"
  "testing"
)

func TestAccountSessionRequiresTabToken(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  csrfCookie, csrfToken := fixture.csrf()
  credentials := url.Values{"username": {"bob"}, "password": {fixture.userPassword}}.Encode()

  noToken := httptest.NewRequest("POST", "/login", strings.NewReader(credentials))
  noToken.Header.Set("Cookie", csrfCookie)
  noToken.Header.Set("X-Csrf-Token", csrfToken)
  noToken.Header.Set("X-Credentials", base64.StdEncoding.EncodeToString([]byte("bob:"+fixture.userPassword)))
  rejected := httptest.NewRecorder()
  fixture.router.ServeHTTP(rejected, noToken)
  if rejected.Code != http.StatusUnauthorized {
    t.Fatalf("Account login without tab token succeeded: %d", rejected.Code)
  }

  cookie := fixture.login(csrfCookie, csrfToken)
  try := func(target, token string) *httptest.ResponseRecorder {
    t.Helper()
    req := httptest.NewRequest("GET", target, nil)
    req.Header.Set("Cookie", cookie)
    if token != "" { req.Header.Set("X-Tab-Token", token) }
    result := httptest.NewRecorder()
    fixture.router.ServeHTTP(result, req)
    return result
  }

  for _, target := range []string{"/vaults", "/vaults/production", "/settings", "/session/status"} {
    without := try(target, "")
    if without.Code != http.StatusSeeOther && without.Code != http.StatusUnauthorized {
      t.Fatalf("Cookie alone authorized %s: %d", target, without.Code)
    }
    withWrong := try(target, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    if withWrong.Code != http.StatusSeeOther && withWrong.Code != http.StatusUnauthorized {
      t.Fatalf("Unrelated tab token authorized %s: %d", target, withWrong.Code)
    }
  }

  // A second tab displaying the login page must not clear the cookie used by
  // the original tab (both tabs share the cookie jar, not the tab token).
  secondTab := try("/", "")
  if secondTab.Code != http.StatusUnauthorized {
    t.Fatalf("New tab bypassed login: %d", secondTab.Code)
  }
  if strings.Contains(secondTab.Header().Get("Set-Cookie"), "Max-Age=0") {
    t.Fatal("A new tab cleared the existing account cookie")
  }
  if active := try("/session/status", fixture.tabToken); active.Code != http.StatusNoContent {
    t.Fatalf("Original tab stopped working: %d", active.Code)
  }
}

func TestTabAuthorizationRequiredForLogout(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  csrfCookie, csrfToken := fixture.csrf()
  cookie := fixture.login(csrfCookie, csrfToken)

  logout := httptest.NewRequest("POST", "/logout", nil)
  logout.Header.Set("Cookie", cookie)
  logout.Header.Set("X-Csrf-Token", csrfToken)
  result := httptest.NewRecorder()
  fixture.router.ServeHTTP(result, logout)
  if result.Code != http.StatusUnauthorized {
    t.Fatalf("Cookie-only logout succeeded: %d", result.Code)
  }
  if result := fixture.send("GET", "/session/status", "", cookie, ""); result.Code != http.StatusNoContent {
    t.Fatalf("Missing-token logout invalidated real session: %d", result.Code)
  }
  result = fixture.send("POST", "/logout", "", cookie, csrfToken)
  if result.Code != http.StatusNoContent {
    t.Fatalf("Authenticated logout failed: %d", result.Code)
  }
  if result := fixture.send("GET", "/session/status", "", cookie, ""); result.Code != http.StatusUnauthorized {
    t.Fatalf("Logged-out session still valid: %d", result.Code)
  }
}
