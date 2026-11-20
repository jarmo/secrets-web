package router

import (
  "net/http"
  "net/url"
  "os"
  "strings"
  "testing"
)

func TestMemberPasswordChange(t *testing.T) {
  fixture := newMemberWebTestFixture(t)
  csrfCookie, csrfToken := fixture.csrf()
  oldPassword := fixture.memberPassword
  newPassword := "different, secure member password 456"

  if result := fixture.send("GET", "/settings", "", csrfCookie, ""); result.Code != http.StatusSeeOther {
    t.Fatalf("Settings accessible without login: %d", result.Code)
  }
  memberCookie := fixture.login(csrfCookie, csrfToken)
  settings := fixture.send("GET", "/settings", "", memberCookie, "")
  if settings.Code != http.StatusOK || !strings.Contains(settings.Body.String(), "Change password") {
    t.Fatalf("Settings unavailable: %d", settings.Code)
  }

  beforeProduction, err := os.ReadFile(fixture.productionPath)
  if err != nil {
    t.Fatal(err)
  }
  beforeDevelopment, err := os.ReadFile(fixture.developmentPath)
  if err != nil {
    t.Fatal(err)
  }

  change := func(current, next, confirmation string, csrf string) int {
    t.Helper()
    form := url.Values{
      "currentPassword": {current},
      "newPassword": {next},
      "confirmation": {confirmation},
    }
    return fixture.send("POST", "/settings/password", form.Encode(), memberCookie, csrf).Code
  }

  if status := change(oldPassword, newPassword, newPassword, ""); status != http.StatusPreconditionFailed {
    t.Fatalf("Change without CSRF allowed: %d", status)
  }
  if status := change("incorrect password", newPassword, newPassword, csrfToken); status != http.StatusBadRequest {
    t.Fatalf("Wrong current password accepted: %d", status)
  }
  if status := change(oldPassword, newPassword, "doesn't match", csrfToken); status != http.StatusBadRequest {
    t.Fatalf("Mismatched confirmation accepted: %d", status)
  }
  if status := change(oldPassword, "too short", "too short", csrfToken); status != http.StatusBadRequest {
    t.Fatalf("Short new password accepted: %d", status)
  }
  if status := change(oldPassword, oldPassword, oldPassword, csrfToken); status != http.StatusBadRequest {
    t.Fatalf("Unchanged password accepted: %d", status)
  }
  if result := fixture.send("GET", "/vaults", "", memberCookie, ""); result.Code != http.StatusOK {
    t.Fatalf("Failed password change invalidated session: %d", result.Code)
  }

  if status := change(oldPassword, newPassword, newPassword, csrfToken); status != http.StatusNoContent {
    t.Fatalf("Password change: %d", status)
  }
  if result := fixture.send("GET", "/vaults", "", memberCookie, ""); result.Code != http.StatusSeeOther {
    t.Fatalf("Session remained active after password change: %d", result.Code)
  }
  if result := fixture.send("GET", "/settings", "", memberCookie, ""); result.Code != http.StatusSeeOther {
    t.Fatalf("Settings remained accessible after password change: %d", result.Code)
  }

  oldCredentials := url.Values{"username": {"bob"}, "password": {oldPassword}}.Encode()
  if result := fixture.send("POST", "/login", oldCredentials, csrfCookie, csrfToken); result.Code != http.StatusUnauthorized {
    t.Fatalf("Old password still works: %d", result.Code)
  }
  newCredentials := url.Values{"username": {"bob"}, "password": {newPassword}}.Encode()
  login := fixture.send("POST", "/login", newCredentials, csrfCookie, csrfToken)
  if login.Code != http.StatusNoContent {
    t.Fatalf("New password rejected: %d", login.Code)
  }
  newCookie := login.Header().Get("Set-Cookie")
  vaults := fixture.send("GET", "/vaults", "", newCookie, "")
  if vaults.Code != http.StatusOK || !strings.Contains(vaults.Body.String(), "production") || !strings.Contains(vaults.Body.String(), "development") {
    t.Fatalf("Previously accessible vaults are unavailable: %d", vaults.Code)
  }
  for _, alias := range []string{"production", "development"} {
    if result := fixture.send("GET", "/vaults/"+alias, "", newCookie, ""); result.Code != http.StatusOK {
      t.Fatalf("Lost access to %s: %d", alias, result.Code)
    }
  }

  afterProduction, err := os.ReadFile(fixture.productionPath)
  if err != nil {
    t.Fatal(err)
  }
  afterDevelopment, err := os.ReadFile(fixture.developmentPath)
  if err != nil {
    t.Fatal(err)
  }
  if string(afterProduction) != string(beforeProduction) || string(afterDevelopment) != string(beforeDevelopment) {
    t.Fatal("Changing the account password rewrote a vault")
  }
}

func TestMemberPasswordChangeRequiresMemberSession(t *testing.T) {
  fixture := newMemberWebTestFixture(t)
  csrfCookie, csrfToken := fixture.csrf()
  form := url.Values{
    "currentPassword": {fixture.memberPassword},
    "newPassword": {"some other long password 123"},
    "confirmation": {"some other long password 123"},
  }
  result := fixture.send("POST", "/settings/password", form.Encode(), csrfCookie, csrfToken)
  if result.Code != http.StatusSeeOther {
    t.Fatalf("Unauthenticated password change returned %d", result.Code)
  }
}
