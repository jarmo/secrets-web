package router

import (
  "net/http"
  "net/url"
  "testing"

  "github.com/jarmo/secrets/user"
)

func TestCLIUserPasswordChangeInvalidatesWebSession(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  csrfCookie, csrfToken := fixture.csrf()
  activeCookie := fixture.login(csrfCookie, csrfToken)

  if result := fixture.send("GET", "/vaults", "", activeCookie, ""); result.Code != http.StatusOK {
    t.Fatalf("Vaults unavailable before password change: %d", result.Code)
  }
  newPassword := "new unique password 456"
  if err := user.ChangePassword(fixture.usersDirectory, "bob", []byte(fixture.userPassword), []byte(newPassword)); err != nil {
    t.Fatal(err)
  }
  if result := fixture.send("GET", "/vaults", "", activeCookie, ""); result.Code != http.StatusSeeOther {
    t.Fatalf("Session survived CLI password change: %d", result.Code)
  }
  if result := fixture.send("GET", "/vaults/production", "", activeCookie, ""); result.Code != http.StatusSeeOther {
    t.Fatalf("Vault still accessible after CLI password change: %d", result.Code)
  }

  oldCredentials := url.Values{"username": {"bob"}, "password": {fixture.userPassword}}.Encode()
  if result := fixture.send("POST", "/login", oldCredentials, csrfCookie, csrfToken); result.Code != http.StatusUnauthorized {
    t.Fatalf("Old password still works: %d", result.Code)
  }
  newCredentials := url.Values{"username": {"bob"}, "password": {newPassword}}.Encode()
  login := fixture.send("POST", "/login", newCredentials, csrfCookie, csrfToken)
  if login.Code != http.StatusNoContent {
    t.Fatalf("New password rejected: %d", login.Code)
  }
  if result := fixture.send("GET", "/vaults/production", "", login.Header().Get("Set-Cookie"), ""); result.Code != http.StatusOK {
    t.Fatalf("Vault access lost after CLI password change: %d", result.Code)
  }
}

func TestCLIUserDeletionInvalidatesWebSession(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  csrfCookie, csrfToken := fixture.csrf()
  activeCookie := fixture.login(csrfCookie, csrfToken)
  if err := user.Destroy(fixture.usersDirectory, "bob"); err != nil {
    t.Fatal(err)
  }
  if result := fixture.send("GET", "/vaults", "", activeCookie, ""); result.Code != http.StatusSeeOther {
    t.Fatalf("Deleted user retained session: %d", result.Code)
  }
  if err := user.Register(fixture.usersDirectory, "bob", []byte("replacement user password 123")); err != nil {
    t.Fatal(err)
  }
  if result := fixture.send("GET", "/vaults", "", activeCookie, ""); result.Code != http.StatusSeeOther {
    t.Fatalf("Recreated user reactivated previous session: %d", result.Code)
  }
}

func TestCLIUserReplacementInvalidatesWebSession(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  csrfCookie, csrfToken := fixture.csrf()
  activeCookie := fixture.login(csrfCookie, csrfToken)
  if err := user.Destroy(fixture.usersDirectory, "bob"); err != nil {
    t.Fatal(err)
  }
  if err := user.Register(fixture.usersDirectory, "bob", []byte("replacement user password 123")); err != nil {
    t.Fatal(err)
  }
  if result := fixture.send("GET", "/vaults", "", activeCookie, ""); result.Code != http.StatusSeeOther {
    t.Fatalf("Old session survived user replacement: %d", result.Code)
  }
}
