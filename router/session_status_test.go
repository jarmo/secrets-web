package router

import (
  "net/http"
  "strings"
  "testing"

  "github.com/jarmo/secrets/user"
  "github.com/jarmo/secrets/storage"
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

func TestSessionStatusDetectsRevokedVaultAccess(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  csrfCookie, csrfToken := fixture.csrf()
  cookie := fixture.login(csrfCookie, csrfToken)

  vault := fixture.send("GET", "/vaults/production", "", cookie, "")
  if vault.Code != http.StatusOK || !strings.Contains(vault.Body.String(), `name="x-vault-alias" content="production"`) {
    t.Fatal("Vault page does not provide its alias for access checks")
  }

  for _, target := range []string{"/session/status?vault=production", "/session/status?vault=development"} {
    result := fixture.send("GET", target, "", cookie, "")
    if result.Code != http.StatusNoContent || result.Header().Get("Set-Cookie") != "" {
      t.Fatalf("Accessible vault status %s: %d, cookie %q", target, result.Code, result.Header().Get("Set-Cookie"))
    }
  }
  if result := fixture.send("GET", "/session/status?vault=private", "", cookie, ""); result.Code != http.StatusForbidden {
    t.Fatalf("Unshared vault status: %d", result.Code)
  }

  if err := storage.RemoveUser(fixture.productionPath, fixture.usersDirectory, "bob", []byte("vault-owner-password")); err != nil {
    t.Fatal(err)
  }
  revoked := fixture.send("GET", "/session/status?vault=production", "", cookie, "")
  if revoked.Code != http.StatusForbidden || revoked.Header().Get("Set-Cookie") != "" {
    t.Fatalf("Revoked vault status: %d, cookie %q", revoked.Code, revoked.Header().Get("Set-Cookie"))
  }
  if result := fixture.send("GET", "/vaults/production", "", cookie, ""); result.Code != http.StatusNotFound {
    t.Fatalf("Revoked user can still open the vault: %d", result.Code)
  }
  if result := fixture.send("GET", "/session/status?vault=development", "", cookie, ""); result.Code != http.StatusNoContent {
    t.Fatalf("Other vault access lost: %d", result.Code)
  }
  if result := fixture.send("GET", "/settings", "", cookie, ""); result.Code != http.StatusOK {
    t.Fatalf("Revoking vault access invalidated the user session: %d", result.Code)
  }
}
