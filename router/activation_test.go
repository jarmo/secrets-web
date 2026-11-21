package router

import (
  "net/http"
  "net/http/httptest"
  "net/url"
  "html"
  "os"
  "regexp"
  "strings"
  "testing"

  "github.com/jarmo/secrets/user"
)

func TestUserActivation(t *testing.T) {
  usersDirectory := t.TempDir()
  if err := os.Chmod(usersDirectory, 0700); err != nil {
    t.Fatal(err)
  }
  code, _, err := user.CreatePending(usersDirectory, "bob")
  if err != nil {
    t.Fatal(err)
  }
  router := Create("unused-config", usersDirectory, false)
  response := httptest.NewRecorder()
  router.ServeHTTP(response, httptest.NewRequest("GET", "/activate", nil))
  if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Activate user account") {
    t.Fatalf("Activation page status %d: %s", response.Code, response.Body.String())
  }
  csrf := regexp.MustCompile(`name="x-csrf-token" content="([^"]+)"`).FindStringSubmatch(response.Body.String())
  if len(csrf) != 2 {
    t.Fatal("CSRF token missing from activation page")
  }
  csrf[1] = html.UnescapeString(csrf[1])
  cookie := response.Header().Get("Set-Cookie")
  if cookie == "" {
    t.Fatal("CSRF session cookie missing")
  }

  submit := func(username, setupCode, password, confirmation, token string) *httptest.ResponseRecorder {
    t.Helper()
    body := url.Values{
      "username": {username}, "setupCode": {setupCode},
      "password": {password}, "confirmation": {confirmation},
    }.Encode()
    request := httptest.NewRequest("POST", "/activate", strings.NewReader(body))
    request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    request.Header.Set("Cookie", cookie)
    if token != "" {
      request.Header.Set("X-Csrf-Token", token)
    }
    result := httptest.NewRecorder()
    router.ServeHTTP(result, request)
    return result
  }

  password := "new private password 123"
  if result := submit("bob", code, password, password, ""); result.Code != http.StatusPreconditionFailed {
    t.Fatalf("Missing CSRF token: got status %d", result.Code)
  }
  if result := submit("bob", code, password, "different-password", csrf[1]); result.Code != http.StatusBadRequest {
    t.Fatalf("Password mismatch: got status %d", result.Code)
  }
  if _, err := user.Load(usersDirectory, "bob"); err == nil {
    t.Fatal("Account activated despite password mismatch")
  }
  for _, invalidPassword := range []string{"short", strings.Repeat("x", 1025)} {
    if result := submit("bob", code, invalidPassword, invalidPassword, csrf[1]); result.Code != http.StatusBadRequest {
      t.Fatalf("Invalid password length: got status %d", result.Code)
    }
    if _, err := user.Load(usersDirectory, "bob"); err == nil {
      t.Fatal("Invalid password activated account")
    }
  }
  if result := submit("bob", "invalid-code", password, password, csrf[1]); result.Code != http.StatusBadRequest {
    t.Fatalf("Wrong code: got status %d", result.Code)
  }
  result := submit("bob", code, password, password, csrf[1])
  if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "Account activated successfully") {
    t.Fatalf("Activation: got status %d and body %s", result.Code, result.Body.String())
  }
  if strings.Contains(result.Body.String(), password) || strings.Contains(result.Body.String(), code) {
    t.Fatal("Credentials exposed in response")
  }
  if _, _, err := user.Authenticate(usersDirectory, "bob", []byte(password)); err != nil {
    t.Fatalf("Account cannot authenticate: %v", err)
  }
  if result := submit("bob", code, password, password, csrf[1]); result.Code != http.StatusBadRequest {
    t.Fatalf("Used code accepted again: status %d", result.Code)
  }
}
