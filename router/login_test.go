package router

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestUserLoginAndSessions(t *testing.T) {
	fixture := newUserWebTestFixture(t)
	send := fixture.send
	userPassword := fixture.userPassword
	csrfCookie, csrfToken := fixture.csrf()
	credentials := url.Values{"username": {"bob"}, "password": {userPassword}}.Encode()
	if result := send("POST", "/login", credentials, csrfCookie, ""); result.Code != http.StatusPreconditionFailed {
		t.Fatalf("Login without CSRF token: %d", result.Code)
	}
	if result := send("POST", "/login", url.Values{"username": {"bob"}, "password": {"wrong"}}.Encode(), csrfCookie, csrfToken); result.Code != http.StatusUnauthorized {
		t.Fatalf("Login with invalid password: %d", result.Code)
	}
	if result := send("POST", "/login", url.Values{"username": {"pending"}, "password": {userPassword}}.Encode(), csrfCookie, csrfToken); result.Code != http.StatusUnauthorized {
		t.Fatalf("Pending user logged in: %d", result.Code)
	}
	if result := send("POST", "/login", url.Values{"username": {"bob"}, "password": {"vault-password"}}.Encode(), csrfCookie, csrfToken); result.Code != http.StatusUnauthorized {
		t.Fatalf("User login fell back to colliding vault: %d", result.Code)
	}
	if result := send("POST", "/login", url.Values{"username": {"production"}, "password": {"vault-owner-password"}}.Encode(), csrfCookie, csrfToken); result.Code != http.StatusSeeOther {
		t.Fatalf("Legacy vault login stopped working: %d", result.Code)
	}
	if result := send("GET", "/vaults", "", csrfCookie, ""); result.Code != http.StatusSeeOther {
		t.Fatalf("Unauthenticated vault listing: %d", result.Code)
	}

	login := send("POST", "/login", credentials, csrfCookie, csrfToken)
	if login.Code != http.StatusNoContent {
		t.Fatalf("Login: %d, %s", login.Code, login.Body.String())
	}
	sessionCookie := login.Header().Get("Set-Cookie")
	if sessionCookie == "" || strings.Contains(sessionCookie, userPassword) {
		t.Fatal("Missing or unsafe user session cookie")
	}
	if result := send("GET", "/user-login", "", sessionCookie, ""); result.Code != http.StatusNotFound {
		t.Fatalf("Old user login route still exists: %d", result.Code)
	}
	renewal := send("GET", "/vaults", "", sessionCookie, "")
	if renewal.Header().Get("Set-Cookie") == "" {
		t.Fatal("Authenticated activity did not renew the session cookie")
	}
	sessionCookie = renewal.Header().Get("Set-Cookie")
	if result := send("GET", "/", "", sessionCookie, ""); result.Code != http.StatusSeeOther || result.Header().Get("Location") != "/vaults" {
		t.Fatalf("Logged-in user was not redirected to vaults: %d", result.Code)
	}
	secondLogin := send("POST", "/login", credentials, csrfCookie, csrfToken)
	if secondLogin.Code != http.StatusNoContent {
		t.Fatalf("Second login: %d", secondLogin.Code)
	}
	secondCookie := secondLogin.Header().Get("Set-Cookie")
	if result := send("GET", "/vaults", "", sessionCookie, ""); result.Code != http.StatusSeeOther {
		t.Fatalf("Old session survived second login: %d", result.Code)
	}
	if result := send("GET", "/vaults", "", secondCookie, ""); result.Code != http.StatusOK {
		t.Fatalf("New session rejected: %d", result.Code)
	}
	sessionCookie = secondCookie
	if result := send("POST", "/logout", "", sessionCookie, ""); result.Code != http.StatusPreconditionFailed {
		t.Fatalf("Logout without CSRF: %d", result.Code)
	}
	logout := send("POST", "/logout", "", sessionCookie, csrfToken)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("Logout: %d", logout.Code)
	}
	if result := send("GET", "/vaults", "", sessionCookie, ""); result.Code != http.StatusSeeOther {
		t.Fatalf("User session remained valid after logout: %d", result.Code)
	}
}

func TestLoginPageRedirect(t *testing.T) {
	fixture := newUserWebTestFixture(t)
	csrfCookie, csrfToken := fixture.csrf()
	cookie := fixture.login(csrfCookie, csrfToken)
	for _, sessionCookie := range []string{"", cookie} {
		req := httptest.NewRequest("GET", "/login", nil)
		if sessionCookie != "" {
			req.Header.Set("Cookie", sessionCookie)
		}
		result := httptest.NewRecorder()
		fixture.router.ServeHTTP(result, req)
		if result.Code != http.StatusSeeOther || result.Header().Get("Location") != "/" {
			t.Fatalf("GET /login returned %d, Location %q", result.Code, result.Header().Get("Location"))
		}
	}
	if result := fixture.send("GET", "/session/status", "", cookie, ""); result.Code != http.StatusNoContent {
		t.Fatalf("GET /login invalidated the existing session: %d", result.Code)
	}
}
