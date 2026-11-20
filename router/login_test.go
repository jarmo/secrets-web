package router

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestMemberLoginAndSessions(t *testing.T) {
	fixture := newMemberWebTestFixture(t)
	send := fixture.send
	memberPassword := fixture.memberPassword
	csrfCookie, csrfToken := fixture.csrf()
	credentials := url.Values{"username": {"bob"}, "password": {memberPassword}}.Encode()
	if result := send("POST", "/login", credentials, csrfCookie, ""); result.Code != http.StatusPreconditionFailed {
		t.Fatalf("Login without CSRF token: %d", result.Code)
	}
	if result := send("POST", "/login", url.Values{"username": {"bob"}, "password": {"wrong"}}.Encode(), csrfCookie, csrfToken); result.Code != http.StatusUnauthorized {
		t.Fatalf("Login with invalid password: %d", result.Code)
	}
	if result := send("POST", "/login", url.Values{"username": {"pending"}, "password": {memberPassword}}.Encode(), csrfCookie, csrfToken); result.Code != http.StatusUnauthorized {
		t.Fatalf("Pending member logged in: %d", result.Code)
	}
	if result := send("POST", "/login", url.Values{"username": {"bob"}, "password": {"vault-password"}}.Encode(), csrfCookie, csrfToken); result.Code != http.StatusUnauthorized {
		t.Fatalf("Member login fell back to colliding vault: %d", result.Code)
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
	if sessionCookie == "" || strings.Contains(sessionCookie, memberPassword) {
		t.Fatal("Missing or unsafe member session cookie")
	}
	if result := send("GET", "/member-login", "", sessionCookie, ""); result.Code != http.StatusNotFound {
		t.Fatalf("Old member login route still exists: %d", result.Code)
	}
	renewal := send("GET", "/vaults", "", sessionCookie, "")
	if renewal.Header().Get("Set-Cookie") == "" {
		t.Fatal("Authenticated activity did not renew the session cookie")
	}
	sessionCookie = renewal.Header().Get("Set-Cookie")
	if result := send("GET", "/", "", sessionCookie, ""); result.Code != http.StatusSeeOther || result.Header().Get("Location") != "/vaults" {
		t.Fatalf("Logged-in member was not redirected to vaults: %d", result.Code)
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
		t.Fatalf("Member session remained valid after logout: %d", result.Code)
	}
}
