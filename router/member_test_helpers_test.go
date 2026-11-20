package router

import (
	"encoding/base64"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jarmo/secrets/member"
	"github.com/jarmo/secrets/secret"
	"github.com/jarmo/secrets/storage"
	"github.com/jarmo/secrets/storage/path"
)

type memberWebTestFixture struct {
	t               *testing.T
	router          http.Handler
	memberPassword  string
	bob             member.Member
	productionPath  string
	developmentPath string
	otherPath       string
}

func newMemberWebTestFixture(t *testing.T) *memberWebTestFixture {
	t.Helper()
	directory := t.TempDir()
	membersDirectory := filepath.Join(directory, "members")
	if err := os.Mkdir(membersDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	memberPassword := "member private password 123"
	if err := member.Register(membersDirectory, "bob", []byte(memberPassword)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := member.CreatePending(membersDirectory, "pending"); err != nil {
		t.Fatal(err)
	}
	bob, err := member.Load(membersDirectory, "bob")
	if err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(directory, "config.json")
	productionPath := filepath.Join(directory, "production.json")
	developmentPath := filepath.Join(directory, "development.json")
	otherPath := filepath.Join(directory, "other.json")
	path.Store(configPath, productionPath, "production")
	path.Store(configPath, developmentPath, "development")
	path.Store(configPath, otherPath, "private")
	storage.Write(productionPath, []byte("vault-owner-password"), []secret.Secret{secret.New("API token", "private value")})
	storage.Write(developmentPath, []byte("development-password"), []secret.Secret{secret.New("Staging token", "another private value")})
	storage.Write(otherPath, []byte("another-password"), []secret.Secret{secret.New("Unshared secret", "not for Bob")})
	if err := storage.AssociateMember(productionPath, []byte("vault-owner-password"), bob.Identity); err != nil {
		t.Fatal(err)
	}
	if err := storage.AssociateMember(developmentPath, []byte("development-password"), bob.Identity); err != nil {
		t.Fatal(err)
	}
	conflictingVaultPath := filepath.Join(directory, "bob-vault.json")
	path.Store(configPath, conflictingVaultPath, "bob")
	storage.Write(conflictingVaultPath, []byte("vault-password"), nil)

	return &memberWebTestFixture{
		t:               t,
		router:          Create(configPath, membersDirectory, false),
		memberPassword:  memberPassword,
		bob:             bob,
		productionPath:  productionPath,
		developmentPath: developmentPath,
		otherPath:       otherPath,
	}
}

func (fixture *memberWebTestFixture) send(method, target, body, cookie, csrf string) *httptest.ResponseRecorder {
	fixture.t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	if csrf != "" {
		request.Header.Set("X-Csrf-Token", csrf)
	}
	if method == "POST" && target == "/login" {
		form, _ := url.ParseQuery(body)
		request.Header.Set("X-Credentials", base64.StdEncoding.EncodeToString([]byte(form.Get("username")+":"+form.Get("password"))))
	}
	response := httptest.NewRecorder()
	fixture.router.ServeHTTP(response, request)
	return response
}

func (fixture *memberWebTestFixture) csrf() (string, string) {
	fixture.t.Helper()
	initial := fixture.send("GET", "/", "", "", "")
	if initial.Code != http.StatusUnauthorized {
		fixture.t.Fatalf("Login form: %d", initial.Code)
	}
	csrf := regexp.MustCompile(`name="x-csrf-token" content="([^"]+)"`).FindStringSubmatch(initial.Body.String())
	if len(csrf) != 2 {
		fixture.t.Fatal("Missing CSRF token")
	}
	return initial.Header().Get("Set-Cookie"), html.UnescapeString(csrf[1])
}

func (fixture *memberWebTestFixture) login(csrfCookie, csrfToken string) string {
	fixture.t.Helper()
	credentials := url.Values{"username": {"bob"}, "password": {fixture.memberPassword}}.Encode()
	response := fixture.send("POST", "/login", credentials, csrfCookie, csrfToken)
	if response.Code != http.StatusNoContent {
		fixture.t.Fatalf("Login: %d, %s", response.Code, response.Body.String())
	}
	sessionCookie := response.Header().Get("Set-Cookie")
	if sessionCookie == "" || strings.Contains(sessionCookie, fixture.memberPassword) {
		fixture.t.Fatal("Missing or unsafe member session cookie")
	}
	return sessionCookie
}
