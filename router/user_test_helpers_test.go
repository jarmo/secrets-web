package router

import (
	"bytes"
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

	"github.com/jarmo/secrets/user"
	"github.com/jarmo/secrets/secret"
	"github.com/jarmo/secrets/storage"
	"github.com/jarmo/secrets/storage/path"
)

type userWebTestFixture struct {
	t               *testing.T
	router          http.Handler
	userPassword  string
	tabToken        string
	bob             user.User
	usersDirectory  string
	productionPath  string
	developmentPath string
	otherPath       string
}

func newUserWebTestFixture(t *testing.T) *userWebTestFixture {
	t.Helper()
	directory := t.TempDir()
	usersDirectory := filepath.Join(directory, "users")
	if err := os.Mkdir(usersDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	userPassword := "user private password 123"
	if err := user.Register(usersDirectory, "bob", []byte(userPassword)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := user.CreatePending(usersDirectory, "pending"); err != nil {
		t.Fatal(err)
	}
	bob, err := user.Load(usersDirectory, "bob")
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
	if err := storage.AssociateUser(productionPath, []byte("vault-owner-password"), bob.Identity); err != nil {
		t.Fatal(err)
	}
	if err := storage.AssociateUser(developmentPath, []byte("development-password"), bob.Identity); err != nil {
		t.Fatal(err)
	}
	conflictingVaultPath := filepath.Join(directory, "bob-vault.json")
	path.Store(configPath, conflictingVaultPath, "bob")
	storage.Write(conflictingVaultPath, []byte("vault-password"), nil)

	return &userWebTestFixture{
		t:               t,
		router:          Create(configPath, usersDirectory, false),
		userPassword:  userPassword,
		tabToken:      base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7a}, 32)),
		bob:             bob,
		usersDirectory:  usersDirectory,
		productionPath:  productionPath,
		developmentPath: developmentPath,
		otherPath:       otherPath,
	}
}

func (fixture *userWebTestFixture) send(method, target, body, cookie, csrf string) *httptest.ResponseRecorder {
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
	if cookie != "" || target == "/login" {
		request.Header.Set("X-Tab-Token", fixture.tabToken)
	}
	if method == "POST" && target == "/login" {
		form, _ := url.ParseQuery(body)
		request.Header.Set("X-Credentials", base64.StdEncoding.EncodeToString([]byte(form.Get("username")+":"+form.Get("password"))))
	}
	response := httptest.NewRecorder()
	fixture.router.ServeHTTP(response, request)
	return response
}

func (fixture *userWebTestFixture) csrf() (string, string) {
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

func (fixture *userWebTestFixture) login(csrfCookie, csrfToken string) string {
	fixture.t.Helper()
	credentials := url.Values{"username": {"bob"}, "password": {fixture.userPassword}}.Encode()
	response := fixture.send("POST", "/login", credentials, csrfCookie, csrfToken)
	if response.Code != http.StatusNoContent {
		fixture.t.Fatalf("Login: %d, %s", response.Code, response.Body.String())
	}
	sessionCookie := response.Header().Get("Set-Cookie")
	if sessionCookie == "" || strings.Contains(sessionCookie, fixture.userPassword) {
		fixture.t.Fatal("Missing or unsafe user session cookie")
	}
	return sessionCookie
}
