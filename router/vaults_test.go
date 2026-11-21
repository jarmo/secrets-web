package router

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jarmo/secrets/storage"
	"github.com/jarmo/secrets/user"
)

func TestUserVaultAccessAndEditing(t *testing.T) {
	fixture := newUserWebTestFixture(t)
	send := fixture.send
	csrfCookie, csrfToken := fixture.csrf()
	sessionCookie := fixture.login(csrfCookie, csrfToken)
	productionPath := fixture.productionPath
	developmentPath := fixture.developmentPath
	otherPath := fixture.otherPath
	listing := send("GET", "/vaults", "", sessionCookie, "")
	if listing.Code != http.StatusOK || !strings.Contains(listing.Body.String(), "production") || !strings.Contains(listing.Body.String(), "development") {
		t.Fatalf("Vault listing: %d, %s", listing.Code, listing.Body.String())
	}
	if strings.Contains(listing.Body.String(), "private") || strings.Contains(listing.Body.String(), "API token") {
		t.Fatal("Vault listing revealed a restricted vault or its secrets")
	}
	vault := send("GET", "/vaults/production", "", sessionCookie, "")
	if vault.Code != http.StatusOK || !strings.Contains(vault.Body.String(), "API token") || !strings.Contains(vault.Body.String(), "private value") {
		t.Fatalf("Shared vault: %d, %s", vault.Code, vault.Body.String())
	}
	development := send("GET", "/vaults/development", "", sessionCookie, "")
	if development.Code != http.StatusOK || !strings.Contains(development.Body.String(), "Staging token") {
		t.Fatalf("Second shared vault: %d", development.Code)
	}
	if result := send("GET", "/vaults/private", "", sessionCookie, ""); result.Code != http.StatusNotFound {
		t.Fatalf("Unshared vault: %d", result.Code)
	}
	if !strings.Contains(vault.Body.String(), `action="/vaults/production"`) ||
		!strings.Contains(vault.Body.String(), `action="/vaults/production/secrets"`) ||
		!strings.Contains(vault.Body.String(), `id="add-secret"`) ||
		strings.Contains(vault.Body.String(), `action="/secrets"`) {
		t.Fatal("User vault did not reuse the secret editor with vault-scoped actions")
	}
	filtered := send("GET", "/vaults/production/secrets?filter=missing", "", sessionCookie, "")
	if filtered.Code != http.StatusOK || strings.Contains(filtered.Body.String(), "API token") {
		t.Fatalf("User filter: %d, %s", filtered.Code, filtered.Body.String())
	}
	if result := send("POST", "/vaults/production", "name=New&value=Value", sessionCookie, ""); result.Code != http.StatusPreconditionFailed {
		t.Fatalf("Write without CSRF protection: %d", result.Code)
	}
	if result := send("POST", "/vaults/private", "name=New&value=Value", sessionCookie, csrfToken); result.Code != http.StatusNotFound {
		t.Fatalf("Write to unauthorized vault: %d", result.Code)
	}
	if result := send("PUT", "/vaults/private/00000000-0000-0000-0000-000000000000", "name=New&value=Value", sessionCookie, csrfToken); result.Code != http.StatusNotFound {
		t.Fatalf("Edit in unauthorized vault: %d", result.Code)
	}
	if result := send("DELETE", "/vaults/private/00000000-0000-0000-0000-000000000000", "", sessionCookie, csrfToken); result.Code != http.StatusNotFound {
		t.Fatalf("Delete in unauthorized vault: %d", result.Code)
	}
	if result := send("POST", "/vaults/production", url.Values{"name": {"New secret"}, "value": {"New value"}}.Encode(), sessionCookie, csrfToken); result.Code != http.StatusSeeOther || result.Header().Get("Location") != "/vaults/production" {
		t.Fatalf("Add to user vault: %d, %s", result.Code, result.Header().Get("Location"))
	}
	userKey, err := fixture.bob.Unlock([]byte(fixture.userPassword))
	if err != nil {
		t.Fatal(err)
	}
	productionSecrets, err := storage.ReadForUser(productionPath, userKey)
	if err != nil || len(productionSecrets) != 2 {
		t.Fatalf("User write was not persisted: %v, %v", productionSecrets, err)
	}
	newSecretID := productionSecrets[1].Id.String()
	if result := send("PUT", "/vaults/production/"+newSecretID, url.Values{"name": {"Renamed"}, "value": {"Updated value"}}.Encode(), sessionCookie, csrfToken); result.Code != http.StatusSeeOther {
		t.Fatalf("Edit shared secret: %d", result.Code)
	}
	productionSecrets, err = storage.Read(productionPath, []byte("vault-owner-password"))
	if err != nil || len(productionSecrets) != 2 || productionSecrets[1].Name != "Renamed" || productionSecrets[1].Value != "Updated value" {
		t.Fatalf("Owner cannot read edited user vault: %v, %v", productionSecrets, err)
	}
	if result := send("DELETE", "/vaults/production/"+newSecretID, "", sessionCookie, csrfToken); result.Code != http.StatusSeeOther {
		t.Fatalf("Delete shared secret: %d", result.Code)
	}
	productionSecrets, err = storage.ReadForUser(productionPath, userKey)
	if err != nil || len(productionSecrets) != 1 || productionSecrets[0].Name != "API token" {
		t.Fatalf("User deleted the wrong secret: %v, %v", productionSecrets, err)
	}
	unaffected, err := storage.Read(otherPath, []byte("another-password"))
	if err != nil || len(unaffected) != 1 || unaffected[0].Name != "Unshared secret" {
		t.Fatalf("Unshared vault was modified: %v, %v", unaffected, err)
	}
	secondVault, err := storage.ReadForUser(developmentPath, userKey)
	if err != nil || len(secondVault) != 1 || secondVault[0].Name != "Staging token" {
		t.Fatalf("Other shared vault was modified: %v, %v", secondVault, err)
	}
}

func TestUserVaultsSortedByName(t *testing.T) {
	fixture := newUserWebTestFixture(t)
	csrfCookie, csrfToken := fixture.csrf()
	sessionCookie := fixture.login(csrfCookie, csrfToken)
	response := fixture.send("GET", "/vaults", "", sessionCookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("Vault listing returned %d", response.Code)
	}
	developmentIndex := strings.Index(response.Body.String(), `href="/vaults/development"`)
	productionIndex := strings.Index(response.Body.String(), `href="/vaults/production"`)
	if developmentIndex == -1 || productionIndex == -1 || developmentIndex >= productionIndex {
		t.Fatalf("Vaults are not sorted alphabetically: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `id="vault-filter"`) || !strings.Contains(response.Body.String(), `class="vault"`) {
		t.Fatal("Vault list is missing filter controls")
	}
}

func TestSingleAccessibleVaultRedirectsToEditor(t *testing.T) {
	fixture := newUserWebTestFixture(t)
	usersDirectory := filepath.Join(filepath.Dir(fixture.productionPath), "users")
	password := "solo private password 123"
	if err := user.Register(usersDirectory, "solo", []byte(password)); err != nil {
		t.Fatal(err)
	}
	account, err := user.Load(usersDirectory, "solo")
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.AssociateUser(fixture.productionPath, []byte("vault-owner-password"), account.Identity); err != nil {
		t.Fatal(err)
	}

	csrfCookie, csrfToken := fixture.csrf()
	credentials := url.Values{"username": {"solo"}, "password": {password}}.Encode()
	login := fixture.send("POST", "/login", credentials, csrfCookie, csrfToken)
	if login.Code != http.StatusNoContent {
		t.Fatalf("Solo login returned %d", login.Code)
	}
	listing := fixture.send("GET", "/vaults", "", login.Header().Get("Set-Cookie"), "")
	if listing.Code != http.StatusSeeOther || listing.Header().Get("Location") != "/vaults/production" {
		t.Fatalf("Single vault was not opened automatically: %d, %s", listing.Code, listing.Header().Get("Location"))
	}
	for _, address := range []string{"/vaults/production", "/settings"} {
		page := fixture.send("GET", address, "", login.Header().Get("Set-Cookie"), "")
		if page.Code != http.StatusOK || strings.Contains(page.Body.String(), `href="/vaults" class="nav-link"`) {
			t.Fatalf("Vaults navigation should be hidden for a single vault on %s: %d", address, page.Code)
		}
	}
	if err := storage.AssociateUser(fixture.developmentPath, []byte("development-password"), account.Identity); err != nil {
		t.Fatal(err)
	}
	page := fixture.send("GET", "/vaults/production", "", login.Header().Get("Set-Cookie"), "")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `href="/vaults" class="nav-link"`) {
		t.Fatal("Vaults navigation was not shown after refreshing with two accessible vaults")
	}
}

func TestVaultsNavigationForNoAccessibleVaults(t *testing.T) {
	fixture := newUserWebTestFixture(t)
	password := "empty user password 123"
	if err := user.Register(fixture.usersDirectory, "empty", []byte(password)); err != nil {
		t.Fatal(err)
	}
	csrfCookie, csrfToken := fixture.csrf()
	credentials := url.Values{"username": {"empty"}, "password": {password}}.Encode()
	login := fixture.send("POST", "/login", credentials, csrfCookie, csrfToken)
	if login.Code != http.StatusNoContent {
		t.Fatalf("Login without vaults returned %d", login.Code)
	}
	for _, address := range []string{"/vaults", "/settings"} {
		page := fixture.send("GET", address, "", login.Header().Get("Set-Cookie"), "")
		if page.Code != http.StatusOK || strings.Contains(page.Body.String(), `href="/vaults" class="nav-link"`) {
			t.Fatalf("Vaults navigation should be hidden without access on %s: %d", address, page.Code)
		}
	}

	if err := os.Remove(filepath.Join(filepath.Dir(fixture.productionPath), "config.json")); err != nil {
		t.Fatal(err)
	}
	page := fixture.send("GET", "/vaults", "", login.Header().Get("Set-Cookie"), "")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "No vaults available yet") {
		t.Fatalf("Missing vault configuration should display an empty list: %d", page.Code)
	}
}

func TestVaultsNavigationForMultipleAccessibleVaults(t *testing.T) {
	fixture := newUserWebTestFixture(t)
	csrfCookie, csrfToken := fixture.csrf()
	userCookie := fixture.login(csrfCookie, csrfToken)
	for _, address := range []string{"/vaults", "/vaults/production", "/settings"} {
		page := fixture.send("GET", address, "", userCookie, "")
		if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `href="/vaults" class="nav-link"`) {
			t.Fatalf("Vaults navigation should appear for multiple vaults on %s: %d", address, page.Code)
		}
	}
}
