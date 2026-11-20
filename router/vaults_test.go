package router

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jarmo/secrets/storage"
)

func TestMemberVaultAccessAndEditing(t *testing.T) {
	fixture := newMemberWebTestFixture(t)
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
		!strings.Contains(vault.Body.String(), "Add Secret") ||
		strings.Contains(vault.Body.String(), `action="/secrets"`) {
		t.Fatal("Member vault did not reuse the secret editor with vault-scoped actions")
	}
	filtered := send("GET", "/vaults/production/secrets?filter=missing", "", sessionCookie, "")
	if filtered.Code != http.StatusOK || strings.Contains(filtered.Body.String(), "API token") {
		t.Fatalf("Member filter: %d, %s", filtered.Code, filtered.Body.String())
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
		t.Fatalf("Add to member vault: %d, %s", result.Code, result.Header().Get("Location"))
	}
	memberKey, err := fixture.bob.Unlock([]byte(fixture.memberPassword))
	if err != nil {
		t.Fatal(err)
	}
	productionSecrets, err := storage.ReadForMember(productionPath, memberKey)
	if err != nil || len(productionSecrets) != 2 {
		t.Fatalf("Member write was not persisted: %v, %v", productionSecrets, err)
	}
	newSecretID := productionSecrets[1].Id.String()
	if result := send("PUT", "/vaults/production/"+newSecretID, url.Values{"name": {"Renamed"}, "value": {"Updated value"}}.Encode(), sessionCookie, csrfToken); result.Code != http.StatusSeeOther {
		t.Fatalf("Edit shared secret: %d", result.Code)
	}
	productionSecrets, err = storage.Read(productionPath, []byte("vault-owner-password"))
	if err != nil || len(productionSecrets) != 2 || productionSecrets[1].Name != "Renamed" || productionSecrets[1].Value != "Updated value" {
		t.Fatalf("Owner cannot read edited member vault: %v, %v", productionSecrets, err)
	}
	if result := send("DELETE", "/vaults/production/"+newSecretID, "", sessionCookie, csrfToken); result.Code != http.StatusSeeOther {
		t.Fatalf("Delete shared secret: %d", result.Code)
	}
	productionSecrets, err = storage.ReadForMember(productionPath, memberKey)
	if err != nil || len(productionSecrets) != 1 || productionSecrets[0].Name != "API token" {
		t.Fatalf("Member deleted the wrong secret: %v, %v", productionSecrets, err)
	}
	unaffected, err := storage.Read(otherPath, []byte("another-password"))
	if err != nil || len(unaffected) != 1 || unaffected[0].Name != "Unshared secret" {
		t.Fatalf("Unshared vault was modified: %v, %v", unaffected, err)
	}
	secondVault, err := storage.ReadForMember(developmentPath, memberKey)
	if err != nil || len(secondVault) != 1 || secondVault[0].Name != "Staging token" {
		t.Fatalf("Other shared vault was modified: %v, %v", secondVault, err)
	}
}
