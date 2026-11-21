package router

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jarmo/secrets/crypto"
)

func TestVaultListingAndStatusDoNotDecryptSecretContents(t *testing.T) {
	fixture := newUserWebTestFixture(t)
	csrfCookie, csrfToken := fixture.csrf()
	cookie := fixture.login(csrfCookie, csrfToken)

	data, err := os.ReadFile(fixture.productionPath)
	if err != nil {
		t.Fatal(err)
	}
	var vault crypto.Shared
	if err := json.Unmarshal(data, &vault); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(vault.Data)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	vault.Data = base64.StdEncoding.EncodeToString(ciphertext)
	modified, err := json.Marshal(vault)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.productionPath, modified, 0600); err != nil {
		t.Fatal(err)
	}

	listing := fixture.send("GET", "/vaults", "", cookie, "")
	if listing.Code != http.StatusOK || !strings.Contains(listing.Body.String(), `href="/vaults/production"`) {
		t.Fatalf("Vault listing unnecessarily decrypted contents: %d", listing.Code)
	}
	status := fixture.send("GET", "/session/status?vault=production", "", cookie, "")
	if status.Code != http.StatusNoContent || status.Header().Get("Set-Cookie") != "" {
		t.Fatalf("Status should only verify membership: %d, cookie %q", status.Code, status.Header().Get("Set-Cookie"))
	}
	opened := fixture.send("GET", "/vaults/production", "", cookie, "")
	if opened.Code != http.StatusNotFound {
		t.Fatalf("Opening a vault must still authenticate its contents: %d", opened.Code)
	}
}
