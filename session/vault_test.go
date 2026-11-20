package session

import (
	"encoding/base64"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jarmo/secrets/secret"
	"github.com/jarmo/secrets/storage"
	"github.com/jarmo/secrets/storage/path"
)

func TestCreateVaultAcceptsColonInPassword(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	vaultPath := filepath.Join(directory, "foo.json")
	password := "correct:horse:battery:staple"

	storage.Write(vaultPath, []byte(password), []secret.Secret{secret.New("example", "value")})
	path.Store(configPath, vaultPath, "foo")

	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	request := httptest.NewRequest("POST", "/login", nil)
	request.Header.Set("X-Credentials", base64.StdEncoding.EncodeToString([]byte("foo:"+password)))
	context.Request = request

	vault, err := CreateVault(configPath, context)
	if err != nil {
		t.Fatal(err)
	}
	if vault.Alias != "foo" || len(vault.Secrets) != 1 || vault.Secrets[0].Name != "example" {
		t.Fatal("Vault was not unlocked correctly")
	}
}
