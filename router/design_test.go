package router

import (
  "net/http"
  "strings"
  "testing"
)

func TestAccessibleSecretEditorAndThemeControls(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  csrfCookie, csrfToken := fixture.csrf()
  userCookie := fixture.login(csrfCookie, csrfToken)

  vault := fixture.send("GET", "/vaults/production", "", userCookie, "")
  if vault.Code != http.StatusOK {
    t.Fatalf("Vault editor returned %d", vault.Code)
  }
  for _, markup := range []string{
    `<details id="add-secret"`,
    `<details class="secret panel">`,
    `<summary class="secret-summary">`,
    `for="secret-add-name"`,
    `for="filter"`,
    `data-theme-toggle`,
    `class="delete-confirm-body"`,
    `data-delete-name=`,
    `class="vault-heading"`,
    `/public/assets/js/details.js`,
    `/public/assets/js/theme.js`,
  } {
    if !strings.Contains(vault.Body.String(), markup) {
      t.Errorf("Vault editor is missing %s", markup)
    }
  }
  if strings.Contains(vault.Body.String(), `class="modal`) {
    t.Error("Vault editor still renders legacy modals")
  }

  vaults := fixture.send("GET", "/vaults", "", userCookie, "")
  if vaults.Code != http.StatusOK || !strings.Contains(vaults.Body.String(), `id="vault-filter"`) || !strings.Contains(vaults.Body.String(), `data-theme-toggle`) {
    t.Fatalf("Vault list is missing filtering or appearance controls: %d", vaults.Code)
  }

  settings := fixture.send("GET", "/settings", "", userCookie, "")
  if settings.Code != http.StatusOK || !strings.Contains(settings.Body.String(), `data-theme-toggle`) {
    t.Fatalf("Settings page is missing appearance controls: %d", settings.Code)
  }
}
