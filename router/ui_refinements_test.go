package router

import (
  "net/http"
  "strings"
  "testing"

  "github.com/jarmo/secrets/storage"
)

func TestUserVaultEditorRefinements(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  csrfCookie, csrfToken := fixture.csrf()
  userCookie := fixture.login(csrfCookie, csrfToken)
  page := fixture.send("GET", "/vaults/production", "", userCookie, "")
  if page.Code != http.StatusOK {
    t.Fatalf("Editor returned %d", page.Code)
  }
  for _, text := range []string{
    `class="nav-username"`,
    `>bob</span>`,
    `class="vault-heading"`,
    `data-clear-filter`,
    `class="secret-actions"`,
    `data-delete-toggle aria-expanded="false"`,
    `class="delete-confirm-body"`,
    `id="delete-confirm-`,
    `class="nav-actions"`,
    `data-delete-name=`,
    `disabled`,
    `data-theme-toggle`,
  } {
    if !strings.Contains(page.Body.String(), text) {
      t.Errorf("Missing editor UI: %s", text)
    }
  }
  for _, unwanted := range []string{
    `Changes are saved to this vault.`,
    `Everything in its place`,
    `data-theme-reset`,
  } {
    if strings.Contains(page.Body.String(), unwanted) {
      t.Errorf("Obsolete editor UI remains: %s", unwanted)
    }
  }
}

func TestEmptyVaultHidesFilter(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  storage.Write(fixture.productionPath, []byte("vault-owner-password"), nil)
  csrfCookie, csrfToken := fixture.csrf()
  userCookie := fixture.login(csrfCookie, csrfToken)
  page := fixture.send("GET", "/vaults/production", "", userCookie, "")
  if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "No secrets yet") {
    t.Fatalf("Empty vault did not render its empty state: %d", page.Code)
  }
  if strings.Contains(page.Body.String(), `id="filter"`) {
    t.Fatal("Empty vault should not have a filter")
  }
}

func TestAuthenticationPagesHaveOneBrand(t *testing.T) {
  fixture := newUserWebTestFixture(t)
  for _, address := range []string{"/", "/activate"} {
    page := fixture.send("GET", address, "", "", "")
    if strings.Count(page.Body.String(), `class="auth-brand"`) != 1 || strings.Contains(page.Body.String(), `class="brand"`) {
      t.Errorf("Unexpected duplicate brand on %s", address)
    }
  }
}
