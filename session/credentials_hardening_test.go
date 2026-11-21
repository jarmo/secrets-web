package session

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCredentialsBoundedAndWellFormed(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString([]byte("name:password:with-colon"))
	name, password, err := Credentials(valid)
	if err != nil || name != "name" || string(password) != "password:with-colon" {
		t.Fatalf("Valid: %q %q %v", name, password, err)
	}
	for _, value := range []string{"", "not-base64", base64.StdEncoding.EncodeToString([]byte("name")), strings.Repeat("A", 4097)} {
		if _, _, err := Credentials(value); err == nil {
			t.Fatalf("Invalid credentials accepted")
		}
	}
}
