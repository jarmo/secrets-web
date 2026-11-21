package cli

import (
  "strings"
  "testing"
)

func TestUsageShowsVersionFlag(t *testing.T) {
  usage := createUsage()
  if !strings.Contains(usage, "  secrets-web (-v | --version)") {
    t.Fatal("Usage does not show the version invocation")
  }
  if !strings.Contains(usage, "-v --version") {
    t.Fatal("Options do not document the version flag")
  }
}
