package azure

import (
	"os"
	"strings"
	"testing"
)

// TestMain strips the Azure SDK's configuration (AZURE_TENANT_ID,
// AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, ...) from the environment before any
// test runs. Every test here talks to a fake; a developer shell that is logged
// in to a real tenant must not be able to turn one into a live Key Vault call.
// Tests that exercise one of these variables set it with t.Setenv.
func TestMain(m *testing.M) {
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "AZURE_") {
			os.Unsetenv(name)
		}
	}
	os.Exit(m.Run())
}
