package gcp

import (
	"os"
	"strings"
	"testing"
)

// TestMain strips the Google Cloud SDK's configuration
// (GOOGLE_APPLICATION_CREDENTIALS, GOOGLE_CLOUD_PROJECT, CLOUDSDK_*) from the
// environment before any test runs. Every test here talks to a fake; a
// developer shell holding real application-default credentials must not be able
// to turn one into a live Cloud KMS call. Tests that exercise one of these
// variables set it with t.Setenv.
func TestMain(m *testing.M) {
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "GOOGLE_") || strings.HasPrefix(name, "CLOUDSDK_") {
			os.Unsetenv(name)
		}
	}
	os.Exit(m.Run())
}
