package aws

import (
	"os"
	"strings"
	"testing"
)

// TestMain strips the AWS SDK's configuration from the environment before any
// test runs. Every test here talks to a fake; the ones that build a real client
// rely on the SDK resolving credentials lazily. A developer shell that exports
// AWS_PROFILE, AWS_REGION or static credentials must not be able to change what
// these tests do, let alone turn one into a live KMS call. Tests that exercise
// one of these variables set it with t.Setenv.
func TestMain(m *testing.M) {
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "AWS_") {
			os.Unsetenv(name)
		}
	}
	// ~/.aws/config and ~/.aws/credentials are read even with no variable set.
	os.Setenv("AWS_CONFIG_FILE", os.DevNull)
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", os.DevNull)
	os.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	os.Exit(m.Run())
}
