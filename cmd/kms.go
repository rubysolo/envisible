package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rubysolo/envisible/pkg/kms"

	// Side-effect imports that register the three cloud KMS providers with the
	// pkg/kms registry at process startup. Pulling these in here (rather than from
	// each subcommand) ensures the binary always carries all three providers, so a
	// freshly-cloned project's envisible.pub can be read regardless of which cloud
	// it points at.
	_ "github.com/rubysolo/envisible/pkg/kms/aws"
	_ "github.com/rubysolo/envisible/pkg/kms/azure"
	_ "github.com/rubysolo/envisible/pkg/kms/gcp"
)

var kmsCmd = &cobra.Command{
	Use:   "kms",
	Short: "Manage cloud-KMS-backed envisible keys",
	Long: `Register, provision, and rotate cloud-KMS-backed envisible keys.

When a project uses ` + "`envisible kms`" + ` instead of ` + "`envisible keygen`" + `, the asymmetric
private key lives in the cloud and never leaves it; only the public half is
downloaded to envisible.pub. Encryption is local (RSA-OAEP wrap of a per-value
data key); decryption round-trips to KMS via the SDK's default credential chain.

Supported providers: gcp | aws | azure.`,
}

func init() {
	rootCmd.AddCommand(kmsCmd)
}

// parseProviderKind normalizes a user-supplied --provider flag into a kms.ProviderKind.
// Case- and whitespace-tolerant; closed set matches what cloud SDKs we ship.
func parseProviderKind(s string) (kms.ProviderKind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "gcp":
		return kms.GCP, nil
	case "aws":
		return kms.AWS, nil
	case "azure":
		return kms.Azure, nil
	default:
		return "", fmt.Errorf("unknown provider %q (expected gcp, aws, or azure)", s)
	}
}
