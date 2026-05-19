package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rubysolo/envisible/pkg/kms"
	"github.com/rubysolo/envisible/pkg/ui"
)

var (
	kmsInitProvider string
	kmsInitResource string
)

var kmsInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Register an existing cloud KMS key as the envisible public key",
	Long: `Fetches the public half of a pre-existing cloud KMS asymmetric key and writes it
to envisible.pub. The private half stays in the cloud and is never downloaded.

The KMS key must be configured for RSA-OAEP-SHA-256 with a 2048-bit RSA modulus,
and the caller must have permission to read the public key (no decrypt permission
is required to run this command).

Examples:
  envisible kms init --provider gcp \
      --resource projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/N
  envisible kms init --provider aws \
      --resource arn:aws:kms:us-east-1:123456789012:key/<uuid>
  envisible kms init --provider azure \
      --resource https://VAULT.vault.azure.net/keys/NAME/VERSION`,
	RunE: func(cmd *cobra.Command, args []string) error {
		kind, err := parseProviderKind(kmsInitProvider)
		if err != nil {
			return err
		}
		if strings.TrimSpace(kmsInitResource) == "" {
			return fmt.Errorf("--resource is required")
		}

		info, err := kms.BootstrapPublicKey(cmd.Context(), kind, kmsInitResource)
		if err != nil {
			return fmt.Errorf("failed to fetch public key: %w", err)
		}

		if err := kms.WritePublicKey(pubKeyPath, info); err != nil {
			return fmt.Errorf("failed to write %s: %w", pubKeyPath, err)
		}

		ui.Success("Registered %s KMS key", info.Kind)
		ui.KV("Resource", info.Resource)
		ui.KV("Algorithm", string(info.Alg))
		ui.KV("Public key written to", pubKeyPath)
		return nil
	},
}

func init() {
	kmsInitCmd.Flags().StringVar(&kmsInitProvider, "provider", "", "Provider: gcp | aws | azure")
	kmsInitCmd.Flags().StringVar(&kmsInitResource, "resource", "", "Provider-native resource identifier")
	_ = kmsInitCmd.MarkFlagRequired("provider")
	_ = kmsInitCmd.MarkFlagRequired("resource")
	kmsCmd.AddCommand(kmsInitCmd)
}
