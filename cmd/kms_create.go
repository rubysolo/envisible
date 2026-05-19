package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/rubysolo/envisible/pkg/kms"
	awskms "github.com/rubysolo/envisible/pkg/kms/aws"
	azurekms "github.com/rubysolo/envisible/pkg/kms/azure"
	gcpkms "github.com/rubysolo/envisible/pkg/kms/gcp"
	"github.com/rubysolo/envisible/pkg/ui"
)

var (
	kmsCreateProvider string

	// kmsCreateName is the shared --name flag, used by both GCP (key short name
	// inside its keyring) and Azure (key name inside its vault). AWS doesn't use
	// it — there a key is identified by ARN or alias.
	kmsCreateName string

	gcpCreateProject  string
	gcpCreateLocation string
	gcpCreateKeyring  string

	awsCreateRegion string
	awsCreateAlias  string

	azCreateVault string
)

// createProviderKey dispatches `kms create` to the right provider package.
// Exposed as a package-level var so cmd-level tests can inject a fake without
// invoking real cloud APIs. Restore the original via defer in test setup.
var createProviderKey = createProviderKeyReal

func createProviderKeyReal(ctx context.Context, kind kms.ProviderKind) (string, error) {
	switch kind {
	case kms.GCP:
		return gcpkms.CreateKey(ctx, gcpkms.CreateKeyParams{
			Project:  gcpCreateProject,
			Location: gcpCreateLocation,
			Keyring:  gcpCreateKeyring,
			Name:     kmsCreateName,
		})
	case kms.AWS:
		return awskms.CreateKey(ctx, awskms.CreateKeyParams{
			Region: awsCreateRegion,
			Alias:  awsCreateAlias,
		})
	case kms.Azure:
		return azurekms.CreateKey(ctx, azurekms.CreateKeyParams{
			Vault: azCreateVault,
			Name:  kmsCreateName,
		})
	default:
		return "", fmt.Errorf("create not supported for provider %q", kind)
	}
}

var kmsCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Provision a new cloud KMS asymmetric key, then register it",
	Long: `Creates an asymmetric RSA-OAEP-SHA-256 / 2048-bit key in the configured cloud
KMS, then runs the same flow as ` + "`kms init`" + ` to fetch its public half and write
envisible.pub.

Requires KMS admin permissions in the target cloud. For least-privilege workflows,
provision the key via Terraform / console / gcloud and use ` + "`kms init`" + ` instead.

Provider-specific flags:
  gcp:   --project --location --keyring --name   (key ring must already exist)
  aws:   [--region] [--alias]                    (region falls back to SDK chain)
  azure: --vault --name                          (vault is name or full URL)`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		kind, err := parseProviderKind(kmsCreateProvider)
		if err != nil {
			return err
		}
		switch kind {
		case kms.GCP:
			if gcpCreateProject == "" || gcpCreateLocation == "" || gcpCreateKeyring == "" || kmsCreateName == "" {
				return fmt.Errorf("--project, --location, --keyring, and --name are all required for gcp")
			}
		case kms.AWS:
			// Both flags optional; CreateKey handles defaults.
		case kms.Azure:
			if azCreateVault == "" || kmsCreateName == "" {
				return fmt.Errorf("--vault and --name are required for azure")
			}
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		kind, _ := parseProviderKind(kmsCreateProvider)

		ui.Info("Creating %s KMS key...", kind)
		resource, err := createProviderKey(cmd.Context(), kind)
		if err != nil {
			return fmt.Errorf("failed to create KMS key: %w", err)
		}

		info, err := kms.BootstrapPublicKey(cmd.Context(), kind, resource)
		if err != nil {
			return fmt.Errorf("created key %s but failed to fetch public key: %w", resource, err)
		}
		if err := kms.WritePublicKey(pubKeyPath, info); err != nil {
			return fmt.Errorf("failed to write %s: %w", pubKeyPath, err)
		}

		ui.Success("Created %s KMS key", info.Kind)
		ui.KV("Resource", info.Resource)
		ui.KV("Algorithm", string(info.Alg))
		ui.KV("Public key written to", pubKeyPath)
		return nil
	},
}

func init() {
	kmsCreateCmd.Flags().StringVar(&kmsCreateProvider, "provider", "", "Provider: gcp | aws | azure")
	_ = kmsCreateCmd.MarkFlagRequired("provider")

	// Shared "name" flag — both GCP and Azure use it for the key's short name.
	// AWS doesn't use --name (it generates UUIDs; --alias is the human handle).
	kmsCreateCmd.Flags().StringVar(&kmsCreateName, "name", "", "Key short name (GCP, Azure)")

	kmsCreateCmd.Flags().StringVar(&gcpCreateProject, "project", "", "GCP project")
	kmsCreateCmd.Flags().StringVar(&gcpCreateLocation, "location", "", "GCP location (e.g. us, europe-west1)")
	kmsCreateCmd.Flags().StringVar(&gcpCreateKeyring, "keyring", "", "GCP key ring name (must already exist)")

	kmsCreateCmd.Flags().StringVar(&awsCreateRegion, "region", "", "AWS region (defaults to SDK config)")
	kmsCreateCmd.Flags().StringVar(&awsCreateAlias, "alias", "", "AWS alias name (will be prefixed with 'alias/' if missing)")

	kmsCreateCmd.Flags().StringVar(&azCreateVault, "vault", "", "Azure Key Vault name or full URL")

	kmsCmd.AddCommand(kmsCreateCmd)
}
