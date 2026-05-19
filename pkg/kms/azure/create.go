package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// CreateKeyParams holds the Azure-specific fields needed to provision a new key.
// Vault accepts either a vault name ("myvault") or a full URL
// ("https://myvault.vault.azure.net"). Name is the key name within the vault.
type CreateKeyParams struct {
	Vault string
	Name  string
}

// creatorClient is the slice of *azkeys.Client that CreateKey uses.
type creatorClient interface {
	CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error)
}

// CreateKey provisions a new RSA-2048 key in the specified Key Vault and returns
// its full resource URL (including the freshly-assigned version), which
// envisible.pub then pins to.
func CreateKey(ctx context.Context, p CreateKeyParams) (string, error) {
	if p.Vault == "" || p.Name == "" {
		return "", fmt.Errorf("azure kms: --vault and --name are required")
	}
	vaultURL := p.Vault
	if !strings.HasPrefix(vaultURL, "https://") {
		vaultURL = fmt.Sprintf("https://%s.vault.azure.net", vaultURL)
	}
	cred, err := newCredential()
	if err != nil {
		return "", err
	}
	client, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return "", fmt.Errorf("azure kms: create keyvault client: %w", err)
	}
	return createKeyWithClient(ctx, client, p)
}

func createKeyWithClient(ctx context.Context, client creatorClient, p CreateKeyParams) (string, error) {
	kty := azkeys.KeyTypeRSA
	size := int32(2048)
	resp, err := client.CreateKey(ctx, p.Name, azkeys.CreateKeyParameters{
		Kty:     &kty,
		KeySize: &size,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("azure kms: create key: %w", err)
	}
	if resp.Key == nil || resp.Key.KID == nil {
		return "", fmt.Errorf("azure kms: CreateKey returned no key identifier")
	}
	return string(*resp.Key.KID), nil
}
