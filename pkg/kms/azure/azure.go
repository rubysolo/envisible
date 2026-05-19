// Package azure implements the pkg/kms provider interfaces for Azure Key Vault.
//
// Importing this package registers Azure with the kms provider registry via init():
//
//	import _ "github.com/rubysolo/envisible/pkg/kms/azure"
//
// Authentication uses azidentity.DefaultAzureCredential — env vars, managed
// identity, az-cli login, etc. The default chain can hang briefly on IMDS in
// environments where it's unreachable; setting AZURE_TENANT_ID and AZURE_CLIENT_ID
// or other explicit credential env vars bypasses that fallback.
package azure

import (
	"context"
	"crypto/rsa"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/rubysolo/envisible/pkg/kms"
)

func init() {
	kms.RegisterUnwrapper(kms.Azure, newUnwrapper)
	kms.RegisterBootstrap(kms.Azure, fetchPublicKey)
}

// kvClient is the subset of *azkeys.Client we depend on. Exposed as an interface
// so tests can substitute a fake without depending on SDK mock churn.
type kvClient interface {
	GetKey(ctx context.Context, name, version string, opts *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	Decrypt(ctx context.Context, name, version string, params azkeys.KeyOperationParameters, opts *azkeys.DecryptOptions) (azkeys.DecryptResponse, error)
}

type azureResource struct {
	vaultURL string
	name     string
	version  string
}

// parseAzureResource cracks an Azure Key Vault key URL into its three components.
// The on-disk envisible.pub stores the full URL; the SDK wants vault URL + key
// name + version as separate arguments, so we split once at construction time.
//
// Required form: https://VAULT.vault.azure.net/keys/NAME/VERSION
func parseAzureResource(s string) (azureResource, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return azureResource{}, fmt.Errorf("azure: parse resource %q: %w", s, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return azureResource{}, fmt.Errorf("azure: resource must be an https URL, got %q", s)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "keys" || parts[1] == "" || parts[2] == "" {
		return azureResource{}, fmt.Errorf("azure: expected resource of form https://VAULT.vault.azure.net/keys/NAME/VERSION, got %q", s)
	}
	return azureResource{
		vaultURL: fmt.Sprintf("%s://%s", u.Scheme, u.Host),
		name:     parts[1],
		version:  parts[2],
	}, nil
}

func newCredential() (azcore.TokenCredential, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure: default credential: %w", err)
	}
	return cred, nil
}

func newUnwrapper(ctx context.Context, info *kms.PublicKeyInfo) (kms.Unwrapper, error) {
	res, err := parseAzureResource(info.Resource)
	if err != nil {
		return nil, err
	}
	cred, err := newCredential()
	if err != nil {
		return nil, err
	}
	client, err := azkeys.NewClient(res.vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: create keyvault client: %w", err)
	}
	return newUnwrapperWithClient(client, res), nil
}

func newUnwrapperWithClient(client kvClient, res azureResource) *unwrapper {
	return &unwrapper{client: client, res: res}
}

type unwrapper struct {
	client kvClient
	res    azureResource
}

func (u *unwrapper) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	alg := azkeys.EncryptionAlgorithmRSAOAEP256
	resp, err := u.client.Decrypt(ctx, u.res.name, u.res.version, azkeys.KeyOperationParameters{
		Algorithm: &alg,
		Value:     wrapped,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azure kms: decrypt: %w", err)
	}
	return resp.Result, nil
}

func fetchPublicKey(ctx context.Context, resource string) (*kms.PublicKeyInfo, error) {
	res, err := parseAzureResource(resource)
	if err != nil {
		return nil, err
	}
	cred, err := newCredential()
	if err != nil {
		return nil, err
	}
	client, err := azkeys.NewClient(res.vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: create keyvault client: %w", err)
	}
	return fetchPublicKeyWithClient(ctx, client, resource, res)
}

func fetchPublicKeyWithClient(ctx context.Context, client kvClient, resource string, res azureResource) (*kms.PublicKeyInfo, error) {
	resp, err := client.GetKey(ctx, res.name, res.version, nil)
	if err != nil {
		return nil, fmt.Errorf("azure kms: get key: %w", err)
	}
	if resp.Key == nil {
		return nil, fmt.Errorf("azure kms: GetKey returned no key material")
	}
	pub, err := jwkToRSAPublicKey(resp.Key)
	if err != nil {
		return nil, err
	}
	if err := kms.ValidateAlgorithm(kms.RSAOAEPSHA256_2048, pub); err != nil {
		return nil, err
	}
	return &kms.PublicKeyInfo{
		Kind:     kms.Azure,
		Resource: resource,
		Alg:      kms.RSAOAEPSHA256_2048,
		PubKey:   pub,
	}, nil
}

// jwkToRSAPublicKey converts an Azure JWK into a stdlib RSA public key. Azure
// returns the modulus (N) and public exponent (E) as raw bytes — big-endian,
// unsigned — which is what big.Int.SetBytes expects.
func jwkToRSAPublicKey(jwk *azkeys.JSONWebKey) (*rsa.PublicKey, error) {
	if jwk.Kty == nil {
		return nil, fmt.Errorf("azure kms: key has no Kty")
	}
	if *jwk.Kty != azkeys.KeyTypeRSA && *jwk.Kty != azkeys.KeyTypeRSAHSM {
		return nil, fmt.Errorf("azure kms: key type %q is not RSA", *jwk.Kty)
	}
	if len(jwk.N) == 0 || len(jwk.E) == 0 {
		return nil, fmt.Errorf("azure kms: key is missing RSA modulus or exponent")
	}
	n := new(big.Int).SetBytes(jwk.N)
	e := new(big.Int).SetBytes(jwk.E)
	if !e.IsInt64() || e.Int64() <= 0 {
		return nil, fmt.Errorf("azure kms: RSA public exponent is invalid or out of range")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
