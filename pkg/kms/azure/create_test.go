package azure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// swapCreatorClient replaces the package-level creator client constructor with
// fn and returns a restore func suitable for t.Cleanup.
func swapCreatorClient(fn func(string, azcore.TokenCredential) (creatorClient, error)) func() {
	prev := newCreatorClient
	newCreatorClient = fn
	return func() { newCreatorClient = prev }
}

type fakeCreatorClient struct {
	createParams azkeys.CreateKeyParameters
	createName   string
	createErr    error
	createResp   azkeys.CreateKeyResponse
}

func (f *fakeCreatorClient) CreateKey(_ context.Context, name string, params azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	f.createName = name
	f.createParams = params
	if f.createErr != nil {
		return azkeys.CreateKeyResponse{}, f.createErr
	}
	return f.createResp, nil
}

func TestCreateKeyHappyPath(t *testing.T) {
	kid := azkeys.ID("https://myvault.vault.azure.net/keys/mykey/abc123")
	client := &fakeCreatorClient{
		createResp: azkeys.CreateKeyResponse{
			KeyBundle: azkeys.KeyBundle{
				Key: &azkeys.JSONWebKey{KID: &kid},
			},
		},
	}
	got, err := createKeyWithClient(context.Background(), client, CreateKeyParams{Vault: "myvault", Name: "mykey"})
	if err != nil {
		t.Fatalf("createKeyWithClient: %v", err)
	}
	if got != string(kid) {
		t.Errorf("returned resource %q, want %q", got, kid)
	}
	if client.createName != "mykey" {
		t.Errorf("CreateKey name = %q, want %q", client.createName, "mykey")
	}
	if client.createParams.Kty == nil || *client.createParams.Kty != azkeys.KeyTypeRSA {
		t.Errorf("Kty = %v, want RSA", client.createParams.Kty)
	}
	if client.createParams.KeySize == nil || *client.createParams.KeySize != 2048 {
		t.Errorf("KeySize = %v, want 2048", client.createParams.KeySize)
	}
}

func TestCreateKeyRejectsMissingFlags(t *testing.T) {
	if _, err := CreateKey(context.Background(), CreateKeyParams{Vault: "v"}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("expected required-fields error, got %v", err)
	}
	if _, err := CreateKey(context.Background(), CreateKeyParams{Name: "k"}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("expected required-fields error, got %v", err)
	}
}

func TestCreateKeyPropagatesAPIError(t *testing.T) {
	client := &fakeCreatorClient{createErr: errors.New("Forbidden: caller lacks keys/create")}
	_, err := createKeyWithClient(context.Background(), client, CreateKeyParams{Vault: "v", Name: "k"})
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("expected API error, got %v", err)
	}
}

func TestCreateKeyThroughInjectedClient(t *testing.T) {
	kid := azkeys.ID("https://myvault.vault.azure.net/keys/mykey/abc123")
	fake := &fakeCreatorClient{
		createResp: azkeys.CreateKeyResponse{
			KeyBundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{KID: &kid}},
		},
	}
	var gotVaultURL string
	t.Cleanup(swapCreatorClient(func(vaultURL string, _ azcore.TokenCredential) (creatorClient, error) {
		gotVaultURL = vaultURL
		return fake, nil
	}))

	// A bare vault name must be expanded to the full vault URL.
	got, err := CreateKey(context.Background(), CreateKeyParams{Vault: "myvault", Name: "mykey"})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if got != string(kid) {
		t.Errorf("CreateKey returned %q, want %q", got, kid)
	}
	if gotVaultURL != "https://myvault.vault.azure.net" {
		t.Errorf("vault URL = %q, want expanded form", gotVaultURL)
	}

	// A full URL must be passed through unchanged.
	if _, err := CreateKey(context.Background(), CreateKeyParams{Vault: "https://other.vault.azure.net", Name: "k"}); err != nil {
		t.Fatalf("CreateKey (full URL): %v", err)
	}
	if gotVaultURL != "https://other.vault.azure.net" {
		t.Errorf("full vault URL = %q, want passthrough", gotVaultURL)
	}
}

func TestCreateKeyClientConstructionError(t *testing.T) {
	t.Cleanup(swapCreatorClient(func(string, azcore.TokenCredential) (creatorClient, error) {
		return nil, errors.New("bad vault URL")
	}))
	_, err := CreateKey(context.Background(), CreateKeyParams{Vault: "v", Name: "k"})
	if err == nil || !strings.Contains(err.Error(), "create keyvault client") {
		t.Errorf("expected client-construction error, got %v", err)
	}
}
