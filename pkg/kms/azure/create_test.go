package azure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

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
