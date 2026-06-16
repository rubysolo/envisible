package gcp

import (
	"context"
	"fmt"
	"time"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

// CreateKeyParams holds the GCP-specific fields needed to provision a new key.
// The KeyRing must already exist — envisible doesn't create rings, only keys
// inside them. Use `gcloud kms keyrings create` or Terraform for the ring.
type CreateKeyParams struct {
	Project  string
	Location string
	Keyring  string
	Name     string
}

// creatorClient is the slice of *cloudkms.KeyManagementClient that CreateKey uses.
// Distinct from the read-path kmsClient so create-flow tests don't have to stub
// methods they don't exercise.
type creatorClient interface {
	CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error)
	GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	Close() error
}

// pollInterval and pollMaxAttempts are package vars so create tests can run fast
// without sleeping a full second between fake polls.
var (
	pollInterval    = time.Second
	pollMaxAttempts = 30
)

// CreateKey provisions an asymmetric ASYMMETRIC_DECRYPT key with algorithm
// RSA_DECRYPT_OAEP_2048_SHA256 and returns the resource string of its first
// CryptoKeyVersion (which envisible.pub then pins to).
// newCreatorClient builds the provisioning-path SDK client. As with newKMSClient,
// it's a package var so tests can inject a fake and cover CreateKey without
// Application Default Credentials.
var newCreatorClient = func(ctx context.Context) (creatorClient, error) {
	return cloudkms.NewKeyManagementClient(ctx)
}

func CreateKey(ctx context.Context, p CreateKeyParams) (string, error) {
	client, err := newCreatorClient(ctx)
	if err != nil {
		return "", fmt.Errorf("gcp kms: create client: %w", err)
	}
	defer client.Close()
	return createKeyWithClient(ctx, client, p)
}

func createKeyWithClient(ctx context.Context, client creatorClient, p CreateKeyParams) (string, error) {
	if p.Project == "" || p.Location == "" || p.Keyring == "" || p.Name == "" {
		return "", fmt.Errorf("gcp kms: --project, --location, --keyring, --name are all required")
	}
	parent := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", p.Project, p.Location, p.Keyring)
	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      parent,
		CryptoKeyId: p.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("gcp kms: create crypto key: %w", err)
	}
	if key.GetPrimary() == nil || key.GetPrimary().GetName() == "" {
		return "", fmt.Errorf("gcp kms: created key has no primary version")
	}

	versionName := key.GetPrimary().GetName()
	state := key.GetPrimary().GetState()

	// New software-backed versions are usually immediately ENABLED. HSM-backed
	// or external versions go through PENDING_GENERATION first; poll briefly.
	for i := 0; i < pollMaxAttempts && state != kmspb.CryptoKeyVersion_ENABLED; i++ {
		if state != kmspb.CryptoKeyVersion_PENDING_GENERATION {
			return "", fmt.Errorf("gcp kms: unexpected key version state %s", state)
		}
		time.Sleep(pollInterval)
		v, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: versionName})
		if err != nil {
			return "", fmt.Errorf("gcp kms: poll key version state: %w", err)
		}
		state = v.GetState()
	}
	if state != kmspb.CryptoKeyVersion_ENABLED {
		return "", fmt.Errorf("gcp kms: timed out waiting for key version to become ENABLED (last state: %s)", state)
	}
	return versionName, nil
}
