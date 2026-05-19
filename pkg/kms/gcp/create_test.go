package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

type fakeCreatorClient struct {
	createReq          *kmspb.CreateCryptoKeyRequest
	createResp         *kmspb.CryptoKey
	createErr          error
	getVersionResponse *kmspb.CryptoKeyVersion
	getVersionErr      error
	getVersionCalls    int
}

func (f *fakeCreatorClient) CreateCryptoKey(_ context.Context, req *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.createReq = req
	if f.createErr != nil {
		return nil, f.createErr
	}
	return f.createResp, nil
}

func (f *fakeCreatorClient) GetCryptoKeyVersion(_ context.Context, _ *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.getVersionCalls++
	if f.getVersionErr != nil {
		return nil, f.getVersionErr
	}
	return f.getVersionResponse, nil
}

func (f *fakeCreatorClient) Close() error { return nil }

func TestCreateKeyHappyPath(t *testing.T) {
	versionName := "projects/p/locations/us/keyRings/r/cryptoKeys/mykey/cryptoKeyVersions/1"
	client := &fakeCreatorClient{
		createResp: &kmspb.CryptoKey{
			Name: "projects/p/locations/us/keyRings/r/cryptoKeys/mykey",
			Primary: &kmspb.CryptoKeyVersion{
				Name:  versionName,
				State: kmspb.CryptoKeyVersion_ENABLED,
			},
		},
	}

	got, err := createKeyWithClient(context.Background(), client, CreateKeyParams{
		Project: "p", Location: "us", Keyring: "r", Name: "mykey",
	})
	if err != nil {
		t.Fatalf("createKeyWithClient: %v", err)
	}
	if got != versionName {
		t.Errorf("got resource %q, want %q", got, versionName)
	}
	if client.createReq.GetCryptoKey().GetPurpose() != kmspb.CryptoKey_ASYMMETRIC_DECRYPT {
		t.Errorf("purpose = %v, want ASYMMETRIC_DECRYPT", client.createReq.GetCryptoKey().GetPurpose())
	}
	if client.createReq.GetCryptoKey().GetVersionTemplate().GetAlgorithm() != kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256 {
		t.Errorf("algorithm = %v, want RSA_DECRYPT_OAEP_2048_SHA256", client.createReq.GetCryptoKey().GetVersionTemplate().GetAlgorithm())
	}
	if client.getVersionCalls != 0 {
		t.Errorf("GetCryptoKeyVersion called %d times for already-ENABLED key", client.getVersionCalls)
	}
}

func TestCreateKeyPollsWhilePending(t *testing.T) {
	// Speed up polling so the test doesn't sleep a full second per attempt.
	oldInterval, oldAttempts := pollInterval, pollMaxAttempts
	pollInterval = time.Millisecond
	pollMaxAttempts = 5
	defer func() { pollInterval, pollMaxAttempts = oldInterval, oldAttempts }()

	versionName := "projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
	client := &fakeCreatorClient{
		createResp: &kmspb.CryptoKey{
			Primary: &kmspb.CryptoKeyVersion{
				Name:  versionName,
				State: kmspb.CryptoKeyVersion_PENDING_GENERATION,
			},
		},
		getVersionResponse: &kmspb.CryptoKeyVersion{
			Name:  versionName,
			State: kmspb.CryptoKeyVersion_ENABLED,
		},
	}
	got, err := createKeyWithClient(context.Background(), client, CreateKeyParams{
		Project: "p", Location: "us", Keyring: "r", Name: "k",
	})
	if err != nil {
		t.Fatalf("createKeyWithClient: %v", err)
	}
	if got != versionName {
		t.Errorf("got %q, want %q", got, versionName)
	}
	if client.getVersionCalls == 0 {
		t.Errorf("expected at least one poll, got zero")
	}
}

func TestCreateKeyRejectsMissingFlags(t *testing.T) {
	_, err := createKeyWithClient(context.Background(), &fakeCreatorClient{}, CreateKeyParams{Project: "p"})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("expected required-fields error, got %v", err)
	}
}

func TestCreateKeyPropagatesAPIError(t *testing.T) {
	client := &fakeCreatorClient{createErr: errors.New("PERMISSION_DENIED: caller lacks cloudkms.cryptoKeys.create")}
	_, err := createKeyWithClient(context.Background(), client, CreateKeyParams{
		Project: "p", Location: "us", Keyring: "r", Name: "k",
	})
	if err == nil || !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Errorf("expected API error, got %v", err)
	}
}

