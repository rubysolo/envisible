package gcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/rubysolo/envisible/pkg/kms"
)

// fakeKMSClient stands in for *cloudkms.KeyManagementClient. AsymmetricDecrypt
// uses a local RSA private key so envelope round-trips can be exercised without
// real GCP credentials. CRC32C fields are populated to match what the live API
// would return — flip the crcSkew bit to simulate corruption.
type fakeKMSClient struct {
	priv      *rsa.PrivateKey
	algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm

	corruptPlaintextCRC bool
	corruptPemCRC       bool
	getPubKeyErr        error
	asymmetricErr       error

	closeCalled bool
}

func (f *fakeKMSClient) GetPublicKey(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	if f.getPubKeyErr != nil {
		return nil, f.getPubKeyErr
	}
	der, err := x509.MarshalPKIXPublicKey(&f.priv.PublicKey)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	crc := int64(crc32.Checksum(pemBytes, crc32cTable))
	if f.corruptPemCRC {
		crc++
	}
	return &kmspb.PublicKey{
		Pem:       string(pemBytes),
		Algorithm: f.algorithm,
		PemCrc32C: &wrapperspb.Int64Value{Value: crc},
	}, nil
}

func (f *fakeKMSClient) AsymmetricDecrypt(_ context.Context, req *kmspb.AsymmetricDecryptRequest, _ ...gax.CallOption) (*kmspb.AsymmetricDecryptResponse, error) {
	if f.asymmetricErr != nil {
		return nil, f.asymmetricErr
	}
	pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.priv, req.GetCiphertext(), nil)
	if err != nil {
		return nil, err
	}
	crc := int64(crc32.Checksum(pt, crc32cTable))
	if f.corruptPlaintextCRC {
		crc++
	}
	return &kmspb.AsymmetricDecryptResponse{
		Plaintext:       pt,
		PlaintextCrc32C: &wrapperspb.Int64Value{Value: crc},
	}, nil
}

func (f *fakeKMSClient) Close() error {
	f.closeCalled = true
	return nil
}

func newFakeClient(t *testing.T) (*rsa.PrivateKey, *fakeKMSClient) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return priv, &fakeKMSClient{
		priv:      priv,
		algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
	}
}

func TestInitRegistersGCP(t *testing.T) {
	if !kms.IsUnwrapperRegistered(kms.GCP) {
		t.Errorf("gcp.init() did not register an unwrapper for kms.GCP")
	}
	if !kms.IsBootstrapRegistered(kms.GCP) {
		t.Errorf("gcp.init() did not register a bootstrap fetcher for kms.GCP")
	}
}

func TestFetchPublicKeyHappyPath(t *testing.T) {
	priv, client := newFakeClient(t)

	info, err := fetchPublicKeyWithClient(context.Background(), client, "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
	if err != nil {
		t.Fatalf("fetchPublicKeyWithClient: %v", err)
	}
	if info.Kind != kms.GCP {
		t.Errorf("info.Kind = %v, want %v", info.Kind, kms.GCP)
	}
	if info.Alg != kms.RSAOAEPSHA256_2048 {
		t.Errorf("info.Alg = %v, want %v", info.Alg, kms.RSAOAEPSHA256_2048)
	}
	if info.PubKey.N.Cmp(priv.PublicKey.N) != 0 || info.PubKey.E != priv.PublicKey.E {
		t.Errorf("returned public key does not match fake's key")
	}
}

func TestFetchPublicKeyRejectsWrongAlgorithm(t *testing.T) {
	_, client := newFakeClient(t)
	client.algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512
	_, err := fetchPublicKeyWithClient(context.Background(), client, "ignored")
	if err == nil {
		t.Fatalf("expected algorithm rejection, got nil error")
	}
	if !strings.Contains(err.Error(), "unsupported key algorithm") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFetchPublicKeyDetectsPemCRCMismatch(t *testing.T) {
	_, client := newFakeClient(t)
	client.corruptPemCRC = true
	_, err := fetchPublicKeyWithClient(context.Background(), client, "ignored")
	if err == nil {
		t.Fatalf("expected CRC mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "CRC32C") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFetchPublicKeyPropagatesAPIError(t *testing.T) {
	_, client := newFakeClient(t)
	client.getPubKeyErr = errors.New("PERMISSION_DENIED: caller lacks cloudkms.cryptoKeyVersions.viewPublicKey")
	_, err := fetchPublicKeyWithClient(context.Background(), client, "ignored")
	if err == nil {
		t.Fatalf("expected API error to surface")
	}
	if !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Errorf("error did not preserve API message: %v", err)
	}
}

func TestUnwrapperRoundTrip(t *testing.T) {
	priv, client := newFakeClient(t)
	u := newUnwrapperWithClient(client, "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")

	dk := make([]byte, 32)
	if _, err := rand.Read(dk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, dk, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}

	got, err := u.Unwrap(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(got) != string(dk) {
		t.Errorf("Unwrap returned wrong plaintext")
	}
}

func TestUnwrapperDetectsPlaintextCRCMismatch(t *testing.T) {
	priv, client := newFakeClient(t)
	client.corruptPlaintextCRC = true
	u := newUnwrapperWithClient(client, "ignored")

	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, make([]byte, 32), nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}
	_, err = u.Unwrap(context.Background(), wrapped)
	if err == nil || !strings.Contains(err.Error(), "CRC32C") {
		t.Errorf("expected CRC mismatch error, got %v", err)
	}
}

func TestUnwrapperPropagatesAPIError(t *testing.T) {
	_, client := newFakeClient(t)
	client.asymmetricErr = errors.New("NOT_FOUND: key version was destroyed")
	u := newUnwrapperWithClient(client, "ignored")
	_, err := u.Unwrap(context.Background(), []byte("anything"))
	if err == nil || !strings.Contains(err.Error(), "NOT_FOUND") {
		t.Errorf("expected API error, got %v", err)
	}
}
