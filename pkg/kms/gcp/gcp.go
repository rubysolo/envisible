// Package gcp implements the pkg/kms provider interfaces for Google Cloud KMS.
//
// Importing this package registers GCP with the kms provider registry via init().
// Callers normally don't reference any symbols here directly:
//
//	import _ "github.com/rubysolo/envisible/pkg/kms/gcp"
//
// Authentication uses Application Default Credentials (ADC) — gcloud auth, service
// account JSON via GOOGLE_APPLICATION_CREDENTIALS, workload identity in GKE, etc.
package gcp

import (
	"context"
	"fmt"
	"hash/crc32"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"

	"github.com/rubysolo/envisible/pkg/kms"
)

func init() {
	kms.RegisterUnwrapper(kms.GCP, newUnwrapper)
	kms.RegisterBootstrap(kms.GCP, fetchPublicKey)
}

// kmsClient is the subset of *cloudkms.KeyManagementClient we depend on. Exposed
// as an interface so tests can substitute a fake without the SDK's mock plumbing.
type kmsClient interface {
	AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...gax.CallOption) (*kmspb.AsymmetricDecryptResponse, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
	Close() error
}

// crc32cTable is the polynomial GCP KMS uses for integrity checksums.
// Verifying the response checksum is GCP's recommended defense against the
// network or SDK silently corrupting a payload.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// newKMSClient builds the read-path SDK client. It's a package var rather than a
// direct call so tests can inject a fake and exercise newUnwrapper/fetchPublicKey
// end-to-end without Application Default Credentials.
var newKMSClient = func(ctx context.Context) (kmsClient, error) {
	return cloudkms.NewKeyManagementClient(ctx)
}

func newUnwrapper(ctx context.Context, info *kms.PublicKeyInfo) (kms.Unwrapper, error) {
	client, err := newKMSClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp kms: create client: %w", err)
	}
	return newUnwrapperWithClient(client, info.Resource), nil
}

func newUnwrapperWithClient(client kmsClient, resource string) *unwrapper {
	return &unwrapper{client: client, resource: resource}
}

type unwrapper struct {
	client   kmsClient
	resource string
}

func (u *unwrapper) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	resp, err := u.client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:       u.resource,
		Ciphertext: wrapped,
	})
	if err != nil {
		return nil, fmt.Errorf("gcp kms: asymmetric decrypt: %w", err)
	}
	if crcWrapper := resp.GetPlaintextCrc32C(); crcWrapper != nil {
		want := crcWrapper.GetValue()
		got := int64(crc32.Checksum(resp.GetPlaintext(), crc32cTable))
		if want != got {
			return nil, fmt.Errorf("gcp kms: plaintext CRC32C mismatch (got %d, want %d) — discard and retry", got, want)
		}
	}
	return resp.GetPlaintext(), nil
}

func fetchPublicKey(ctx context.Context, resource string) (*kms.PublicKeyInfo, error) {
	client, err := newKMSClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp kms: create client: %w", err)
	}
	defer client.Close()
	return fetchPublicKeyWithClient(ctx, client, resource)
}

func fetchPublicKeyWithClient(ctx context.Context, client kmsClient, resource string) (*kms.PublicKeyInfo, error) {
	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: resource})
	if err != nil {
		return nil, fmt.Errorf("gcp kms: get public key: %w", err)
	}
	if got := resp.GetAlgorithm(); got != kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256 {
		return nil, fmt.Errorf("gcp kms: unsupported key algorithm %s (expected RSA_DECRYPT_OAEP_2048_SHA256)", got)
	}
	if crcWrapper := resp.GetPemCrc32C(); crcWrapper != nil {
		want := crcWrapper.GetValue()
		got := int64(crc32.Checksum([]byte(resp.GetPem()), crc32cTable))
		if want != got {
			return nil, fmt.Errorf("gcp kms: public key PEM CRC32C mismatch (got %d, want %d)", got, want)
		}
	}
	pub, err := kms.ParseRSAPublicKeyPEM(resp.GetPem())
	if err != nil {
		return nil, err
	}
	return &kms.PublicKeyInfo{
		Kind:     kms.GCP,
		Resource: resource,
		Alg:      kms.RSAOAEPSHA256_2048,
		PubKey:   pub,
	}, nil
}
