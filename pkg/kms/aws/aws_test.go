package aws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/rubysolo/envisible/pkg/kms"
)

// fakeKMSAPI stands in for *awskms.Client. Decrypt uses a local RSA key so the
// envelope round-trip can be exercised offline. The last KeyId and EncryptionAlgorithm
// passed to Decrypt are recorded so tests can assert the AWS-specific contract.
type fakeKMSAPI struct {
	priv *rsa.PrivateKey

	keySpec        types.KeySpec
	keyUsage       types.KeyUsageType
	encryptionAlgs []types.EncryptionAlgorithmSpec
	getPubKeyErr   error
	decryptErr     error

	lastKeyID     *string
	lastEncAlg    types.EncryptionAlgorithmSpec
	decryptCalled int
}

func (f *fakeKMSAPI) GetPublicKey(_ context.Context, _ *awskms.GetPublicKeyInput, _ ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error) {
	if f.getPubKeyErr != nil {
		return nil, f.getPubKeyErr
	}
	der, err := x509.MarshalPKIXPublicKey(&f.priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &awskms.GetPublicKeyOutput{
		PublicKey:            der,
		KeySpec:              f.keySpec,
		KeyUsage:             f.keyUsage,
		EncryptionAlgorithms: f.encryptionAlgs,
	}, nil
}

func (f *fakeKMSAPI) Decrypt(_ context.Context, in *awskms.DecryptInput, _ ...func(*awskms.Options)) (*awskms.DecryptOutput, error) {
	f.decryptCalled++
	f.lastKeyID = in.KeyId
	f.lastEncAlg = in.EncryptionAlgorithm
	if f.decryptErr != nil {
		return nil, f.decryptErr
	}
	pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.priv, in.CiphertextBlob, nil)
	if err != nil {
		return nil, err
	}
	return &awskms.DecryptOutput{Plaintext: pt}, nil
}

func newFakeAPI(t *testing.T) (*rsa.PrivateKey, *fakeKMSAPI) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return priv, &fakeKMSAPI{
		priv:           priv,
		keySpec:        types.KeySpecRsa2048,
		keyUsage:       types.KeyUsageTypeEncryptDecrypt,
		encryptionAlgs: []types.EncryptionAlgorithmSpec{types.EncryptionAlgorithmSpecRsaesOaepSha256},
	}
}

func TestInitRegistersAWS(t *testing.T) {
	if !kms.IsUnwrapperRegistered(kms.AWS) {
		t.Errorf("aws.init() did not register an unwrapper for kms.AWS")
	}
	if !kms.IsBootstrapRegistered(kms.AWS) {
		t.Errorf("aws.init() did not register a bootstrap fetcher for kms.AWS")
	}
}

func TestFetchPublicKeyHappyPath(t *testing.T) {
	priv, api := newFakeAPI(t)
	resource := "arn:aws:kms:us-east-1:123456789012:key/abcd1234-ab12-cd34-ef56-1234567890ab"

	info, err := fetchPublicKeyWithClient(context.Background(), api, resource)
	if err != nil {
		t.Fatalf("fetchPublicKeyWithClient: %v", err)
	}
	if info.Kind != kms.AWS {
		t.Errorf("info.Kind = %v, want %v", info.Kind, kms.AWS)
	}
	if info.Resource != resource {
		t.Errorf("info.Resource = %q, want %q", info.Resource, resource)
	}
	if info.PubKey.N.Cmp(priv.PublicKey.N) != 0 {
		t.Errorf("returned public key does not match fake's key")
	}
}

func TestFetchPublicKeyRejectsWrongKeySpec(t *testing.T) {
	_, api := newFakeAPI(t)
	api.keySpec = types.KeySpecRsa4096

	_, err := fetchPublicKeyWithClient(context.Background(), api, "ignored")
	if err == nil || !strings.Contains(err.Error(), "key spec") {
		t.Errorf("expected key spec rejection, got %v", err)
	}
}

func TestFetchPublicKeyRejectsWrongKeyUsage(t *testing.T) {
	_, api := newFakeAPI(t)
	api.keyUsage = types.KeyUsageTypeSignVerify

	_, err := fetchPublicKeyWithClient(context.Background(), api, "ignored")
	if err == nil || !strings.Contains(err.Error(), "key usage") {
		t.Errorf("expected key usage rejection, got %v", err)
	}
}

func TestFetchPublicKeyRejectsMissingOAEPSHA256(t *testing.T) {
	_, api := newFakeAPI(t)
	api.encryptionAlgs = []types.EncryptionAlgorithmSpec{types.EncryptionAlgorithmSpecRsaesOaepSha1}

	_, err := fetchPublicKeyWithClient(context.Background(), api, "ignored")
	if err == nil || !strings.Contains(err.Error(), "RSAES_OAEP_SHA_256") {
		t.Errorf("expected algorithm rejection, got %v", err)
	}
}

func TestFetchPublicKeyPropagatesAPIError(t *testing.T) {
	_, api := newFakeAPI(t)
	api.getPubKeyErr = errors.New("AccessDeniedException: caller lacks kms:GetPublicKey")

	_, err := fetchPublicKeyWithClient(context.Background(), api, "ignored")
	if err == nil || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Errorf("expected API error to surface, got %v", err)
	}
}

func TestUnwrapperRoundTrip(t *testing.T) {
	priv, api := newFakeAPI(t)
	resource := "arn:aws:kms:us-east-1:111122223333:key/uuid-here"
	u := newUnwrapperWithClient(api, resource)

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

	// The AWS-specific footgun: KeyId and EncryptionAlgorithm must be passed
	// even when the ciphertext is self-identifying. Verify we did.
	if api.lastKeyID == nil || *api.lastKeyID != resource {
		t.Errorf("Decrypt KeyId = %v, want %q", api.lastKeyID, resource)
	}
	if api.lastEncAlg != types.EncryptionAlgorithmSpecRsaesOaepSha256 {
		t.Errorf("Decrypt EncryptionAlgorithm = %v, want %v", api.lastEncAlg, types.EncryptionAlgorithmSpecRsaesOaepSha256)
	}
}

func TestUnwrapperPropagatesAPIError(t *testing.T) {
	_, api := newFakeAPI(t)
	api.decryptErr = errors.New("KMSInvalidStateException: key is pending deletion")
	u := newUnwrapperWithClient(api, "ignored")

	_, err := u.Unwrap(context.Background(), []byte("anything"))
	if err == nil || !strings.Contains(err.Error(), "KMSInvalidStateException") {
		t.Errorf("expected API error to surface, got %v", err)
	}
}
