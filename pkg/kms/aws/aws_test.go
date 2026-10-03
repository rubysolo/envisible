package aws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
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

	// lastGetPublicKeyInput is the most recent GetPublicKey request.
	lastGetPublicKeyInput *awskms.GetPublicKeyInput
}

func (f *fakeKMSAPI) GetPublicKey(_ context.Context, in *awskms.GetPublicKeyInput, _ ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error) {
	f.lastGetPublicKeyInput = in
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
	if in := api.lastGetPublicKeyInput; in == nil || in.KeyId == nil || *in.KeyId != resource {
		t.Errorf("GetPublicKey input = %+v, want KeyId %q", in, resource)
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

// swapKMSClient replaces the package-level read-path client constructor with fn
// and returns a restore func suitable for t.Cleanup.
func swapKMSClient(fn func(context.Context, string) (kmsAPI, error)) func() {
	prev := newKMSClient
	newKMSClient = fn
	return func() { newKMSClient = prev }
}

func TestNewUnwrapperThroughInjectedClient(t *testing.T) {
	_, api := newFakeAPI(t)
	var gotResource string
	t.Cleanup(swapKMSClient(func(_ context.Context, resource string) (kmsAPI, error) {
		gotResource = resource
		return api, nil
	}))

	resource := "arn:aws:kms:::key/x"
	u, err := newUnwrapper(context.Background(), &kms.PublicKeyInfo{Resource: resource})
	if err != nil {
		t.Fatalf("newUnwrapper: %v", err)
	}
	if u == nil {
		t.Fatal("newUnwrapper returned a nil unwrapper")
	}
	// The client is built per resource so its region can come from the ARN.
	if gotResource != resource {
		t.Errorf("newKMSClient resource = %q, want %q", gotResource, resource)
	}
}

func TestNewUnwrapperClientError(t *testing.T) {
	t.Cleanup(swapKMSClient(func(context.Context, string) (kmsAPI, error) {
		return nil, errors.New("no credentials")
	}))
	if _, err := newUnwrapper(context.Background(), &kms.PublicKeyInfo{Resource: "x"}); err == nil {
		t.Error("expected client-construction error")
	}
}

func TestFetchPublicKeyThroughInjectedClient(t *testing.T) {
	priv, api := newFakeAPI(t)
	var gotResource string
	t.Cleanup(swapKMSClient(func(_ context.Context, resource string) (kmsAPI, error) {
		gotResource = resource
		return api, nil
	}))

	resource := "arn:aws:kms:us-east-1:123456789012:key/abcd"
	info, err := fetchPublicKey(context.Background(), resource)
	if err != nil {
		t.Fatalf("fetchPublicKey: %v", err)
	}
	if gotResource != resource {
		t.Errorf("newKMSClient resource = %q, want %q", gotResource, resource)
	}
	if info.PubKey.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("returned public key does not match the fake's key")
	}
	if in := api.lastGetPublicKeyInput; in == nil || in.KeyId == nil || *in.KeyId != resource {
		t.Errorf("GetPublicKey input = %+v, want KeyId %q", in, resource)
	}
}

func TestFetchPublicKeyClientError(t *testing.T) {
	t.Cleanup(swapKMSClient(func(context.Context, string) (kmsAPI, error) {
		return nil, errors.New("no credentials")
	}))
	if _, err := fetchPublicKey(context.Background(), "x"); err == nil {
		t.Error("expected client-construction error")
	}
}

// The default client constructors build their SDK clients without any network
// round-trip (the AWS SDK resolves credentials lazily, on first call). Exercising
// them directly covers the real wiring rather than only the injected fakes.
func TestDefaultClientConstructorsAreOffline(t *testing.T) {
	if c, err := newKMSClient(context.Background(), "arn:aws:kms:us-east-1:123456789012:key/abcd"); err != nil || c == nil {
		t.Fatalf("newKMSClient: client=%v err=%v", c, err)
	}
	if c, err := newCreatorClient(context.Background(), "us-east-1"); err != nil || c == nil {
		t.Fatalf("newCreatorClient: client=%v err=%v", c, err)
	}
}

func TestRegionFromResource(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		want     string
	}{
		{"key ARN", "arn:aws:kms:eu-west-1:123456789012:key/abcd1234-ab12-cd34-ef56-1234567890ab", "eu-west-1"},
		{"alias ARN", "arn:aws:kms:us-west-2:123456789012:alias/my-app", "us-west-2"},
		{"aws-cn partition", "arn:aws-cn:kms:cn-north-1:123456789012:key/abcd", "cn-north-1"},
		{"aws-us-gov partition", "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/abcd", "us-gov-west-1"},
		{"alias name containing colons", "arn:aws:kms:ap-south-1:123456789012:alias/team:app", "ap-south-1"},
		{"bare key UUID", "abcd1234-ab12-cd34-ef56-1234567890ab", ""},
		{"bare alias name", "alias/my-app", ""},
		{"wrong service", "arn:aws:s3:us-east-1:123456789012:bucket/key", ""},
		{"not an ARN prefix", "urn:aws:kms:us-east-1:123456789012:key/abcd", ""},
		{"empty", "", ""},
		{"too few segments", "arn:aws:kms:us-east-1", ""},
		{"missing resource segment", "arn:aws:kms:us-east-1:123456789012", ""},
		{"empty region field", "arn:aws:kms::123456789012:key/abcd", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := regionFromResource(tt.resource); got != tt.want {
				t.Errorf("regionFromResource(%q) = %q, want %q", tt.resource, got, tt.want)
			}
		})
	}
}

// isolateAWSEnv points the real SDK config chain at nothing: no shared config
// or credentials files, no IMDS, no profile, and no ambient region. Dummy static
// credentials are set so nothing tries to resolve any. The tests that use it
// only inspect the constructed client; no request is ever sent.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	// t.Setenv first so the original value is restored on cleanup, then unset.
	for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_SESSION_TOKEN"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unsetenv %s: %v", name, err)
		}
	}
}

// clientRegion returns the region the real SDK client was configured with.
func clientRegion(t *testing.T, api kmsAPI) string {
	t.Helper()
	client, ok := api.(*awskms.Client)
	if !ok {
		t.Fatalf("newKMSClient returned %T, want *awskms.Client", api)
	}
	return client.Options().Region
}

// The region embedded in an ARN is authoritative: KMS keys are regional, so the
// request has to go to the key's region whatever the ambient SDK chain says.
func TestNewKMSClientTakesRegionFromARN(t *testing.T) {
	const resource = "arn:aws:kms:eu-west-1:123456789012:key/abcd1234-ab12-cd34-ef56-1234567890ab"

	t.Run("no ambient region", func(t *testing.T) {
		isolateAWSEnv(t)
		client, err := newKMSClient(context.Background(), resource)
		if err != nil {
			t.Fatalf("newKMSClient: %v", err)
		}
		if got := clientRegion(t, client); got != "eu-west-1" {
			t.Errorf("client region = %q, want %q", got, "eu-west-1")
		}
	})

	t.Run("overrides AWS_REGION", func(t *testing.T) {
		isolateAWSEnv(t)
		t.Setenv("AWS_REGION", "us-east-1")
		client, err := newKMSClient(context.Background(), resource)
		if err != nil {
			t.Fatalf("newKMSClient: %v", err)
		}
		if got := clientRegion(t, client); got != "eu-west-1" {
			t.Errorf("client region = %q, want %q", got, "eu-west-1")
		}
	})
}

// A resource with no region in it keeps the ambient SDK region, as before.
func TestNewKMSClientNonARNUsesAmbientRegion(t *testing.T) {
	for _, resource := range []string{"abcd1234-ab12-cd34-ef56-1234567890ab", "alias/my-app"} {
		t.Run(resource, func(t *testing.T) {
			isolateAWSEnv(t)
			t.Setenv("AWS_REGION", "ap-southeast-2")
			client, err := newKMSClient(context.Background(), resource)
			if err != nil {
				t.Fatalf("newKMSClient: %v", err)
			}
			if got := clientRegion(t, client); got != "ap-southeast-2" {
				t.Errorf("client region = %q, want %q", got, "ap-southeast-2")
			}
		})
	}
}

// With no region in the resource and none in the environment, fail up front
// with something actionable instead of the SDK's "Missing Region" at call time.
func TestNewKMSClientNoRegionAnywhere(t *testing.T) {
	isolateAWSEnv(t)
	const resource = "abcd1234-ab12-cd34-ef56-1234567890ab"

	client, err := newKMSClient(context.Background(), resource)
	if err == nil {
		t.Fatalf("expected a no-region error, got client %v", client)
	}
	want := `aws kms: no region for resource "` + resource + `" — use the full key ARN, or set AWS_REGION`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}

	// The same error reaches both callers of the constructor.
	if _, err := newUnwrapper(context.Background(), &kms.PublicKeyInfo{Resource: resource}); err == nil || err.Error() != want {
		t.Errorf("newUnwrapper error = %v, want %q", err, want)
	}
	if _, err := fetchPublicKey(context.Background(), resource); err == nil || err.Error() != want {
		t.Errorf("fetchPublicKey error = %v, want %q", err, want)
	}
}
