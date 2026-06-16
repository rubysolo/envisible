package azure

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/rubysolo/envisible/pkg/kms"
)

// swapKeyVaultClient replaces the package-level keyvault client constructor with
// fn and returns a restore func suitable for t.Cleanup.
func swapKeyVaultClient(fn func(string, azcore.TokenCredential) (kvClient, error)) func() {
	prev := newKeyVaultClient
	newKeyVaultClient = fn
	return func() { newKeyVaultClient = prev }
}

// fakeKVClient stands in for *azkeys.Client. Decrypt uses a local RSA key so
// envelope round-trips can be exercised offline. The last name/version/algorithm
// passed to Decrypt are recorded so tests can assert the SDK call shape.
type fakeKVClient struct {
	priv *rsa.PrivateKey
	kty  azkeys.KeyType

	getKeyErr  error
	decryptErr error

	lastName    string
	lastVersion string
	lastAlg     *azkeys.EncryptionAlgorithm
	calls       int
}

func (f *fakeKVClient) GetKey(_ context.Context, name, version string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	if f.getKeyErr != nil {
		return azkeys.GetKeyResponse{}, f.getKeyErr
	}
	kty := f.kty
	nBytes := f.priv.PublicKey.N.Bytes()
	eBytes := big.NewInt(int64(f.priv.PublicKey.E)).Bytes()
	return azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Key: &azkeys.JSONWebKey{
				Kty: &kty,
				N:   nBytes,
				E:   eBytes,
			},
		},
	}, nil
}

func (f *fakeKVClient) Decrypt(_ context.Context, name, version string, params azkeys.KeyOperationParameters, _ *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	f.calls++
	f.lastName = name
	f.lastVersion = version
	f.lastAlg = params.Algorithm
	if f.decryptErr != nil {
		return azkeys.DecryptResponse{}, f.decryptErr
	}
	pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.priv, params.Value, nil)
	if err != nil {
		return azkeys.DecryptResponse{}, err
	}
	return azkeys.DecryptResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: pt}}, nil
}

func newFakeClient(t *testing.T) (*rsa.PrivateKey, *fakeKVClient) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return priv, &fakeKVClient{priv: priv, kty: azkeys.KeyTypeRSA}
}

func TestInitRegistersAzure(t *testing.T) {
	if !kms.IsUnwrapperRegistered(kms.Azure) {
		t.Errorf("azure.init() did not register an unwrapper for kms.Azure")
	}
	if !kms.IsBootstrapRegistered(kms.Azure) {
		t.Errorf("azure.init() did not register a bootstrap fetcher for kms.Azure")
	}
}

func TestParseAzureResource(t *testing.T) {
	cases := map[string]struct {
		in        string
		wantVault string
		wantName  string
		wantVer   string
		wantErr   bool
	}{
		"happy":           {"https://myvault.vault.azure.net/keys/mykey/abc123", "https://myvault.vault.azure.net", "mykey", "abc123", false},
		"trailing_slash":  {"https://v.vault.azure.net/keys/k/v/", "https://v.vault.azure.net", "k", "v", false},
		"http_not_https":  {"http://v.vault.azure.net/keys/k/v", "", "", "", true},
		"missing_version": {"https://v.vault.azure.net/keys/k", "", "", "", true},
		"wrong_path_root": {"https://v.vault.azure.net/secrets/k/v", "", "", "", true},
		"empty":           {"", "", "", "", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseAzureResource(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got %+v", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAzureResource(%q): %v", tc.in, err)
			}
			if got.vaultURL != tc.wantVault || got.name != tc.wantName || got.version != tc.wantVer {
				t.Errorf("parseAzureResource(%q) = %+v, want vault=%q name=%q version=%q", tc.in, got, tc.wantVault, tc.wantName, tc.wantVer)
			}
		})
	}
}

func TestFetchPublicKeyHappyPath(t *testing.T) {
	priv, api := newFakeClient(t)
	resource := "https://myvault.vault.azure.net/keys/mykey/v1"
	res, _ := parseAzureResource(resource)

	info, err := fetchPublicKeyWithClient(context.Background(), api, resource, res)
	if err != nil {
		t.Fatalf("fetchPublicKeyWithClient: %v", err)
	}
	if info.Kind != kms.Azure || info.Resource != resource {
		t.Errorf("info metadata mismatch: %+v", info)
	}
	if info.PubKey.N.Cmp(priv.PublicKey.N) != 0 || info.PubKey.E != priv.PublicKey.E {
		t.Errorf("returned public key does not match fake's key")
	}
}

func TestFetchPublicKeyRejectsNonRSA(t *testing.T) {
	_, api := newFakeClient(t)
	api.kty = azkeys.KeyTypeEC

	res, _ := parseAzureResource("https://v.vault.azure.net/keys/k/v")
	_, err := fetchPublicKeyWithClient(context.Background(), api, "https://v.vault.azure.net/keys/k/v", res)
	if err == nil || !strings.Contains(err.Error(), "not RSA") {
		t.Errorf("expected non-RSA rejection, got %v", err)
	}
}

func TestFetchPublicKeyRejectsWrongKeySize(t *testing.T) {
	// Build a fake whose modulus is RSA-1024 — must be rejected at bootstrap.
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	api := &fakeKVClient{priv: priv, kty: azkeys.KeyTypeRSA}
	res, _ := parseAzureResource("https://v.vault.azure.net/keys/k/v")
	_, err = fetchPublicKeyWithClient(context.Background(), api, "https://v.vault.azure.net/keys/k/v", res)
	if err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("expected key-size rejection, got %v", err)
	}
}

func TestFetchPublicKeyPropagatesAPIError(t *testing.T) {
	_, api := newFakeClient(t)
	api.getKeyErr = errors.New("Forbidden: caller does not have keys/get permission")
	res, _ := parseAzureResource("https://v.vault.azure.net/keys/k/v")
	_, err := fetchPublicKeyWithClient(context.Background(), api, "https://v.vault.azure.net/keys/k/v", res)
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("expected API error to surface, got %v", err)
	}
}

func TestUnwrapperRoundTrip(t *testing.T) {
	priv, api := newFakeClient(t)
	res, _ := parseAzureResource("https://myvault.vault.azure.net/keys/mykey/v1")
	u := newUnwrapperWithClient(api, res)

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

	// Assert the SDK call was shaped correctly — Azure splits resource into
	// name/version arguments rather than a single ARN-style string.
	if api.lastName != "mykey" || api.lastVersion != "v1" {
		t.Errorf("Decrypt name/version = %q/%q, want mykey/v1", api.lastName, api.lastVersion)
	}
	if api.lastAlg == nil || *api.lastAlg != azkeys.EncryptionAlgorithmRSAOAEP256 {
		t.Errorf("Decrypt algorithm = %v, want RSA-OAEP-256", api.lastAlg)
	}
}

func TestUnwrapperPropagatesAPIError(t *testing.T) {
	_, api := newFakeClient(t)
	api.decryptErr = errors.New("KeyNotFound: key version was destroyed")
	res, _ := parseAzureResource("https://v.vault.azure.net/keys/k/v")
	u := newUnwrapperWithClient(api, res)

	_, err := u.Unwrap(context.Background(), []byte("anything"))
	if err == nil || !strings.Contains(err.Error(), "KeyNotFound") {
		t.Errorf("expected API error to surface, got %v", err)
	}
}

func TestNewCredential(t *testing.T) {
	// DefaultAzureCredential constructs without any network round-trip — it only
	// reaches out when a token is first requested. So this exercises the wiring
	// without depending on a live Azure environment.
	cred, err := newCredential()
	if err != nil {
		t.Fatalf("newCredential: %v", err)
	}
	if cred == nil {
		t.Fatal("newCredential returned a nil credential")
	}
}

func TestNewUnwrapperRejectsBadResource(t *testing.T) {
	_, err := newUnwrapper(context.Background(), &kms.PublicKeyInfo{Resource: "not-a-url"})
	if err == nil || !strings.Contains(err.Error(), "azure") {
		t.Errorf("expected resource parse error, got %v", err)
	}
}

func TestNewUnwrapperBuildsClient(t *testing.T) {
	// A valid resource must yield a usable unwrapper. Client construction is
	// offline; the SDK only dials on the first Decrypt call, which we don't make.
	u, err := newUnwrapper(context.Background(), &kms.PublicKeyInfo{
		Resource: "https://myvault.vault.azure.net/keys/mykey/v1",
	})
	if err != nil {
		t.Fatalf("newUnwrapper: %v", err)
	}
	if u == nil {
		t.Fatal("newUnwrapper returned a nil unwrapper")
	}
}

func TestFetchPublicKeyRejectsBadResource(t *testing.T) {
	if _, err := fetchPublicKey(context.Background(), "not-a-url"); err == nil {
		t.Error("expected resource parse error for malformed resource")
	}
}

func TestFetchPublicKeyThroughInjectedClient(t *testing.T) {
	priv, api := newFakeClient(t)
	t.Cleanup(swapKeyVaultClient(func(string, azcore.TokenCredential) (kvClient, error) {
		return api, nil
	}))

	resource := "https://myvault.vault.azure.net/keys/mykey/v1"
	info, err := fetchPublicKey(context.Background(), resource)
	if err != nil {
		t.Fatalf("fetchPublicKey: %v", err)
	}
	if info.PubKey.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("returned public key does not match the fake's key")
	}
}

func TestFetchPublicKeyClientConstructionError(t *testing.T) {
	t.Cleanup(swapKeyVaultClient(func(string, azcore.TokenCredential) (kvClient, error) {
		return nil, errors.New("bad vault URL")
	}))
	_, err := fetchPublicKey(context.Background(), "https://v.vault.azure.net/keys/k/v")
	if err == nil || !strings.Contains(err.Error(), "create keyvault client") {
		t.Errorf("expected client-construction error, got %v", err)
	}
}

func TestJWKToRSAPublicKeyErrors(t *testing.T) {
	rsaKty := azkeys.KeyTypeRSA
	ecKty := azkeys.KeyTypeEC
	cases := map[string]struct {
		jwk  *azkeys.JSONWebKey
		want string
	}{
		"nil_kty":   {&azkeys.JSONWebKey{N: []byte{1, 0, 0}, E: []byte{1, 0, 1}}, "no Kty"},
		"not_rsa":   {&azkeys.JSONWebKey{Kty: &ecKty, N: []byte{1, 0, 0}, E: []byte{1, 0, 1}}, "not RSA"},
		"missing_n": {&azkeys.JSONWebKey{Kty: &rsaKty, E: []byte{1, 0, 1}}, "missing RSA modulus"},
		"zero_exp":  {&azkeys.JSONWebKey{Kty: &rsaKty, N: []byte{1, 0, 0}, E: []byte{0}}, "exponent is invalid"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := jwkToRSAPublicKey(tc.jwk); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("jwkToRSAPublicKey: got %v, want error containing %q", err, tc.want)
			}
		})
	}
}
