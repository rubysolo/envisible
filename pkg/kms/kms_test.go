package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeUnwrapper performs RSA-OAEP-SHA-256 unwrap locally using the matching
// private key. Used to exercise the envelope round-trip without a real KMS.
type fakeUnwrapper struct {
	priv *rsa.PrivateKey
	err  error // optional injected failure
}

func (f *fakeUnwrapper) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, f.priv, wrapped, nil)
}

func generateRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return priv
}

func TestRSAWrapperRoundTrip(t *testing.T) {
	priv := generateRSAKey(t, 2048)
	w := NewRSAWrapper(&priv.PublicKey)
	if got := w.WrappedSize(); got != 256 {
		t.Errorf("WrappedSize() = %d, want 256", got)
	}

	dk := make([]byte, 32)
	if _, err := rand.Read(dk); err != nil {
		t.Fatalf("rand: %v", err)
	}

	wrapped, err := w.Wrap(dk)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if len(wrapped) != w.WrappedSize() {
		t.Errorf("wrapped length = %d, want %d", len(wrapped), w.WrappedSize())
	}

	unwrapper := &fakeUnwrapper{priv: priv}
	got, err := unwrapper.Unwrap(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(got) != string(dk) {
		t.Errorf("unwrapped DK mismatch")
	}
}

func TestValidateAlgorithm(t *testing.T) {
	priv2048 := generateRSAKey(t, 2048)
	priv1024 := generateRSAKey(t, 1024)

	if err := ValidateAlgorithm(RSAOAEPSHA256_2048, &priv2048.PublicKey); err != nil {
		t.Errorf("RSA-2048 should validate: %v", err)
	}
	if err := ValidateAlgorithm(RSAOAEPSHA256_2048, &priv1024.PublicKey); err == nil {
		t.Errorf("RSA-1024 should be rejected for RSAOAEPSHA256_2048")
	}
	if err := ValidateAlgorithm(Algorithm("nope"), &priv2048.PublicKey); err == nil {
		t.Errorf("unknown algorithm should be rejected")
	}
}

func TestLoadPublicKeyV1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "envisible.pub")

	// Write a legacy v1 file: base64-encoded 32-byte key, no trailing newline.
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw[:])), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	info, key, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if info != nil {
		t.Errorf("v1 file produced non-nil PublicKeyInfo")
	}
	if key == nil {
		t.Fatalf("v1 file produced nil [32]byte")
	}
	if *key != raw {
		t.Errorf("loaded key mismatch")
	}
}

func TestLoadPublicKeyV1WithTrailingWhitespace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "envisible.pub")

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// Some editors append a trailing newline; legacy files should still load.
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw[:])+"\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, key, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if key == nil || *key != raw {
		t.Errorf("trailing whitespace broke v1 load")
	}
}

func TestWriteLoadPublicKeyV2RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "envisible.pub")

	priv := generateRSAKey(t, 2048)
	original := &PublicKeyInfo{
		Kind:     GCP,
		Resource: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
		Alg:      RSAOAEPSHA256_2048,
		PubKey:   &priv.PublicKey,
	}

	if err := WritePublicKey(path, original); err != nil {
		t.Fatalf("WritePublicKey: %v", err)
	}

	info, key, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if key != nil {
		t.Errorf("v2 file produced non-nil legacy key")
	}
	if info == nil {
		t.Fatalf("v2 file produced nil PublicKeyInfo")
	}
	if info.Kind != GCP || info.Resource != original.Resource || info.Alg != RSAOAEPSHA256_2048 {
		t.Errorf("metadata mismatch: %+v", info)
	}
	if info.PubKey.N.Cmp(priv.PublicKey.N) != 0 || info.PubKey.E != priv.PublicKey.E {
		t.Errorf("public key mismatch after round trip")
	}
}

// validDescriptor returns the fields of a v2 envisible.pub that loads cleanly.
// The descriptor tests change one field at a time, so each case can only fail
// at the check for the field it changed.
func validDescriptor(t *testing.T) map[string]any {
	t.Helper()
	priv := generateRSAKey(t, 2048)
	return map[string]any{
		"version":    2,
		"provider":   "gcp",
		"resource":   "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
		"algorithm":  string(RSAOAEPSHA256_2048),
		"public_key": pkixPEM(t, &priv.PublicKey),
	}
}

// pkixPEM encodes any public key the way WritePublicKey encodes an RSA one.
func pkixPEM(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func writeDescriptor(t *testing.T, fields map[string]any) string {
	t.Helper()
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	path := filepath.Join(t.TempDir(), "envisible.pub")
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoadPublicKeyValidDescriptorLoads(t *testing.T) {
	// The base every rejection case below is derived from must itself load,
	// or those cases would prove nothing about the field they change.
	fields := validDescriptor(t)
	info, key, err := LoadPublicKey(writeDescriptor(t, fields))
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if key != nil || info == nil {
		t.Fatalf("valid v2 descriptor loaded as info=%v key=%v", info, key)
	}
	if info.Kind != GCP || info.Resource != fields["resource"] || info.Alg != RSAOAEPSHA256_2048 {
		t.Errorf("metadata mismatch: %+v", info)
	}
}

func TestLoadPublicKeyRejectsInvalidDescriptorField(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	cases := map[string]struct {
		field string
		value any
		want  string // substring the error must carry, naming the bad field
	}{
		"future_version":    {"version", 3, "version"},
		"zero_version":      {"version", 0, "version"},
		"unknown_provider":  {"provider", "icloud", "provider"},
		"empty_provider":    {"provider", "", "provider"},
		"empty_resource":    {"resource", "", "resource"},
		"blank_resource":    {"resource", "  ", "resource"},
		"unknown_algorithm": {"algorithm", "RSA-OAEP-SHA1", "algorithm"},
		"empty_algorithm":   {"algorithm", "", "algorithm"},
		"rsa_1024_key":      {"public_key", pkixPEM(t, &generateRSAKey(t, 1024).PublicKey), "1024-bit"},
		"ec_key":            {"public_key", pkixPEM(t, &ecPriv.PublicKey), "not RSA"},
		"not_a_pem_block":   {"public_key", "not-a-pem-block", "PEM"},
		"empty_public_key":  {"public_key", "", "PEM"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fields := validDescriptor(t)
			fields[tc.field] = tc.value

			info, key, err := LoadPublicKey(writeDescriptor(t, fields))
			if err == nil {
				t.Fatalf("descriptor with %s=%v loaded: info=%+v key=%v", tc.field, tc.value, info, key)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadPublicKeyIgnoresUnknownDescriptorField(t *testing.T) {
	// encoding/json drops fields it does not know, so a descriptor written by
	// a newer envisible that adds one still loads here. Pinned so that cannot
	// change by accident (e.g. by switching to DisallowUnknownFields).
	fields := validDescriptor(t)
	fields["key_origin"] = "hsm"

	info, _, err := LoadPublicKey(writeDescriptor(t, fields))
	if err != nil {
		t.Fatalf("descriptor with an unknown field was rejected: %v", err)
	}
	if info == nil || info.Resource != fields["resource"] {
		t.Errorf("descriptor with an unknown field loaded wrong: %+v", info)
	}
}

func TestLoadPublicKeyRejectsUnparseableFiles(t *testing.T) {
	dir := t.TempDir()

	cases := map[string]string{
		"malformed_json":   `{"version": 2, "provider": "gcp"`,
		"truncated_base64": "this is not valid base64 of 32 bytes",
		"empty_file":       "",
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, _, err := LoadPublicKey(path); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}

// goldenDescriptorModulus is the modulus of the key in
// testdata/envisible.pub.v2.golden, as printed by the generator.
const goldenDescriptorModulus = "f13a2f999b8cd658302f52c20e4bdca29242927b2e26de34d0fb5c294f7c57e0" +
	"0ca5d3704408237e80533617c03e1fa464635f7353fb6eabfcbf19b53f4e1453" +
	"adae5858f8f500649aa4b9e760fb5a917a5484f80abaee6f185af2acd6ca7c5d" +
	"6f7515c6de6ec86efbd151da6f1631694426d5e4a5c479fa01e6c51589c2b00c" +
	"fb8d32474831bb3159d0da8bf76fdc247f6cc31d1f9e2fc7b096bfcca294ea8f" +
	"1b3183b6f09a05d263b91e7a1b8aa42ee9e3a1b91cb202438a85d8c14ff75578" +
	"f90cf57d7d77322bb8edaafeea19ccc9748a9f10eae43e3b093447d93d555012" +
	"6f1b79285ae8bf9c35a95663585943e0344a9893c8464f9940da45986a5bbed1"

// TestLoadPublicKeyGoldenV2Descriptor loads an envisible.pub written by
// v0.0.5's WritePublicKey, the first release with the v2 format. Projects have
// files like it committed, so a failure here means the descriptor format
// changed: fix the code, never the fixture. See testdata/README.md.
func TestLoadPublicKeyGoldenV2Descriptor(t *testing.T) {
	info, key, err := LoadPublicKey(filepath.Join("testdata", "envisible.pub.v2.golden"))
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if key != nil {
		t.Errorf("golden v2 descriptor produced a legacy v1 key")
	}
	if info == nil {
		t.Fatalf("golden v2 descriptor produced nil PublicKeyInfo")
	}
	if info.Kind != GCP {
		t.Errorf("Kind = %q, want %q", info.Kind, GCP)
	}
	const wantResource = "projects/envisible-golden/locations/us/keyRings/golden/cryptoKeys/golden/cryptoKeyVersions/1"
	if info.Resource != wantResource {
		t.Errorf("Resource = %q, want %q", info.Resource, wantResource)
	}
	if info.Alg != RSAOAEPSHA256_2048 {
		t.Errorf("Alg = %q, want %q", info.Alg, RSAOAEPSHA256_2048)
	}
	wantN, ok := new(big.Int).SetString(goldenDescriptorModulus, 16)
	if !ok {
		t.Fatalf("goldenDescriptorModulus is not valid hex")
	}
	if info.PubKey.N.Cmp(wantN) != 0 {
		t.Errorf("modulus = %x, want %x", info.PubKey.N, wantN)
	}
	if info.PubKey.E != 65537 {
		t.Errorf("exponent = %d, want 65537", info.PubKey.E)
	}
}

func TestRegistryDispatches(t *testing.T) {
	// Use a one-off kind to avoid colliding with any real provider that might
	// register later in the same test binary.
	kind := ProviderKind("test-provider")
	priv := generateRSAKey(t, 2048)

	called := 0
	RegisterUnwrapper(kind, func(_ context.Context, info *PublicKeyInfo) (Unwrapper, error) {
		called++
		return &fakeUnwrapper{priv: priv}, nil
	})

	info := &PublicKeyInfo{
		Kind:     kind,
		Resource: "fake",
		Alg:      RSAOAEPSHA256_2048,
		PubKey:   &priv.PublicKey,
	}

	prov, err := OpenProvider(context.Background(), info)
	if err != nil {
		t.Fatalf("OpenProvider: %v", err)
	}
	if called != 1 {
		t.Errorf("factory called %d times, want 1", called)
	}
	if prov.Kind() != kind || prov.Resource() != "fake" {
		t.Errorf("provider metadata mismatch")
	}

	dk := make([]byte, 32)
	if _, err := rand.Read(dk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wrapped, err := prov.Wrap(dk)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := prov.Unwrap(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(got) != string(dk) {
		t.Errorf("round trip mismatch")
	}
}

func TestOpenUnwrapperUnknownProvider(t *testing.T) {
	priv := generateRSAKey(t, 2048)
	info := &PublicKeyInfo{
		Kind:     ProviderKind("does-not-exist"),
		Resource: "x",
		Alg:      RSAOAEPSHA256_2048,
		PubKey:   &priv.PublicKey,
	}
	_, err := OpenUnwrapper(context.Background(), info)
	if err == nil {
		t.Errorf("expected error for unregistered provider")
	}
}

func TestBootstrapRegistry(t *testing.T) {
	kind := ProviderKind("test-bootstrap")
	if IsBootstrapRegistered(kind) {
		t.Fatalf("kind %q unexpectedly registered before test", kind)
	}

	called := 0
	RegisterBootstrap(kind, func(_ context.Context, resource string) (*PublicKeyInfo, error) {
		called++
		return &PublicKeyInfo{Kind: kind, Resource: resource}, nil
	})
	if !IsBootstrapRegistered(kind) {
		t.Error("IsBootstrapRegistered returned false after RegisterBootstrap")
	}

	info, err := BootstrapPublicKey(context.Background(), kind, "the-resource")
	if err != nil {
		t.Fatalf("BootstrapPublicKey: %v", err)
	}
	if called != 1 || info.Resource != "the-resource" {
		t.Errorf("bootstrap dispatch wrong: called=%d info=%+v", called, info)
	}

	if _, err := BootstrapPublicKey(context.Background(), ProviderKind("unregistered-bootstrap"), "x"); err == nil {
		t.Error("expected error for unregistered bootstrap provider")
	}
}

func TestIsUnwrapperRegistered(t *testing.T) {
	kind := ProviderKind("test-isreg")
	if IsUnwrapperRegistered(kind) {
		t.Fatalf("kind %q unexpectedly registered before test", kind)
	}
	RegisterUnwrapper(kind, func(context.Context, *PublicKeyInfo) (Unwrapper, error) { return nil, nil })
	if !IsUnwrapperRegistered(kind) {
		t.Error("IsUnwrapperRegistered returned false after RegisterUnwrapper")
	}
}

func TestReplaceUnwrapperAndBootstrap(t *testing.T) {
	kind := ProviderKind("test-replace")
	ctx := context.Background()

	// Funcs are not comparable, so each one is identified by the error it
	// returns: calling a factory says which factory it is.
	errOriginal := errors.New("original")
	errReplacement := errors.New("replacement")

	RegisterUnwrapper(kind, func(context.Context, *PublicKeyInfo) (Unwrapper, error) {
		return nil, errOriginal
	})
	prev := ReplaceUnwrapper(kind, func(context.Context, *PublicKeyInfo) (Unwrapper, error) {
		return nil, errReplacement
	})
	if prev == nil {
		t.Fatal("ReplaceUnwrapper did not return the prior factory")
	}
	if _, err := prev(ctx, nil); !errors.Is(err, errOriginal) {
		t.Errorf("ReplaceUnwrapper returned a factory yielding %v, want the original", err)
	}
	if _, err := OpenUnwrapper(ctx, &PublicKeyInfo{Kind: kind}); !errors.Is(err, errReplacement) {
		t.Errorf("after ReplaceUnwrapper, OpenUnwrapper dispatched to %v, want the replacement", err)
	}

	// Restoring is the same call with the prior factory. withFakeKMSProvider in
	// cmd depends on it putting the original back; if it did not, one test's
	// fake would leak into every later test in the package.
	restored := ReplaceUnwrapper(kind, prev)
	if restored == nil {
		t.Fatal("restoring the prior factory should return the replacement")
	}
	if _, err := restored(ctx, nil); !errors.Is(err, errReplacement) {
		t.Errorf("restore returned a factory yielding %v, want the replacement", err)
	}
	if _, err := OpenUnwrapper(ctx, &PublicKeyInfo{Kind: kind}); !errors.Is(err, errOriginal) {
		t.Errorf("after restore, OpenUnwrapper dispatched to %v, want the original", err)
	}

	RegisterBootstrap(kind, func(context.Context, string) (*PublicKeyInfo, error) {
		return nil, errOriginal
	})
	bPrev := ReplaceBootstrap(kind, func(context.Context, string) (*PublicKeyInfo, error) {
		return nil, errReplacement
	})
	if bPrev == nil {
		t.Fatal("ReplaceBootstrap did not return the prior fetcher")
	}
	if _, err := bPrev(ctx, "x"); !errors.Is(err, errOriginal) {
		t.Errorf("ReplaceBootstrap returned a fetcher yielding %v, want the original", err)
	}
	if _, err := BootstrapPublicKey(ctx, kind, "x"); !errors.Is(err, errReplacement) {
		t.Errorf("after ReplaceBootstrap, BootstrapPublicKey dispatched to %v, want the replacement", err)
	}

	bRestored := ReplaceBootstrap(kind, bPrev)
	if bRestored == nil {
		t.Fatal("restoring the prior fetcher should return the replacement")
	}
	if _, err := bRestored(ctx, "x"); !errors.Is(err, errReplacement) {
		t.Errorf("restore returned a fetcher yielding %v, want the replacement", err)
	}
	if _, err := BootstrapPublicKey(ctx, kind, "x"); !errors.Is(err, errOriginal) {
		t.Errorf("after restore, BootstrapPublicKey dispatched to %v, want the original", err)
	}
}

func TestWritePublicKeyRejectsInvalidAlgorithm(t *testing.T) {
	priv := generateRSAKey(t, 2048)
	path := filepath.Join(t.TempDir(), "envisible.pub")
	err := WritePublicKey(path, &PublicKeyInfo{
		Kind:     GCP,
		Resource: "x",
		Alg:      Algorithm("bogus-algorithm"),
		PubKey:   &priv.PublicKey,
	})
	if err == nil {
		t.Error("expected WritePublicKey to reject an invalid algorithm")
	}
}

func TestParseRSAPublicKeyDERErrors(t *testing.T) {
	if _, err := ParseRSAPublicKeyDER([]byte("not-valid-der")); err == nil {
		t.Error("expected parse error for malformed DER")
	}

	// A well-formed PKIX key that isn't RSA must be rejected.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	if _, err := ParseRSAPublicKeyDER(der); err == nil {
		t.Error("expected ParseRSAPublicKeyDER to reject a non-RSA key")
	}
}
