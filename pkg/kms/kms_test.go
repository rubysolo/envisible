package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
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

func TestLoadPublicKeyRejectsBadInputs(t *testing.T) {
	dir := t.TempDir()

	cases := map[string]string{
		"unknown_provider":  `{"version": 2, "provider": "icloud", "resource": "x", "algorithm": "RSA-OAEP-SHA256-2048", "public_key": ""}`,
		"missing_resource":  `{"version": 2, "provider": "gcp", "resource": "", "algorithm": "RSA-OAEP-SHA256-2048", "public_key": ""}`,
		"wrong_version":     `{"version": 9, "provider": "gcp", "resource": "x", "algorithm": "RSA-OAEP-SHA256-2048", "public_key": ""}`,
		"bad_pem":           `{"version": 2, "provider": "gcp", "resource": "x", "algorithm": "RSA-OAEP-SHA256-2048", "public_key": "not-a-pem-block"}`,
		"truncated_base64":  "this is not valid base64 of 32 bytes",
		"empty_file":        "",
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
