package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/rubysolo/envisible/pkg/kms"
)

func TestParseProviderKind(t *testing.T) {
	cases := map[string]struct {
		in      string
		want    kms.ProviderKind
		wantErr bool
	}{
		"gcp":       {"gcp", kms.GCP, false},
		"upper_GCP": {"GCP", kms.GCP, false},
		"trimmed":   {"  azure  ", kms.Azure, false},
		"aws":       {"aws", kms.AWS, false},
		"unknown":   {"vault", "", true},
		"empty":     {"", "", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseProviderKind(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProviderKind(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseProviderKind(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// localUnwrapper performs RSA-OAEP-SHA-256 unwrap locally with the matching
// private key. Used to fake a cloud KMS in cmd-level integration tests.
type localUnwrapper struct{ priv *rsa.PrivateKey }

func (u *localUnwrapper) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, u.priv, wrapped, nil)
}

// withFakeKMSProvider temporarily swaps the registry entries for kind to use a
// local-RSA fake backed by priv. Returns a restore func to defer.
func withFakeKMSProvider(t *testing.T, kind kms.ProviderKind, priv *rsa.PrivateKey, resource string) func() {
	t.Helper()
	oldUnwrap := kms.ReplaceUnwrapper(kind, func(_ context.Context, _ *kms.PublicKeyInfo) (kms.Unwrapper, error) {
		return &localUnwrapper{priv: priv}, nil
	})
	oldBootstrap := kms.ReplaceBootstrap(kind, func(_ context.Context, res string) (*kms.PublicKeyInfo, error) {
		return &kms.PublicKeyInfo{
			Kind:     kind,
			Resource: res,
			Alg:      kms.RSAOAEPSHA256_2048,
			PubKey:   &priv.PublicKey,
		}, nil
	})
	return func() {
		kms.ReplaceUnwrapper(kind, oldUnwrap)
		kms.ReplaceBootstrap(kind, oldBootstrap)
	}
}

func TestKmsInitFetchesAndWritesPubkey(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	resource := "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
	restore := withFakeKMSProvider(t, kms.GCP, priv, resource)
	defer restore()

	b := &bytes.Buffer{}
	resetRoot(b)
	rootCmd.SetArgs([]string{"kms", "init", "--provider", "gcp", "--resource", resource})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("kms init failed: %v", err)
	}

	// envisible.pub must now exist as a JSON v2 file pointing at the fake.
	raw, err := os.ReadFile("envisible.pub")
	if err != nil {
		t.Fatalf("read envisible.pub: %v", err)
	}
	var got struct {
		Version   int    `json:"version"`
		Provider  string `json:"provider"`
		Resource  string `json:"resource"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal envisible.pub: %v\nfile:\n%s", err, raw)
	}
	if got.Version != 2 || got.Provider != "gcp" || got.Resource != resource {
		t.Errorf("envisible.pub metadata mismatch: %+v", got)
	}
	if got.Algorithm != string(kms.RSAOAEPSHA256_2048) {
		t.Errorf("envisible.pub algorithm = %q, want %q", got.Algorithm, kms.RSAOAEPSHA256_2048)
	}
	if got.PublicKey == "" {
		t.Errorf("envisible.pub public_key is empty")
	}

	// And it must round-trip through LoadPublicKey back into the same info.
	info, _, err := kms.LoadPublicKey("envisible.pub")
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if info == nil || info.PubKey.N.Cmp(priv.PublicKey.N) != 0 {
		t.Errorf("loaded public key does not match the fake")
	}
}

func TestKmsInitRejectsUnknownProvider(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "init", "--provider", "vault", "--resource", "whatever"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected error for unknown provider")
	}
}

func TestKmsInitRequiresFlags(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "init"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected error when --provider and --resource are missing")
	}
}

func TestKmsCreateDispatchAndBootstrap(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	resource := "projects/p/locations/us/keyRings/r/cryptoKeys/mykey/cryptoKeyVersions/1"

	// Swap the create dispatch hook to a fake — pretends provisioning succeeded
	// and returns a resource string. The bootstrap fetcher must also be faked
	// so the post-create public-key fetch doesn't hit the real cloud.
	oldCreate := createProviderKey
	createProviderKey = func(_ context.Context, kind kms.ProviderKind) (string, error) {
		if kind != kms.GCP {
			t.Errorf("unexpected provider kind: %v", kind)
		}
		return resource, nil
	}
	defer func() { createProviderKey = oldCreate }()

	restore := withFakeKMSProvider(t, kms.GCP, priv, resource)
	defer restore()

	resetRoot(nil)
	rootCmd.SetArgs([]string{
		"kms", "create",
		"--provider", "gcp",
		"--project", "p", "--location", "us",
		"--keyring", "r", "--name", "mykey",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("kms create: %v", err)
	}

	info, _, err := kms.LoadPublicKey("envisible.pub")
	if err != nil || info == nil {
		t.Fatalf("envisible.pub not produced: info=%v err=%v", info, err)
	}
	if info.Resource != resource {
		t.Errorf("envisible.pub resource = %q, want %q", info.Resource, resource)
	}
}

func TestKmsCreateRejectsIncompleteGCPFlags(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "create", "--provider", "gcp", "--project", "p"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected error when GCP flags are partially set")
	}
}

func TestKmsCreateRejectsIncompleteAzureFlags(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "create", "--provider", "azure", "--vault", "myvault"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected error when Azure --name is missing")
	}
}

// keyedFakeProvider serves a different RSA key per resource string. Lets a
// single registry entry pretend to be multiple distinct KMS keys — needed for
// rotate, where one factory call has to unwrap with the OLD key and another
// has to fetch the NEW public key.
type keyedFakeProvider struct {
	byResource map[string]*rsa.PrivateKey
}

func (p *keyedFakeProvider) install(t *testing.T, kind kms.ProviderKind) func() {
	t.Helper()
	oldUnwrap := kms.ReplaceUnwrapper(kind, func(_ context.Context, info *kms.PublicKeyInfo) (kms.Unwrapper, error) {
		priv, ok := p.byResource[info.Resource]
		if !ok {
			return nil, fmt.Errorf("fake: no key for resource %q", info.Resource)
		}
		return &localUnwrapper{priv: priv}, nil
	})
	oldBootstrap := kms.ReplaceBootstrap(kind, func(_ context.Context, resource string) (*kms.PublicKeyInfo, error) {
		priv, ok := p.byResource[resource]
		if !ok {
			return nil, fmt.Errorf("fake: no key for resource %q", resource)
		}
		return &kms.PublicKeyInfo{
			Kind:     kind,
			Resource: resource,
			Alg:      kms.RSAOAEPSHA256_2048,
			PubKey:   &priv.PublicKey,
		}, nil
	})
	return func() {
		kms.ReplaceUnwrapper(kind, oldUnwrap)
		kms.ReplaceBootstrap(kind, oldBootstrap)
	}
}

func TestKmsRotateRewrapsFileAndUpdatesPubkey(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	oldPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	newPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	oldResource := "projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
	newResource := "projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2"

	fake := &keyedFakeProvider{byResource: map[string]*rsa.PrivateKey{
		oldResource: oldPriv,
		newResource: newPriv,
	}}
	restore := fake.install(t, kms.GCP)
	defer restore()

	// 1. Register the OLD key.
	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "init", "--provider", "gcp", "--resource", oldResource})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("kms init: %v", err)
	}

	// 2. Encrypt a file with the OLD key.
	const conf = "config.yaml"
	os.WriteFile(conf, []byte("DB=ENC[hello-rotate]\nLEGACY=ENC[v1:passthrough]"), 0644)
	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", conf})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	encryptedBefore, _ := os.ReadFile(conf)
	if !bytes.Contains(encryptedBefore, []byte("ENC[v2:")) {
		t.Fatalf("setup: file has no v2 marker: %s", encryptedBefore)
	}

	// 3. Rotate to the NEW key.
	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "rotate", "--to", newResource, conf})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("kms rotate: %v", err)
	}

	// 4. File content must have changed (the wrapped DK bytes differ between
	// keys) but the v1 marker must still be present untouched.
	encryptedAfter, _ := os.ReadFile(conf)
	if bytes.Equal(encryptedBefore, encryptedAfter) {
		t.Errorf("rotate produced no change to %s", conf)
	}
	if !bytes.Contains(encryptedAfter, []byte("ENC[v1:passthrough]")) {
		t.Errorf("rotate touched a v1 marker")
	}

	// 5. envisible.pub must now point at the NEW resource.
	info, _, err := kms.LoadPublicKey("envisible.pub")
	if err != nil || info == nil {
		t.Fatalf("load updated envisible.pub: info=%v err=%v", info, err)
	}
	if info.Resource != newResource {
		t.Errorf("envisible.pub resource = %q, want %q", info.Resource, newResource)
	}

	// 6. Decrypt with the now-current setup recovers the original plaintext.
	b := &bytes.Buffer{}
	resetRoot(b)
	rootCmd.SetArgs([]string{"decrypt", conf})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt after rotate: %v", err)
	}
	if !bytes.Contains(b.Bytes(), []byte("DB=ENC[hello-rotate]")) {
		t.Errorf("decrypt after rotate didn't recover plaintext: %s", b.String())
	}
}

func TestKmsRotateRejectsV1Pubkey(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// Stand up a legacy v1 project via the existing keygen path.
	resetRoot(nil)
	rootCmd.SetArgs([]string{"keygen"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "rotate", "--to", "projects/x/.../cryptoKeyVersions/2"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected rotate to refuse to operate on a v1 NaCl project")
	}
}

func TestKmsRotateRequiresTo(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "rotate"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected error when --to is missing")
	}
}
