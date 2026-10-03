package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rubysolo/envisible/pkg/kms"
	awskms "github.com/rubysolo/envisible/pkg/kms/aws"
	azurekms "github.com/rubysolo/envisible/pkg/kms/azure"
	gcpkms "github.com/rubysolo/envisible/pkg/kms/gcp"
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
	t.Chdir(tmpDir)

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
	t.Chdir(tmpDir)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "init", "--provider", "vault", "--resource", "whatever"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected error for unknown provider")
	}
}

func TestKmsInitRequiresFlags(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "init"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected error when --provider and --resource are missing")
	}
}

func TestKmsCreateDispatchAndBootstrap(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)

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

// capturedCreate records which provider creator `kms create` reached and the
// params it was handed.
type capturedCreate struct {
	calls int
	gcp   gcpkms.CreateKeyParams
	aws   awskms.CreateKeyParams
	azure azurekms.CreateKeyParams
}

// stubProviderCreators swaps all three provider CreateKey seams for recorders
// that return resource, so createProviderKeyReal's flag→param mapping runs for
// real while nothing reaches a cloud SDK.
func stubProviderCreators(t *testing.T, resource string) *capturedCreate {
	t.Helper()
	got := &capturedCreate{}
	oldGCP, oldAWS, oldAzure := gcpCreateKey, awsCreateKey, azureCreateKey
	t.Cleanup(func() { gcpCreateKey, awsCreateKey, azureCreateKey = oldGCP, oldAWS, oldAzure })

	gcpCreateKey = func(_ context.Context, p gcpkms.CreateKeyParams) (string, error) {
		got.calls++
		got.gcp = p
		return resource, nil
	}
	awsCreateKey = func(_ context.Context, p awskms.CreateKeyParams) (string, error) {
		got.calls++
		got.aws = p
		return resource, nil
	}
	azureCreateKey = func(_ context.Context, p azurekms.CreateKeyParams) (string, error) {
		got.calls++
		got.azure = p
		return resource, nil
	}
	return got
}

// TestKmsCreateMapsFlagsToProviderParams runs `kms create` through the real
// dispatch and asserts each flag lands in the param it is named for. Every flag
// value in a case is distinct, so a field wired to the wrong flag cannot match.
func TestKmsCreateMapsFlagsToProviderParams(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	cases := map[string]struct {
		kind     kms.ProviderKind
		args     []string
		resource string
		want     capturedCreate
	}{
		"gcp": {
			kind:     kms.GCP,
			args:     []string{"--provider", "gcp", "--project", "the-project", "--location", "the-location", "--keyring", "the-keyring", "--name", "the-name"},
			resource: "projects/the-project/locations/the-location/keyRings/the-keyring/cryptoKeys/the-name/cryptoKeyVersions/1",
			want: capturedCreate{calls: 1, gcp: gcpkms.CreateKeyParams{
				Project: "the-project", Location: "the-location", Keyring: "the-keyring", Name: "the-name",
			}},
		},
		"aws": {
			kind:     kms.AWS,
			args:     []string{"--provider", "aws", "--region", "the-region", "--alias", "the-alias"},
			resource: "arn:aws:kms:the-region:123456789012:key/abcd-1234",
			want:     capturedCreate{calls: 1, aws: awskms.CreateKeyParams{Region: "the-region", Alias: "the-alias"}},
		},
		"aws_no_flags": {
			// Both AWS flags are optional; the provider package fills defaults.
			kind:     kms.AWS,
			args:     []string{"--provider", "aws"},
			resource: "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
			want:     capturedCreate{calls: 1},
		},
		"azure": {
			kind:     kms.Azure,
			args:     []string{"--provider", "azure", "--vault", "the-vault", "--name", "the-name"},
			resource: "https://the-vault.vault.azure.net/keys/the-name/abc123",
			want:     capturedCreate{calls: 1, azure: azurekms.CreateKeyParams{Vault: "the-vault", Name: "the-name"}},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			got := stubProviderCreators(t, tc.resource)
			defer withFakeKMSProvider(t, tc.kind, priv, tc.resource)()

			resetRoot(nil)
			rootCmd.SetArgs(append([]string{"kms", "create"}, tc.args...))
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("kms create: %v", err)
			}

			if *got != tc.want {
				t.Errorf("creator calls:\n got %+v\nwant %+v", *got, tc.want)
			}

			// The resource the creator returned is what envisible.pub pins to.
			info, _, err := kms.LoadPublicKey("envisible.pub")
			if err != nil || info == nil {
				t.Fatalf("envisible.pub not produced: info=%v err=%v", info, err)
			}
			if info.Kind != tc.kind || info.Resource != tc.resource {
				t.Errorf("envisible.pub = %s %q, want %s %q", info.Kind, info.Resource, tc.kind, tc.resource)
			}
		})
	}
}

func TestCreateProviderKeyRealRejectsUnknownKind(t *testing.T) {
	got := stubProviderCreators(t, "unused")
	_, err := createProviderKeyReal(context.Background(), kms.ProviderKind("icloud"))
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("expected an unsupported-provider error, got %v", err)
	}
	if got.calls != 0 {
		t.Errorf("an unknown provider kind reached a creator: %+v", *got)
	}
}

// failIfProviderCreatorReached stubs the provider creators to fail the test.
// The provider packages reject incomplete params too, so without this a flag
// check deleted from PreRunE would still surface as *an* error and the tests
// below would keep passing.
func failIfProviderCreatorReached(t *testing.T) {
	t.Helper()
	oldGCP, oldAWS, oldAzure := gcpCreateKey, awsCreateKey, azureCreateKey
	t.Cleanup(func() { gcpCreateKey, awsCreateKey, azureCreateKey = oldGCP, oldAWS, oldAzure })

	gcpCreateKey = func(context.Context, gcpkms.CreateKeyParams) (string, error) {
		t.Fatal("gcp CreateKey reached; PreRunE should have rejected the flags")
		return "", nil
	}
	awsCreateKey = func(context.Context, awskms.CreateKeyParams) (string, error) {
		t.Fatal("aws CreateKey reached; PreRunE should have rejected the flags")
		return "", nil
	}
	azureCreateKey = func(context.Context, azurekms.CreateKeyParams) (string, error) {
		t.Fatal("azure CreateKey reached; PreRunE should have rejected the flags")
		return "", nil
	}
}

func TestKmsCreateRejectsIncompleteGCPFlags(t *testing.T) {
	full := map[string]string{"--project": "p", "--location": "us", "--keyring": "r", "--name": "k"}

	for missing := range full {
		t.Run("missing"+missing, func(t *testing.T) {
			t.Chdir(t.TempDir())
			failIfProviderCreatorReached(t)

			args := []string{"kms", "create", "--provider", "gcp"}
			for flag, value := range full {
				if flag != missing {
					args = append(args, flag, value)
				}
			}
			resetRoot(nil)
			rootCmd.SetArgs(args)
			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("expected error when %s is missing", missing)
			}
			if want := "--project, --location, --keyring, and --name are all required for gcp"; err.Error() != want {
				t.Errorf("error = %q, want the command-level message %q", err, want)
			}
			if _, statErr := os.Stat("envisible.pub"); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("envisible.pub was written despite rejected flags (stat err: %v)", statErr)
			}
		})
	}
}

func TestKmsCreateRejectsIncompleteAzureFlags(t *testing.T) {
	cases := map[string][]string{
		"missing--name":  {"--vault", "myvault"},
		"missing--vault": {"--name", "mykey"},
	}

	for name, flags := range cases {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			failIfProviderCreatorReached(t)

			resetRoot(nil)
			rootCmd.SetArgs(append([]string{"kms", "create", "--provider", "azure"}, flags...))
			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("expected error for azure with only %v", flags)
			}
			if want := "--vault and --name are required for azure"; err.Error() != want {
				t.Errorf("error = %q, want the command-level message %q", err, want)
			}
			if _, statErr := os.Stat("envisible.pub"); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("envisible.pub was written despite rejected flags (stat err: %v)", statErr)
			}
		})
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
	t.Chdir(tmpDir)

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
	os.WriteFile(conf, []byte("DB=ENC[hello-rotate]\nAPI=ENC[second-secret]\nLEGACY=ENC[v1:passthrough]"), 0644)
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
	var rotateErr error
	report := captureKmsStderr(t, func() { rotateErr = rootCmd.Execute() })
	if rotateErr != nil {
		t.Fatalf("kms rotate: %v", rotateErr)
	}

	// The report counts v2 markers only: two rotated, the v1 marker is not one.
	if want := "Rotated 2 v2 marker(s) across 1 file(s)"; !strings.Contains(report, want) {
		t.Errorf("rotate report missing %q:\n%s", want, report)
	}
	if want := conf + ": 2 marker(s)"; !strings.Contains(report, want) {
		t.Errorf("rotate report missing the per-file count %q:\n%s", want, report)
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

	// Rotation swaps the wrapped data key and nothing else: each marker's
	// secretbox payload (everything after the 256-byte wrapped key) must be
	// bit-for-bit what it was, as the README and RewrapContent promise.
	blobsBefore, blobsAfter := v2Blobs(t, encryptedBefore), v2Blobs(t, encryptedAfter)
	if len(blobsBefore) != 2 || len(blobsAfter) != 2 {
		t.Fatalf("v2 marker count before/after = %d/%d, want 2/2", len(blobsBefore), len(blobsAfter))
	}
	wrappedSize := oldPriv.PublicKey.Size()
	for i := range blobsBefore {
		before, after := blobsBefore[i], blobsAfter[i]
		if !bytes.Equal(before[wrappedSize:], after[wrappedSize:]) {
			t.Errorf("marker %d: secretbox payload changed during rotation", i)
		}
		if bytes.Equal(before[:wrappedSize], after[:wrappedSize]) {
			t.Errorf("marker %d: wrapped data key was not re-wrapped", i)
		}
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
	if !bytes.Contains(b.Bytes(), []byte("API=ENC[second-secret]")) {
		t.Errorf("decrypt after rotate didn't recover the second plaintext: %s", b.String())
	}
}

var ansiStyleRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// captureKmsStderr runs fn with os.Stderr redirected and returns what it wrote,
// with terminal styling stripped. pkg/ui prints straight to os.Stderr, so the
// command's own SetErr does not see the rotate report.
func captureKmsStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		out, _ := io.ReadAll(r)
		done <- string(out)
	}()
	func() {
		defer func() {
			os.Stderr = old
			w.Close()
		}()
		fn()
	}()
	out := <-done
	r.Close()
	return ansiStyleRe.ReplaceAllString(out, "")
}

var v2MarkerRe = regexp.MustCompile(`ENC\[v2:([A-Za-z0-9+/=]+)\]`)

// v2Blobs returns the decoded payload of every ENC[v2:...] marker in content,
// in file order.
func v2Blobs(t *testing.T, content []byte) [][]byte {
	t.Helper()
	var blobs [][]byte
	for _, m := range v2MarkerRe.FindAllSubmatch(content, -1) {
		blob, err := base64.StdEncoding.DecodeString(string(m[1]))
		if err != nil {
			t.Fatalf("v2 marker is not valid base64: %v", err)
		}
		blobs = append(blobs, blob)
	}
	return blobs
}

// rotateFixture is a KMS-backed project in the current directory: envisible.pub
// registered against oldResource, and two files encrypted under it.
type rotateFixture struct {
	oldResource, newResource string
	first, second            string
}

func setupRotateFixture(t *testing.T) rotateFixture {
	t.Helper()
	t.Chdir(t.TempDir())

	oldPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	newPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	fx := rotateFixture{
		oldResource: "projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
		newResource: "projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2",
		first:       "first.yaml",
		second:      "second.yaml",
	}
	fake := &keyedFakeProvider{byResource: map[string]*rsa.PrivateKey{
		fx.oldResource: oldPriv,
		fx.newResource: newPriv,
	}}
	t.Cleanup(fake.install(t, kms.GCP))

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "init", "--provider", "gcp", "--resource", fx.oldResource})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("kms init: %v", err)
	}
	for path, content := range map[string]string{
		fx.first:  "A=ENC[first-secret]\n",
		fx.second: "B=ENC[second-secret]\nC=ENC[third-secret]\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		resetRoot(nil)
		rootCmd.SetArgs([]string{"encrypt", "-i", path})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("encrypt %s: %v", path, err)
		}
	}
	return fx
}

// snapshotDir reads every regular file under the current directory, keyed by
// relative path. Two snapshots compare equal only if no file was added, removed
// or changed by a single byte — which also rules out a leftover temp file.
func snapshotDir(t *testing.T) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snap[path] = string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return snap
}

func assertDirUnchanged(t *testing.T, before map[string]string) {
	t.Helper()
	after := snapshotDir(t)
	for path, want := range before {
		got, ok := after[path]
		switch {
		case !ok:
			t.Errorf("%s was removed", path)
		case got != want:
			t.Errorf("%s was modified:\nbefore: %q\n after: %q", path, want, got)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			t.Errorf("%s was created", path)
		}
		if strings.Contains(path, ".envisible-") {
			t.Errorf("temp file %s left behind", path)
		}
	}
}

// garbleFirstWrappedKey overwrites the wrapped data key of the first v2 marker
// in path and leaves the rest of the marker alone. The marker stays
// structurally valid, so the failure rotate hits is the unwrap itself.
func garbleFirstWrappedKey(t *testing.T, path string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	loc := v2MarkerRe.FindSubmatchIndex(content)
	if loc == nil {
		t.Fatalf("setup: no v2 marker in %s", path)
	}
	blob, err := base64.StdEncoding.DecodeString(string(content[loc[2]:loc[3]]))
	if err != nil {
		t.Fatalf("setup: decode marker: %v", err)
	}
	for i := 0; i < 256; i++ {
		blob[i] = 0x5a
	}
	mutated := string(content[:loc[2]]) + base64.StdEncoding.EncodeToString(blob) + string(content[loc[3]:])
	if err := os.WriteFile(path, []byte(mutated), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestKmsRotateAbortsBeforeWritingOnAnyFailure pins the promise in the rotate
// command: everything is rewrapped in memory first, and a failure anywhere
// aborts before a single byte reaches disk. A half-rotated project — some
// files on the new key, envisible.pub on either — is unrecoverable once the
// old key version is destroyed.
func TestKmsRotateAbortsBeforeWritingOnAnyFailure(t *testing.T) {
	cases := map[string]struct {
		// corrupt breaks the fixture and returns the rotate args after
		// `--to <resource>` plus the substrings the error must carry.
		corrupt func(t *testing.T, fx rotateFixture) (to string, files []string, wantErr []string)
	}{
		"second_file_wrapped_key_is_garbage": {
			corrupt: func(t *testing.T, fx rotateFixture) (string, []string, []string) {
				garbleFirstWrappedKey(t, fx.second)
				return fx.newResource, []string{fx.first, fx.second}, []string{fx.second, "unwrap"}
			},
		},
		"first_file_wrapped_key_is_garbage": {
			// Same failure, first in the list: nothing after it may be written.
			corrupt: func(t *testing.T, fx rotateFixture) (string, []string, []string) {
				garbleFirstWrappedKey(t, fx.first)
				return fx.newResource, []string{fx.first, fx.second}, []string{fx.first, "unwrap"}
			},
		},
		"second_file_marker_is_truncated": {
			corrupt: func(t *testing.T, fx rotateFixture) (string, []string, []string) {
				// Shorter than one wrapped key: there is no payload to keep.
				short := base64.StdEncoding.EncodeToString([]byte("far too short"))
				content := "B=ENC[v2:" + short + "]\n"
				if err := os.WriteFile(fx.second, []byte(content), 0644); err != nil {
					t.Fatalf("write: %v", err)
				}
				return fx.newResource, []string{fx.first, fx.second}, []string{fx.second, "too short"}
			},
		},
		"second_file_does_not_exist": {
			corrupt: func(t *testing.T, fx rotateFixture) (string, []string, []string) {
				return fx.newResource, []string{fx.first, "no-such-file.yaml"}, []string{"no-such-file.yaml"}
			},
		},
		"bootstrap_of_new_key_fails": {
			corrupt: func(t *testing.T, fx rotateFixture) (string, []string, []string) {
				// The fake has no key for this resource, so its bootstrap errors.
				unknown := "projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/99"
				return unknown, []string{fx.first, fx.second}, []string{"failed to fetch new public key", unknown}
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fx := setupRotateFixture(t)
			to, files, wantErr := tc.corrupt(t, fx)
			before := snapshotDir(t)
			if _, ok := before["envisible.pub"]; !ok {
				t.Fatalf("setup: envisible.pub not in snapshot")
			}

			resetRoot(nil)
			rootCmd.SetArgs(append([]string{"kms", "rotate", "--to", to}, files...))
			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("kms rotate succeeded; want an error")
			}
			for _, want := range wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}

			assertDirUnchanged(t, before)

			// envisible.pub still names the old key, so the project still decrypts.
			info, _, loadErr := kms.LoadPublicKey("envisible.pub")
			if loadErr != nil || info == nil {
				t.Fatalf("load envisible.pub: info=%v err=%v", info, loadErr)
			}
			if info.Resource != fx.oldResource {
				t.Errorf("envisible.pub resource = %q, want the old key %q", info.Resource, fx.oldResource)
			}
		})
	}
}

// TestKmsRotateWriteFailureLeavesPubkeyOnOldKey pins the write phase as it is
// today, which is NOT transactional across files: they are written in argument
// order and envisible.pub last. A failure writing the second file leaves the
// first one rotated and envisible.pub untouched. Making that atomic is out of
// scope for plan 08; this test exists so the order cannot change by accident.
func TestKmsRotateWriteFailureLeavesPubkeyOnOldKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions; cannot make a write fail")
	}
	fx := setupRotateFixture(t)

	// A file in a read-only directory can be read but not replaced: the
	// atomic writer cannot create its temp file next to it.
	if err := os.Mkdir("locked", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	locked := filepath.Join("locked", fx.second)
	if err := os.Rename(fx.second, locked); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.Chmod("locked", 0555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod("locked", 0755) })

	before := snapshotDir(t)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "rotate", "--to", fx.newResource, fx.first, locked})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("kms rotate succeeded; want a write error")
	}
	if !strings.Contains(err.Error(), "write "+locked) {
		t.Errorf("error %q does not name the file that failed to write", err)
	}

	after := snapshotDir(t)
	if after[fx.first] == before[fx.first] {
		t.Errorf("%s was not written before the failing file; write order changed", fx.first)
	}
	if after[locked] != before[locked] {
		t.Errorf("%s changed despite its write failing", locked)
	}
	if after["envisible.pub"] != before["envisible.pub"] {
		t.Errorf("envisible.pub was updated although a file write failed")
	}
	for path := range after {
		if strings.Contains(path, ".envisible-") {
			t.Errorf("temp file %s left behind", path)
		}
	}
}

func TestKmsRotateRejectsV1Pubkey(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)

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
	t.Chdir(tmpDir)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "rotate"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected error when --to is missing")
	}
}
