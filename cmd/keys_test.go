package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	envcrypto "github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/kms"
	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/rubysolo/envisible/pkg/ui"
)

// withKeyPaths points the package-level pubKeyPath/privKeyPath at the given
// values for the duration of a test, restoring the originals afterward.
func withKeyPaths(t *testing.T, pub, priv string) {
	t.Helper()
	origPub, origPriv := pubKeyPath, privKeyPath
	pubKeyPath, privKeyPath = pub, priv
	t.Cleanup(func() { pubKeyPath, privKeyPath = origPub, origPriv })
}

func writeV1Pub(t *testing.T, path string) {
	t.Helper()
	var pub [32]byte
	if _, err := rand.Read(pub[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(pub[:])), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
}

func TestLoadDecryptorErrors(t *testing.T) {
	dir := t.TempDir()
	missingPub := filepath.Join(dir, "missing.pub")
	missingPriv := filepath.Join(dir, "missing.key")

	t.Run("no keys present", func(t *testing.T) {
		withKeyPaths(t, missingPub, missingPriv)
		if _, err := loadDecryptor(context.Background()); err == nil {
			t.Error("expected an error when neither key file exists")
		}
	})

	t.Run("malformed public key", func(t *testing.T) {
		badPub := filepath.Join(dir, "bad.pub")
		if err := os.WriteFile(badPub, []byte("{not valid json"), 0o644); err != nil {
			t.Fatal(err)
		}
		withKeyPaths(t, badPub, missingPriv)
		if _, err := loadDecryptor(context.Background()); err == nil {
			t.Error("expected an error for a malformed public key file")
		}
	})

	t.Run("malformed private key", func(t *testing.T) {
		badPriv := filepath.Join(dir, "bad.key")
		if err := os.WriteFile(badPriv, []byte("not-a-valid-base64-key!!!"), 0o644); err != nil {
			t.Fatal(err)
		}
		withKeyPaths(t, missingPub, badPriv)
		if _, err := loadDecryptor(context.Background()); err == nil {
			t.Error("expected an error for a malformed private key file")
		}
	})
}

func TestLoadProviderErrors(t *testing.T) {
	dir := t.TempDir()

	t.Run("encryptor load fails", func(t *testing.T) {
		withKeyPaths(t, filepath.Join(dir, "missing.pub"), filepath.Join(dir, "missing.key"))
		if _, _, err := loadProvider(context.Background()); err == nil {
			t.Error("expected an error when the encryptor cannot load")
		}
	})

	t.Run("decryptor load fails", func(t *testing.T) {
		// A valid v1 public key lets the encryptor load, but with no private key
		// the decryptor has nothing to open markers with — loadProvider surfaces it.
		goodPub := filepath.Join(dir, "good.pub")
		writeV1Pub(t, goodPub)
		withKeyPaths(t, goodPub, filepath.Join(dir, "missing.key"))
		if _, _, err := loadProvider(context.Background()); err == nil {
			t.Error("expected an error when the decryptor cannot load")
		}
	})
}

func TestCreateProviderKeyRealRejectsUnknownProvider(t *testing.T) {
	if _, err := createProviderKeyReal(context.Background(), kms.ProviderKind("nope")); err == nil {
		t.Error("expected an error for an unsupported provider")
	}
}

// withKeyMaterial sets the package-level privKeyMaterial for the duration of a
// test. Production code fills it in from ENVISIBLE_KEY in PersistentPreRunE,
// which unit tests calling loadDecryptor directly never run.
func withKeyMaterial(t *testing.T, material string) {
	t.Helper()
	orig := privKeyMaterial
	privKeyMaterial = material
	t.Cleanup(func() { privKeyMaterial = orig })
}

// sealV1 encrypts plaintext to pub as the inner text of a v1 ENC[...] marker.
func sealV1(t *testing.T, pub [32]byte, plaintext string) string {
	t.Helper()
	inner, err := processor.NaclEncryptor{PublicKey: pub}.EncryptValue([]byte(plaintext))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	return inner
}

func mustKeypair(t *testing.T) ([32]byte, [32]byte) {
	t.Helper()
	pub, priv, err := envcrypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return pub, priv
}

// TestLoadDecryptorAcceptsKeyMaterial covers the headline case: the private key
// arrives as material (ENVISIBLE_KEY) with no key file anywhere on disk.
func TestLoadDecryptorAcceptsKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	pub, priv := mustKeypair(t)

	for name, material := range map[string]string{
		"bare":                     envcrypto.EncodeKey(priv),
		"trailing newline":         envcrypto.EncodeKey(priv) + "\n",
		"surrounded by whitespace": "  " + envcrypto.EncodeKey(priv) + "\t\n",
	} {
		t.Run(name, func(t *testing.T) {
			withKeyPaths(t, filepath.Join(dir, "missing.pub"), filepath.Join(dir, "missing.key"))
			withKeyMaterial(t, material)

			dec, err := loadDecryptor(context.Background())
			if err != nil {
				t.Fatalf("loadDecryptor with ENVISIBLE_KEY material: %v", err)
			}
			got, err := dec.DecryptMarker(context.Background(), sealV1(t, pub, "material-secret"))
			if err != nil {
				t.Fatalf("DecryptMarker: %v", err)
			}
			if string(got) != "material-secret" {
				t.Errorf("decrypted %q, want %q", got, "material-secret")
			}
		})
	}
}

// TestLoadDecryptorKeyMaterialBeatsKeyFile pins resolution order 2 over 3/4:
// material wins over whatever the key path points at.
func TestLoadDecryptorKeyMaterialBeatsKeyFile(t *testing.T) {
	dir := t.TempDir()
	wantedPub, wantedPriv := mustKeypair(t)
	_, otherPriv := mustKeypair(t)

	keyFile := filepath.Join(dir, "other.key")
	if err := os.WriteFile(keyFile, []byte(envcrypto.EncodeKey(otherPriv)), 0o600); err != nil {
		t.Fatal(err)
	}
	withKeyPaths(t, filepath.Join(dir, "missing.pub"), keyFile)
	withKeyMaterial(t, envcrypto.EncodeKey(wantedPriv))

	dec, err := loadDecryptor(context.Background())
	if err != nil {
		t.Fatalf("loadDecryptor: %v", err)
	}
	got, err := dec.DecryptMarker(context.Background(), sealV1(t, wantedPub, "from-material"))
	if err != nil {
		t.Fatalf("material did not win over the key file: %v", err)
	}
	if string(got) != "from-material" {
		t.Errorf("decrypted %q, want %q", got, "from-material")
	}
}

// TestLoadDecryptorMalformedKeyMaterialNeverLeaksIt is the leak regression: a
// bad ENVISIBLE_KEY must produce a clear error that names the variable and
// never any part of its value.
func TestLoadDecryptorMalformedKeyMaterialNeverLeaksIt(t *testing.T) {
	dir := t.TempDir()

	cases := map[string]string{
		"not base64":     "not-a-valid-base64-key!!! hunter2",
		"wrong length":   base64.StdEncoding.EncodeToString([]byte("hunter2-too-short")),
		"pem-ish blob":   "-----BEGIN PRIVATE KEY-----\nhunter2\n-----END PRIVATE KEY-----",
		"plaintext word": "correct horse battery staple",
	}
	for name, material := range cases {
		t.Run(name, func(t *testing.T) {
			withKeyPaths(t, filepath.Join(dir, "missing.pub"), filepath.Join(dir, "missing.key"))
			withKeyMaterial(t, material)

			_, err := loadDecryptor(context.Background())
			if err == nil {
				t.Fatal("expected an error for malformed ENVISIBLE_KEY material")
			}
			msg := err.Error()
			if !strings.Contains(msg, "ENVISIBLE_KEY") {
				t.Errorf("error should name the source, got %q", msg)
			}
			if strings.Contains(msg, strings.TrimSpace(material)) {
				t.Errorf("error leaked the key material verbatim: %q", msg)
			}
			for _, frag := range strings.Fields(material) {
				if len(frag) < 4 {
					continue
				}
				if strings.Contains(msg, frag) {
					t.Errorf("error leaked a fragment %q of the key material: %q", frag, msg)
				}
			}
		})
	}
}

// TestLoadDecryptorKMSOnlyWithoutAnyPrivateKey is the regression on the
// best-effort private key read: a fully migrated v2 project has neither a key
// file nor ENVISIBLE_KEY, and must still get a working KMS-backed decryptor.
func TestLoadDecryptorKMSOnlyWithoutAnyPrivateKey(t *testing.T) {
	dir := t.TempDir()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	resource := "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
	defer withFakeKMSProvider(t, kms.GCP, priv, resource)()

	pubPath := filepath.Join(dir, "v2.pub")
	info := &kms.PublicKeyInfo{Kind: kms.GCP, Resource: resource, Alg: kms.RSAOAEPSHA256_2048, PubKey: &priv.PublicKey}
	if err := kms.WritePublicKey(pubPath, info); err != nil {
		t.Fatalf("WritePublicKey: %v", err)
	}

	withKeyPaths(t, pubPath, filepath.Join(dir, "missing.key"))
	withKeyMaterial(t, "")

	dec, err := loadDecryptor(context.Background())
	if err != nil {
		t.Fatalf("KMS-only decryptor should still build: %v", err)
	}
	enc := processor.NewEnvelopeEncryptor(kms.NewRSAWrapper(&priv.PublicKey))
	inner, err := enc.EncryptValue([]byte("kms-secret"))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	got, err := dec.DecryptMarker(context.Background(), inner)
	if err != nil {
		t.Fatalf("DecryptMarker: %v", err)
	}
	if string(got) != "kms-secret" {
		t.Errorf("decrypted %q, want %q", got, "kms-secret")
	}
}

// TestLoadDecryptorNoKeyAtAllKeepsTodaysError pins the wording (and the two
// interpolated paths) of the nothing-available error.
func TestLoadDecryptorNoKeyAtAllKeepsTodaysError(t *testing.T) {
	dir := t.TempDir()
	missingPub := filepath.Join(dir, "missing.pub")
	missingPriv := filepath.Join(dir, "missing.key")
	withKeyPaths(t, missingPub, missingPriv)
	withKeyMaterial(t, "")

	_, err := loadDecryptor(context.Background())
	if err == nil {
		t.Fatal("expected an error when no key of any kind is available")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no decryption key available") {
		t.Errorf("unexpected error text: %q", msg)
	}
	if !strings.Contains(msg, missingPub) || !strings.Contains(msg, missingPriv) {
		t.Errorf("error should name both paths it looked at, got %q", msg)
	}
}

// TestLoadDecryptorWarnsOnPermissiveKeyFile: a key file readable beyond its
// owner warns, but never fails.
func TestLoadDecryptorWarnsOnPermissiveKeyFile(t *testing.T) {
	dir := t.TempDir()
	_, priv := mustKeypair(t)

	origQuiet := ui.Quiet
	ui.Quiet = false
	t.Cleanup(func() { ui.Quiet = origQuiet })

	run := func(t *testing.T, mode os.FileMode) (string, error) {
		t.Helper()
		keyFile := filepath.Join(dir, "perm.key")
		if err := os.WriteFile(keyFile, []byte(envcrypto.EncodeKey(priv)), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(keyFile, mode); err != nil {
			t.Fatal(err)
		}
		withKeyPaths(t, filepath.Join(dir, "missing.pub"), keyFile)
		withKeyMaterial(t, "")

		var err error
		_, stderr := captureStdStreams(t, func() {
			_, err = loadDecryptor(context.Background())
		})
		return stderr, err
	}

	t.Run("group readable", func(t *testing.T) {
		stderr, err := run(t, 0o640)
		if err != nil {
			t.Fatalf("a permissive key file must still work: %v", err)
		}
		if !strings.Contains(stderr, "readable beyond its owner") {
			t.Errorf("expected a permissions warning on stderr, got %q", stderr)
		}
	})

	t.Run("owner only", func(t *testing.T) {
		stderr, err := run(t, 0o600)
		if err != nil {
			t.Fatalf("loadDecryptor: %v", err)
		}
		if strings.Contains(stderr, "readable beyond its owner") {
			t.Errorf("0600 key file should not warn, got %q", stderr)
		}
	})
}
