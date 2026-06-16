package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/rubysolo/envisible/pkg/kms"
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
