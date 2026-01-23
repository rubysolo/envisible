package processor

import (
	"bytes"
	"testing"

	"github.com/rubysolo/envisible/pkg/crypto"
)

func TestEncryptDecrypt(t *testing.T) {
	pub, priv, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	content := []byte(`
DB_PASSWORD=ENC[supersecret]
API_KEY=ENC[abc-123]
OTHER=plain
`)

	// Encrypt
	encrypted, err := EncryptContent(content, pub)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if bytes.Contains(encrypted, []byte("supersecret")) {
		t.Errorf("Encrypted content still contains plaintext")
	}
	if !bytes.Contains(encrypted, []byte("ENC[v1:")) {
		t.Errorf("Encrypted content missing v1 marker")
	}

	// Idempotency: Encrypting again should not change anything (since markers are v1:)
	encryptedAgain, err := EncryptContent(encrypted, pub)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}
	if !bytes.Equal(encrypted, encryptedAgain) {
		t.Errorf("Encryption not idempotent")
	}

	// Decrypt (keeping markers)
	decrypted, err := DecryptContent(encrypted, priv, true)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	expected := string(content)
	if string(decrypted) != expected {
		t.Errorf("Decrypted content mismatch.\nExpected: %s\nGot: %s", expected, string(decrypted))
	}

	// Decrypt (stripping markers)
	stripped, err := DecryptContent(encrypted, priv, false)
	if err != nil {
		t.Fatalf("Stripped decryption failed: %v", err)
	}
	if bytes.Contains(stripped, []byte("ENC[")) {
		t.Errorf("Stripped content still contains markers")
	}
}

func TestExtractEnv(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeypair()
	content := []byte("FOO=ENC[bar]\nBAZ=\"ENC[qux]\"\n# Comment\nPLAIN=simple")
	encrypted, _ := EncryptContent(content, pub)

	env, err := ExtractEnv(encrypted, priv)
	if err != nil {
		t.Fatalf("ExtractEnv failed: %v", err)
	}

	if env["FOO"] != "bar" {
		t.Errorf("expected bar, got %s", env["FOO"])
	}
	if env["BAZ"] != "qux" {
		t.Errorf("expected qux, got %s", env["BAZ"])
	}
	if env["PLAIN"] != "simple" {
		t.Errorf("expected simple, got %s", env["PLAIN"])
	}
}

func TestDecryptErrors(t *testing.T) {
	_, priv, _ := crypto.GenerateKeypair()
	content := []byte("BAD=ENC[v1:not-base64-at-all]")
	
	_, err := DecryptContent(content, priv, false)
	if err == nil {
		t.Error("expected error for invalid base64")
	}

	// Wrong key
	pub2, _, _ := crypto.GenerateKeypair()
	encrypted, _ := EncryptContent([]byte("ENC[secret]"), pub2)
	_, err = DecryptContent(encrypted, priv, false)
	if err == nil {
		t.Error("expected error for decryption with wrong key")
	}
}

