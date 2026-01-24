package processor

import (
	"bytes"
	"fmt"
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

func TestPartialEncryption(t *testing.T) {
	pub, priv, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// 1. Start with one already encrypted value and one plain value
	secret1 := "already-encrypted"
	secret2 := "newly-encrypted"

	enc1, _ := crypto.Encrypt([]byte(secret1), pub)
	marker1 := "ENC[v1:" + enc1 + "]"

	content := []byte(fmt.Sprintf("VAR1=%s\nVAR2=ENC[%s]", marker1, secret2))

	// 2. Run encryption
	encrypted, err := EncryptContent(content, pub)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 3. Verify VAR1 is unchanged and VAR2 is encrypted
	if !bytes.Contains(encrypted, []byte(marker1)) {
		t.Error("Pre-encrypted marker was modified")
	}
	if !bytes.Contains(encrypted, []byte("VAR2=ENC[v1:")) {
		t.Error("New marker was not encrypted")
	}
	if bytes.Contains(encrypted, []byte(secret2)) {
		t.Error("New secret still visible in plaintext")
	}

	// 4. Decrypt and verify both are correct
	decrypted, err := DecryptContent(encrypted, priv, true)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	expected := fmt.Sprintf("VAR1=ENC[%s]\nVAR2=ENC[%s]", secret1, secret2)
	if string(decrypted) != expected {
		t.Errorf("Decrypted content mismatch.\nExpected: %s\nGot: %s", expected, string(decrypted))
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
