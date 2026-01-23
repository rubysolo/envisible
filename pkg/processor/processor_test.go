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
