package crypto

import (
	"bytes"
	"testing"
)

func TestKeygen(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	if pub == [32]byte{} || priv == [32]byte{} {
		t.Fatal("GenerateKeypair returned empty keys")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	plaintext := []byte("hello world")
	ciphertext, err := Encrypt(plaintext, pub)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, priv)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("expected %s, got %s", plaintext, decrypted)
	}
}

func TestKeyEncoding(t *testing.T) {
	pub, _, _ := GenerateKeypair()
	encoded := EncodeKey(pub)
	decoded, err := DecodeKey(encoded)
	if err != nil {
		t.Fatalf("DecodeKey failed: %v", err)
	}

	if pub != decoded {
		t.Error("encoded/decoded key does not match original")
	}
}

func TestDecryptFailure(t *testing.T) {
	_, priv, _ := GenerateKeypair()
	_, priv2, _ := GenerateKeypair()

	plaintext := []byte("secret")
	// Encrypt for someone else
	pub2, _, _ := GenerateKeypair()
	ciphertext, _ := Encrypt(plaintext, pub2)

	// Try to decrypt with our key
	_, err := Decrypt(ciphertext, priv)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}

	// Try to decrypt with another wrong key
	_, err = Decrypt(ciphertext, priv2)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}
