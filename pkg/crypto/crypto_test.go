package crypto

import (
	"bytes"
	"encoding/base64"
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

// A v1 blob is ephemeral_pub[32] || nonce[24] || box. Flipping a single bit in
// any of the three must fail the open: none of it is malleable, and a tampered
// marker is an error, never a value.
func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	plaintext := []byte("tamper-me")
	ciphertext, err := Encrypt(plaintext, pub)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	blob, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatalf("Encrypt returned invalid base64: %v", err)
	}
	if want := 32 + 24 + len(plaintext) + 16; len(blob) != want {
		t.Fatalf("blob is %d bytes, want %d", len(blob), want)
	}

	offsets := map[string]int{
		"ephemeral_pubkey": 0,
		"nonce":            32,
		"payload_first":    56,
		"payload_last":     len(blob) - 1,
	}
	for name, offset := range offsets {
		t.Run(name, func(t *testing.T) {
			tampered := append([]byte(nil), blob...)
			tampered[offset] ^= 0x01
			got, err := Decrypt(base64.StdEncoding.EncodeToString(tampered), priv)
			if err == nil {
				t.Errorf("a flipped bit at offset %d decrypted to %q", offset, got)
			}
			if got != nil {
				t.Errorf("a failed decrypt returned data: %q", got)
			}
		})
	}
}

// Anything shorter than pubkey + nonce + tag cannot be a ciphertext. It must
// come back as an error — in particular it must not panic slicing the header.
func TestDecryptRejectsTruncatedCiphertext(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	ciphertext, err := Encrypt([]byte("payload"), pub)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	blob, _ := base64.StdEncoding.DecodeString(ciphertext)

	cases := map[string][]byte{
		"empty":             {},
		"three_bytes":       {0, 0, 0}, // base64 "AAAA"
		"header_cut_short":  blob[:55],
		"header_only":       blob[:56],
		"one_short_of_tag":  blob[:71],
		"zeros_under_floor": make([]byte, 40),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Decrypt(base64.StdEncoding.EncodeToString(data), priv)
			if err == nil {
				t.Fatalf("a %d-byte blob decrypted to %q", len(data), got)
			}
			if err.Error() != "ciphertext too short" {
				t.Errorf("error = %q, want the length guard's \"ciphertext too short\"", err)
			}
		})
	}
}
