package crypto

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// v1MinLen is the smallest well-formed v1 blob: ephemeral public key, nonce,
// and the Poly1305 tag of an empty plaintext.
const v1MinLen = 32 + 24 + box.Overhead

// An encrypted empty string is exactly the minimum length, and must decrypt.
// The length check is `<`, not `<=`: tightening it by one rejects this value.
func TestDecryptAcceptsMinimumLengthCiphertext(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	encoded, err := Encrypt(nil, pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if len(raw) != v1MinLen {
		t.Fatalf("encrypted empty string is %d bytes, want exactly %d", len(raw), v1MinLen)
	}

	got, err := Decrypt(encoded, priv)
	if err != nil {
		t.Fatalf("Decrypt of a minimum-length ciphertext: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Decrypt = %q, want empty plaintext", got)
	}
}

// One byte under the minimum is rejected by the length check; exactly at the
// minimum the check passes and the failure comes from authentication instead.
func TestDecryptLengthBoundaryErrors(t *testing.T) {
	_, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	cases := []struct {
		name string
		n    int
		want string
	}{
		{"one byte short", v1MinLen - 1, "ciphertext too short"},
		{"exactly minimum", v1MinLen, "decryption failed"},
		{"header only", 32 + 24, "ciphertext too short"},
		{"empty", 0, "ciphertext too short"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString(make([]byte, tc.n))
			got, err := Decrypt(encoded, priv)
			if err == nil {
				t.Fatalf("Decrypt of %d zero bytes succeeded with %q", tc.n, got)
			}
			if err.Error() != tc.want {
				t.Errorf("Decrypt of %d zero bytes: error = %q, want %q", tc.n, err, tc.want)
			}
		})
	}
}
