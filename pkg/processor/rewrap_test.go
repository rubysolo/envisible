package processor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
)

func TestRewrapContentReencryptsV2MarkersOnly(t *testing.T) {
	// Generate two distinct RSA keys: "old" and "new". Build a fake unwrapper
	// for each by closing over the corresponding private key.
	oldPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey (old): %v", err)
	}
	newPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey (new): %v", err)
	}

	oldWrapper := newRSAWrapperForTest(&oldPriv.PublicKey)
	newWrapper := newRSAWrapperForTest(&newPriv.PublicKey)
	oldUnwrapper := &localRSAUnwrapper{priv: oldPriv}
	newUnwrapper := &localRSAUnwrapper{priv: newPriv}

	// Encrypt a file with the OLD key.
	enc := NewEnvelopeEncryptor(oldWrapper)
	plain := []byte("DB_URL=ENC[postgres://user:pass@host/db]\nLEGACY=ENC[v1:not-touched]\nPLAIN=ok")
	encrypted, err := EncryptContent(plain, enc)
	if err != nil {
		t.Fatalf("EncryptContent: %v", err)
	}
	if !bytes.Contains(encrypted, []byte("ENC[v2:")) {
		t.Fatalf("setup: expected a v2 marker in input")
	}

	// Sanity: the v1 marker passes through untouched (no Wrap/Unwrap involved).
	if !bytes.Contains(encrypted, []byte("ENC[v1:not-touched]")) {
		t.Fatalf("setup: v1 marker was rewritten by encrypt; got %s", encrypted)
	}

	// Rotate: rewrap each v2 marker against newWrapper.
	rotated, count, err := RewrapContent(context.Background(), encrypted, oldUnwrapper, oldPriv.Size(), newWrapper)
	if err != nil {
		t.Fatalf("RewrapContent: %v", err)
	}
	if count != 1 {
		t.Errorf("rotated count = %d, want 1 (only one v2 marker in the file)", count)
	}
	if !bytes.Contains(rotated, []byte("ENC[v1:not-touched]")) {
		t.Errorf("v1 marker was modified during rotation")
	}
	if bytes.Equal(rotated, encrypted) {
		t.Errorf("rotated content is identical to input — rewrap was a no-op")
	}

	// The OLD unwrapper must NOT be able to decrypt the rotated file anymore.
	oldDec := NewEnvelopeDecryptor(oldUnwrapper, oldPriv.Size())
	if _, err := DecryptContent(context.Background(), rotated, oldDec, true); err == nil {
		t.Errorf("rotated content was decryptable by the old key — rotation didn't take effect")
	}

	// The NEW unwrapper must successfully decrypt the rotated file and recover
	// the original plaintext.
	newDec := NewEnvelopeDecryptor(newUnwrapper, newPriv.Size())
	got, err := DecryptContent(context.Background(), rotated, newDec, true)
	if err != nil {
		t.Fatalf("DecryptContent with new key: %v", err)
	}
	// The v2 marker should reveal the original plaintext value.
	if !bytes.Contains(got, []byte("ENC[postgres://user:pass@host/db]")) {
		t.Errorf("rotated file did not round-trip; got: %s", got)
	}
}

func TestRewrapContentRejectsCorruptCiphertext(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrapper := newRSAWrapperForTest(&priv.PublicKey)
	unwrapper := &localRSAUnwrapper{priv: priv}

	// A v2 marker with random bytes that won't survive RSA-OAEP decryption.
	garbage := make([]byte, priv.Size()+24+16)
	_, _ = rand.Read(garbage)
	content := []byte("BAD=ENC[v2:" + base64.StdEncoding.EncodeToString(garbage) + "]")

	_, _, err := RewrapContent(context.Background(), content, unwrapper, priv.Size(), wrapper)
	if err == nil {
		t.Errorf("expected RewrapContent to fail on garbage ciphertext")
	}
	if !strings.Contains(err.Error(), "rewrap") {
		t.Errorf("error message doesn't mention rewrap context: %v", err)
	}
}

func TestRewrapContentLeavesNonV2Untouched(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrapper := newRSAWrapperForTest(&priv.PublicKey)
	unwrapper := &localRSAUnwrapper{priv: priv}

	content := []byte("PLAIN=ENC[my-secret]\nLEGACY=ENC[v1:abc]\nNOTHING_HERE=value")
	rotated, count, err := RewrapContent(context.Background(), content, unwrapper, priv.Size(), wrapper)
	if err != nil {
		t.Fatalf("RewrapContent: %v", err)
	}
	if count != 0 {
		t.Errorf("rotated count = %d, want 0 (no v2 markers in input)", count)
	}
	if !bytes.Equal(rotated, content) {
		t.Errorf("file with no v2 markers was modified")
	}
}
