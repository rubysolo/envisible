package processor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

	enc := NaclEncryptor{PublicKey: pub}
	dec := NaclDecryptor{PrivateKey: priv}
	ctx := context.Background()

	// Encrypt
	encrypted, err := EncryptContent(content, enc)
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
	encryptedAgain, err := EncryptContent(encrypted, enc)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}
	if !bytes.Equal(encrypted, encryptedAgain) {
		t.Errorf("Encryption not idempotent")
	}

	// Decrypt (keeping markers)
	decrypted, err := DecryptContent(ctx, encrypted, dec, true)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	expected := string(content)
	if string(decrypted) != expected {
		t.Errorf("Decrypted content mismatch.\nExpected: %s\nGot: %s", expected, string(decrypted))
	}

	// Decrypt (stripping markers)
	stripped, err := DecryptContent(ctx, encrypted, dec, false)
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
	encrypted, err := EncryptContent(content, NaclEncryptor{PublicKey: pub})
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
	decrypted, err := DecryptContent(context.Background(), encrypted, NaclDecryptor{PrivateKey: priv}, true)
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
	encrypted, _ := EncryptContent(content, NaclEncryptor{PublicKey: pub})

	env, err := ExtractEnv(context.Background(), encrypted, NaclDecryptor{PrivateKey: priv})
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
	ctx := context.Background()

	_, err := DecryptContent(ctx, content, NaclDecryptor{PrivateKey: priv}, false)
	if err == nil {
		t.Error("expected error for invalid base64")
	}

	// Wrong key
	pub2, _, _ := crypto.GenerateKeypair()
	encrypted, _ := EncryptContent([]byte("ENC[secret]"), NaclEncryptor{PublicKey: pub2})
	_, err = DecryptContent(ctx, encrypted, NaclDecryptor{PrivateKey: priv}, false)
	if err == nil {
		t.Error("expected error for decryption with wrong key")
	}
}

// --- envelope (v2) tests ---

// localRSAUnwrapper performs RSA-OAEP-SHA-256 unwrap with a matching private key.
// Stands in for a real KMS in unit tests.
type localRSAUnwrapper struct{ priv *rsa.PrivateKey }

func (u *localRSAUnwrapper) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, u.priv, wrapped, nil)
}

func newTestEnvelopeKeys(t *testing.T) (*rsa.PrivateKey, *EnvelopeEncryptor, *EnvelopeDecryptor) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	wrapper := newRSAWrapperForTest(&priv.PublicKey)
	enc := NewEnvelopeEncryptor(wrapper)
	dec := NewEnvelopeDecryptor(&localRSAUnwrapper{priv: priv}, priv.Size())
	return priv, enc, dec
}

// newRSAWrapperForTest is a thin local Wrapper that doesn't import pkg/kms (to
// avoid an import cycle now that pkg/processor depends on pkg/kms in production).
// It must produce ciphertext that pkg/kms.NewRSAWrapper would also produce.
type rsaWrapperForTest struct{ pub *rsa.PublicKey }

func (r *rsaWrapperForTest) Wrap(dk []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, r.pub, dk, nil)
}
func (r *rsaWrapperForTest) WrappedSize() int { return r.pub.Size() }

func newRSAWrapperForTest(pub *rsa.PublicKey) *rsaWrapperForTest {
	return &rsaWrapperForTest{pub: pub}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	_, enc, dec := newTestEnvelopeKeys(t)
	ctx := context.Background()

	content := []byte(`
DB_PASSWORD=ENC[supersecret]
API_KEY=ENC[abc-123]
OTHER=plain
`)

	encrypted, err := EncryptContent(content, enc)
	if err != nil {
		t.Fatalf("EncryptContent: %v", err)
	}
	if bytes.Contains(encrypted, []byte("supersecret")) {
		t.Errorf("encrypted content still contains plaintext")
	}
	if !bytes.Contains(encrypted, []byte("ENC[v2:")) {
		t.Errorf("encrypted content missing v2 marker")
	}

	decrypted, err := DecryptContent(ctx, encrypted, dec, true)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}
	if string(decrypted) != string(content) {
		t.Errorf("round trip mismatch.\nexpected: %s\ngot: %s", content, decrypted)
	}
}

func TestEnvelopeHandlesLargePlaintext(t *testing.T) {
	// One of the explicit motivations for the envelope format is encrypting
	// values too large for direct RSA-OAEP (e.g. PEM private keys, certificates).
	_, enc, dec := newTestEnvelopeKeys(t)
	ctx := context.Background()

	// 4 KB of random data — bigger than any direct-RSA scheme could handle.
	big := make([]byte, 4096)
	if _, err := rand.Read(big); err != nil {
		t.Fatalf("rand: %v", err)
	}
	bigB64 := fmt.Sprintf("%x", big) // hex so it survives going through the regex

	content := []byte("BIG=ENC[" + bigB64 + "]")
	encrypted, err := EncryptContent(content, enc)
	if err != nil {
		t.Fatalf("EncryptContent: %v", err)
	}
	decrypted, err := DecryptContent(ctx, encrypted, dec, true)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}
	if string(decrypted) != string(content) {
		t.Errorf("large-plaintext round trip failed")
	}
}

func TestEnvelopeIdempotentEncrypt(t *testing.T) {
	_, enc, _ := newTestEnvelopeKeys(t)
	content := []byte("FOO=ENC[bar]")
	once, err := EncryptContent(content, enc)
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	twice, err := EncryptContent(once, enc)
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}
	if !bytes.Equal(once, twice) {
		t.Errorf("v2 encryption not idempotent")
	}
}

func TestEnvelopeDecryptRejectsTruncated(t *testing.T) {
	_, _, dec := newTestEnvelopeKeys(t)
	ctx := context.Background()
	// "v2:" plus base64 of 10 bytes — far below the wrappedSize + nonce + tag floor.
	short := "v2:AAECAwQFBgcICQ=="
	if _, err := dec.DecryptMarker(ctx, short); err == nil {
		t.Errorf("expected truncated ciphertext to fail")
	}
}

func TestEnvelopeUnwrapCacheCoalescesDuplicateWrappedKeys(t *testing.T) {
	// In practice each ENC value carries its own fresh wrapped DK, but if a file
	// happens to contain the same v2 marker twice the decryptor must not pay two
	// KMS calls.
	priv, enc, _ := newTestEnvelopeKeys(t)

	one, err := enc.EncryptValue([]byte("payload"))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	marker := "ENC[" + one + "]"
	content := []byte(marker + "\n" + marker)

	counting := &countingUnwrapper{priv: priv}
	cachingDec := NewEnvelopeDecryptor(counting, priv.Size())

	got, err := DecryptContent(context.Background(), content, cachingDec, true)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}
	want := "ENC[payload]\nENC[payload]"
	if string(got) != want {
		t.Errorf("decrypt mismatch:\ngot:  %q\nwant: %q", got, want)
	}
	if counting.calls != 1 {
		t.Errorf("Unwrap called %d times, expected 1 due to caching", counting.calls)
	}
}

type countingUnwrapper struct {
	priv  *rsa.PrivateKey
	calls int
}

func (c *countingUnwrapper) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	c.calls++
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, c.priv, wrapped, nil)
}

func TestMixedV1V2File(t *testing.T) {
	// A file that contains both legacy NaCl (v1) and KMS-backed (v2) markers
	// must round-trip when given a composite decryptor. This is the contract that
	// lets users migrate one secret at a time without breaking the file.
	naclPub, naclPriv, _ := crypto.GenerateKeypair()
	naclEnc := NaclEncryptor{PublicKey: naclPub}
	naclDec := NaclDecryptor{PrivateKey: naclPriv}

	_, envEnc, envDec := newTestEnvelopeKeys(t)

	v1Inner, _ := naclEnc.EncryptValue([]byte("legacy-secret"))
	v2Inner, _ := envEnc.EncryptValue([]byte("kms-secret"))

	content := []byte(fmt.Sprintf("LEGACY=ENC[%s]\nKMS=ENC[%s]\nPLAIN=ok", v1Inner, v2Inner))

	composite := CompositeDecryptor{Decryptors: []Decryptor{naclDec, envDec}}
	got, err := DecryptContent(context.Background(), content, composite, true)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}
	want := "LEGACY=ENC[legacy-secret]\nKMS=ENC[kms-secret]\nPLAIN=ok"
	if string(got) != want {
		t.Errorf("mixed-version round trip failed.\ngot:  %q\nwant: %q", got, want)
	}
}

func TestStructureCheck(t *testing.T) {
	// Build a valid v1 ciphertext we can truncate.
	pub, _, _ := crypto.GenerateKeypair()
	v1ct, _ := crypto.Encrypt([]byte("payload"), pub)

	// Build a valid v2 ciphertext we can truncate.
	_, enc, _ := newTestEnvelopeKeys(t)
	v2Inner, _ := enc.EncryptValue([]byte("payload"))

	cases := map[string]struct {
		inner   string
		size    int
		wantErr bool
	}{
		"v1_ok":             {"v1:" + v1ct, 256, false},
		"v2_ok":             {v2Inner, 256, false},
		"unknown_prefix":    {"v9:abcdef", 256, true},
		"no_prefix":         {"raw-secret", 256, true},
		"v1_truncated":      {"v1:" + v1ct[:8], 256, true},
		"v2_truncated":      {v2Inner[:10] + "==", 256, true},
		"v1_bad_base64":     {"v1:not-base64!!!", 256, true},
		"v2_bad_base64":     {"v2:!!!not-base64", 256, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := StructureCheck(tc.inner, tc.size)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tc.inner)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tc.inner, err)
			}
		})
	}
}

func TestCompositeFallsThroughOnSkip(t *testing.T) {
	// Sanity: if all members ErrSkip, the composite also reports ErrSkip — so the
	// processor leaves the marker untouched rather than treating it as a hard fail.
	_, _, envDec := newTestEnvelopeKeys(t)
	_, naclPriv, _ := crypto.GenerateKeypair()
	composite := CompositeDecryptor{Decryptors: []Decryptor{envDec, NaclDecryptor{PrivateKey: naclPriv}}}

	if _, err := composite.DecryptMarker(context.Background(), "not-encrypted"); err != ErrSkip {
		t.Errorf("expected ErrSkip, got %v", err)
	}
}
