package processor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
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

func TestEncryptSkipsMarkersInComments(t *testing.T) {
	pub, priv, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	content := []byte("# ENC[full-line-comment]\n" +
		"DB_PASSWORD=ENC[supersecret]  # old: ENC[oldsecret]\n" +
		"   # ENC[indented-comment]\n" +
		"NOTE=plain # trailing ENC[also-comment]\n" +
		"HASHY=ENC[p@ss # word]\n" +
		"NOSPACE=ENC[a#b]\n")

	encrypted, err := EncryptContent(content, NaclEncryptor{PublicKey: pub})
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Comment-bound markers must be left literal.
	commentLiterals := [][]byte{
		[]byte("# ENC[full-line-comment]"),
		[]byte("# old: ENC[oldsecret]"),
		[]byte("# ENC[indented-comment]"),
		[]byte("# trailing ENC[also-comment]"),
	}
	for _, want := range commentLiterals {
		if !bytes.Contains(encrypted, want) {
			t.Errorf("expected commented marker %q to be preserved verbatim", want)
		}
	}

	// Real values must be encrypted, including ones whose plaintext contains '#'.
	for _, plain := range [][]byte{
		[]byte("ENC[supersecret]"),
		[]byte("ENC[p@ss # word]"),
		[]byte("ENC[a#b]"),
	} {
		if bytes.Contains(encrypted, plain) {
			t.Errorf("expected plaintext marker %q to be encrypted", plain)
		}
	}
	for _, prefix := range [][]byte{
		[]byte("DB_PASSWORD=ENC[v1:"),
		[]byte("HASHY=ENC[v1:"),
		[]byte("NOSPACE=ENC[v1:"),
	} {
		if !bytes.Contains(encrypted, prefix) {
			t.Errorf("expected %q in encrypted output", prefix)
		}
	}

	// Round-trip: decrypting (keepMarkers) must reproduce the original content.
	// The commented markers carry no version prefix so DecryptContent leaves
	// them untouched, while the real values come back as ENC[plaintext].
	decrypted, err := DecryptContent(context.Background(), encrypted, NaclDecryptor{PrivateKey: priv}, true)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, content) {
		t.Errorf("round trip mismatch.\nwant:\n%s\ngot:\n%s", content, decrypted)
	}
}

func TestDecryptSkipsMarkersInComments(t *testing.T) {
	// Symmetric to TestEncryptSkipsMarkersInComments: a real ciphertext sitting
	// in a comment (e.g. an old value kept for reference) must be left literal
	// rather than decrypted — otherwise plaintext leaks back into the comment.
	pub, priv, _ := crypto.GenerateKeypair()
	enc := NaclEncryptor{PublicKey: pub}
	dec := NaclDecryptor{PrivateKey: priv}

	liveInner, _ := enc.EncryptValue([]byte("live-secret"))
	staleInner, _ := enc.EncryptValue([]byte("stale-secret"))

	content := []byte("PASSWORD=ENC[" + liveInner + "]  # old: ENC[" + staleInner + "]\n" +
		"# ENC[" + staleInner + "]\n")

	got, err := DecryptContent(context.Background(), content, dec, true)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}

	if !bytes.Contains(got, []byte("PASSWORD=ENC[live-secret]")) {
		t.Errorf("live value should be decrypted; got:\n%s", got)
	}
	if !bytes.Contains(got, []byte("# old: ENC["+staleInner+"]")) {
		t.Errorf("trailing-comment ciphertext should not be decrypted; got:\n%s", got)
	}
	if !bytes.Contains(got, []byte("# ENC["+staleInner+"]")) {
		t.Errorf("full-line-comment ciphertext should not be decrypted; got:\n%s", got)
	}
	if bytes.Contains(got, []byte("stale-secret")) {
		t.Errorf("stale secret leaked into output; got:\n%s", got)
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

	out, err := DecryptContent(ctx, content, NaclDecryptor{PrivateKey: priv}, false)
	if err == nil {
		t.Error("expected error for invalid base64")
	}
	// The marker that failed stays exactly as it was: never dropped, never
	// replaced by an empty value.
	if !bytes.Equal(out, content) {
		t.Errorf("content changed on a failed decrypt.\ngot:  %q\nwant: %q", out, content)
	}

	// Wrong key
	pub2, _, _ := crypto.GenerateKeypair()
	encrypted, _ := EncryptContent([]byte("ENC[secret]"), NaclEncryptor{PublicKey: pub2})
	out, err = DecryptContent(ctx, encrypted, NaclDecryptor{PrivateKey: priv}, false)
	if err == nil {
		t.Error("expected error for decryption with wrong key")
	}
	if !bytes.Equal(out, encrypted) {
		t.Errorf("content changed on a failed decrypt.\ngot:  %q\nwant: %q", out, encrypted)
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

	// Truncations are valid base64 of a too-short blob, so they get past the
	// decode and reach the length check they are named for.
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }

	// wantErr is a substring of the expected error; empty means no error.
	cases := map[string]struct {
		inner   string
		size    int
		wantErr string
	}{
		"v1_ok":          {"v1:" + v1ct, 256, ""},
		"v2_ok":          {v2Inner, 256, ""},
		"v1_minimum":     {"v1:" + b64(72), 256, ""},
		"v2_minimum":     {"v2:" + b64(256+24+16), 256, ""},
		"unknown_prefix": {"v9:abcdef", 256, "unknown marker version: v9:"},
		"no_prefix":      {"raw-secret", 256, "not a versioned marker"},
		"v1_truncated":   {"v1:" + v1ct[:8], 256, "v1: ciphertext truncated"},
		"v1_one_short":   {"v1:" + b64(71), 256, "v1: ciphertext truncated"},
		// 40 bytes is exactly nonce + tag: long enough only if the wrapped
		// data key is left out of the minimum.
		"v2_truncated":     {"v2:" + b64(40), 256, "v2: ciphertext truncated"},
		"v2_one_short":     {"v2:" + b64(256+24+16-1), 256, "v2: ciphertext truncated"},
		"v2_short_for_key": {v2Inner, 512, "v2: ciphertext truncated"},
		"v1_bad_base64":    {"v1:not-base64!!!", 256, "v1: base64 decode"},
		"v2_bad_base64":    {"v2:!!!not-base64", 256, "v2: base64 decode"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := StructureCheck(tc.inner, tc.size)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error for %q", tc.inner)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
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

// --- evidence table from docs/plans/01-marker-scanner.md ---
//
// Each of these inputs used to be silently truncated, silently corrupted, or a
// silent no-op that `envisible check` reported as clean. They now either
// round-trip exactly or produce a loud defect.

// Row 1: `password: ENC[ab]cd]`. The bracket is genuinely ambiguous, so the two
// halves of the fix are (a) the documented escape round-trips exactly, and
// (b) the unescaped form is flagged rather than passing silently.
func TestEvidenceRowTrailingBracket(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeypair()
	enc := NaclEncryptor{PublicKey: pub}
	dec := NaclDecryptor{PrivateKey: priv}
	ctx := context.Background()

	// (a) Escaped: the whole value is encrypted, nothing is left in the clear.
	escaped := []byte(`password: ENC[ab\]cd]`)
	encrypted, defects, err := EncryptContentWithDefects(escaped, enc)
	if err != nil {
		t.Fatalf("EncryptContentWithDefects: %v", err)
	}
	if len(defects) != 0 {
		t.Fatalf("unexpected defects: %+v", defects)
	}
	if bytes.Contains(encrypted, []byte("cd")) {
		t.Errorf("part of the secret stayed in the file as plaintext: %s", encrypted)
	}
	stripped, err := DecryptContent(ctx, encrypted, dec, false)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}
	if string(stripped) != "password: ab]cd" {
		t.Errorf("round trip = %q, want %q", stripped, "password: ab]cd")
	}

	// (b) Unescaped: the scanner reads "ab" (unavoidable), but the trailing
	// unmatched bracket is detectable so `check` can warn about it.
	ambiguous := []byte("password: ENC[ab]cd]")
	markers, _ := Scan(ambiguous)
	if len(markers) != 1 || markers[0].Value != "ab" {
		t.Fatalf("markers = %+v, want a single marker with Value \"ab\"", markers)
	}
	if !UnmatchedTrailingBracket(ambiguous, markers[0]) {
		t.Errorf("the ambiguous form must be flagged by the heuristic")
	}
}

// Row 2: `sa: ENC[{"scopes":["a","b"]}]` used to lose the ']' that closed the
// JSON array. Bracket balancing keeps the value intact.
func TestEvidenceRowBracketedStructure(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeypair()
	ctx := context.Background()

	const value = `{"scopes":["a","b"]}`
	content := []byte(`sa: ENC[` + value + `]`)

	encrypted, defects, err := EncryptContentWithDefects(content, NaclEncryptor{PublicKey: pub})
	if err != nil {
		t.Fatalf("EncryptContentWithDefects: %v", err)
	}
	if len(defects) != 0 {
		t.Fatalf("unexpected defects: %+v", defects)
	}
	if bytes.Contains(encrypted, []byte("scopes")) {
		t.Errorf("plaintext survived encryption: %s", encrypted)
	}

	stripped, err := DecryptContent(ctx, encrypted, NaclDecryptor{PrivateKey: priv}, false)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}
	if string(stripped) != "sa: "+value {
		t.Errorf("value was corrupted.\ngot:  %s\nwant: %s", stripped, "sa: "+value)
	}
}

// Row 3: a multi-line PEM used to be a total no-op — the file was written back
// with the private key still in the clear.
func TestEvidenceRowMultiLineValue(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeypair()
	ctx := context.Background()

	const pem = "-----BEGIN KEY-----\nMIIEv\n-----END KEY-----"
	contPEM := strings.ReplaceAll(pem, "\n", "\\\n")
	content := []byte("key: ENC[" + contPEM + "]\nother: plain\n")

	encrypted, defects, err := EncryptContentWithDefects(content, NaclEncryptor{PublicKey: pub})
	if err != nil {
		t.Fatalf("EncryptContentWithDefects: %v", err)
	}
	if len(defects) != 0 {
		t.Fatalf("unexpected defects: %+v", defects)
	}
	if bytes.Contains(encrypted, []byte("MIIEv")) {
		t.Errorf("multi-line plaintext was left in the file: %s", encrypted)
	}
	if !bytes.Contains(encrypted, []byte("other: plain")) {
		t.Errorf("surrounding content was disturbed: %s", encrypted)
	}
	if bytes.Count(encrypted, []byte("\n")) != 2 {
		t.Errorf("ciphertext must occupy a single line; got: %s", encrypted)
	}

	decrypted, err := DecryptContent(ctx, encrypted, NaclDecryptor{PrivateKey: priv}, true)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}
	if !bytes.Equal(decrypted, content) {
		t.Errorf("multi-line round trip failed.\ngot:\n%s\nwant:\n%s", decrypted, content)
	}
}

// Row 4: `key: ENC[oops-no-close` used to match nothing at all, so encrypt
// reported success and check passed. It is now a reported defect.
func TestEvidenceRowUnterminatedMarker(t *testing.T) {
	pub, _, _ := crypto.GenerateKeypair()
	content := []byte("key: ENC[oops-no-close\n")

	out, defects, err := EncryptContentWithDefects(content, NaclEncryptor{PublicKey: pub})
	if err != nil {
		t.Fatalf("EncryptContentWithDefects: %v", err)
	}
	if len(defects) != 1 || defects[0].Kind != Unterminated {
		t.Fatalf("defects = %+v, want one Unterminated", defects)
	}
	if line, col := LineCol(content, defects[0].Offset); line != 1 || col != 6 {
		t.Errorf("defect located at %d:%d, want 1:6", line, col)
	}
	if !bytes.Equal(out, content) {
		t.Errorf("content should be untouched when nothing parses; got %s", out)
	}
}

// Row 5: the case that already worked. It must not regress.
func TestEvidenceRowTwoMarkersOneLine(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeypair()
	ctx := context.Background()

	content := []byte("a: ENC[one] b: ENC[two]")
	encrypted, defects, err := EncryptContentWithDefects(content, NaclEncryptor{PublicKey: pub})
	if err != nil {
		t.Fatalf("EncryptContentWithDefects: %v", err)
	}
	if len(defects) != 0 {
		t.Fatalf("unexpected defects: %+v", defects)
	}
	if n := bytes.Count(encrypted, []byte("ENC[v1:")); n != 2 {
		t.Errorf("expected 2 encrypted markers, got %d: %s", n, encrypted)
	}

	stripped, err := DecryptContent(ctx, encrypted, NaclDecryptor{PrivateKey: priv}, false)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}
	if string(stripped) != "a: one b: two" {
		t.Errorf("round trip = %q, want %q", stripped, "a: one b: two")
	}
}

// TestEditRoundTripPreservesBracketsAndNewlines is the `envisible edit` shape:
// encrypt, decrypt with markers kept, re-encrypt the edited buffer, decrypt
// again. DecryptContent(keepMarkers) re-escapes, so a value full of brackets,
// backslashes and newlines survives an arbitrary number of laps.
func TestEditRoundTripPreservesBracketsAndNewlines(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeypair()
	enc := NaclEncryptor{PublicKey: pub}
	dec := NaclDecryptor{PrivateKey: priv}
	ctx := context.Background()

	value := "a]b[c\\d\ne]f"
	original := []byte("secret: ENC[" + escapeMarkerValue(value) + "]\ntrailing: 1\n")

	encrypted, err := EncryptContent(original, enc)
	if err != nil {
		t.Fatalf("EncryptContent: %v", err)
	}

	for lap := 0; lap < 3; lap++ {
		// What `edit` puts in the temp file.
		editable, err := DecryptContent(ctx, encrypted, dec, true)
		if err != nil {
			t.Fatalf("lap %d: DecryptContent: %v", lap, err)
		}
		if !bytes.Equal(editable, original) {
			t.Fatalf("lap %d: editable buffer drifted.\ngot:  %q\nwant: %q", lap, editable, original)
		}
		// What `edit` writes back.
		encrypted, err = EncryptContent(editable, enc)
		if err != nil {
			t.Fatalf("lap %d: re-encrypt: %v", lap, err)
		}
	}

	stripped, err := DecryptContent(ctx, encrypted, dec, false)
	if err != nil {
		t.Fatalf("DecryptContent(strip): %v", err)
	}
	want := "secret: " + value + "\ntrailing: 1\n"
	if string(stripped) != want {
		t.Errorf("final plaintext = %q, want %q", stripped, want)
	}
}

func TestRewrapContentSkipsCiphertextInComments(t *testing.T) {
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

	enc := NewEnvelopeEncryptor(oldWrapper)
	live, err := enc.EncryptValue([]byte("live"))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	stale, err := enc.EncryptValue([]byte("stale"))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}

	content := []byte("LIVE=ENC[" + live + "]  # old: ENC[" + stale + "]\n" +
		"# ENC[" + stale + "]\n")

	rotated, count, err := RewrapContent(context.Background(), content, oldUnwrapper, oldPriv.Size(), newWrapper)
	if err != nil {
		t.Fatalf("RewrapContent: %v", err)
	}
	if count != 1 {
		t.Errorf("rotated %d markers, want 1 (the commented ones must be skipped)", count)
	}
	if bytes.Contains(rotated, []byte("ENC["+live+"]")) {
		t.Errorf("the live marker was not rewrapped")
	}
	if n := bytes.Count(rotated, []byte("ENC["+stale+"]")); n != 2 {
		t.Errorf("commented ciphertexts were sent to the KMS: found %d of 2 unchanged", n)
	}
}

func TestExtractEnvReportsDefects(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeypair()
	content := []byte("GOOD=ENC[value]\n")
	encrypted, err := EncryptContent(content, NaclEncryptor{PublicKey: pub})
	if err != nil {
		t.Fatalf("EncryptContent: %v", err)
	}
	encrypted = append(encrypted, []byte("BROKEN=ENC[oops\n")...)

	env, defects, err := ExtractEnvWithDefects(context.Background(), encrypted, NaclDecryptor{PrivateKey: priv})
	if err != nil {
		t.Fatalf("ExtractEnvWithDefects: %v", err)
	}
	if len(defects) != 1 || defects[0].Kind != Unterminated {
		t.Errorf("defects = %+v, want one Unterminated", defects)
	}
	if env["GOOD"] != "value" {
		t.Errorf("a defect elsewhere must not stop the good values loading; got %v", env)
	}
}

func TestEncryptContentReportsMalformedCiphertext(t *testing.T) {
	pub, _, _ := crypto.GenerateKeypair()
	content := []byte("A=ENC[v1:truncated\nB=ENC[plain]\n")

	out, defects, err := EncryptContentWithDefects(content, NaclEncryptor{PublicKey: pub})
	if err != nil {
		t.Fatalf("EncryptContentWithDefects: %v", err)
	}
	if len(defects) != 1 || defects[0].Kind != MalformedCiphertext {
		t.Fatalf("defects = %+v, want one MalformedCiphertext", defects)
	}
	// The healthy marker on the next line is still processed.
	if !bytes.Contains(out, []byte("B=ENC[v1:")) {
		t.Errorf("a defect must not stop the rest of the file from encrypting: %s", out)
	}
}

func TestDefectsInCommentsAreNotReported(t *testing.T) {
	pub, _, _ := crypto.GenerateKeypair()
	content := []byte("# TODO: wrap this in ENC[\nA=ENC[value]\n")

	_, defects, err := EncryptContentWithDefects(content, NaclEncryptor{PublicKey: pub})
	if err != nil {
		t.Fatalf("EncryptContentWithDefects: %v", err)
	}
	if len(defects) != 0 {
		t.Errorf("prose in a comment is not a malformed marker; got %+v", defects)
	}
}

// --- review regressions -----------------------------------------------------

// A stray 'ENC[' in prose used to open a plaintext body that ran across the
// newline, absorbed the real marker below it, and was then dropped whole
// because its Start was inside a comment. The file came out of Scan with zero
// markers and zero defects, so `encrypt` was a no-op and `check` passed on a
// committed cleartext password.
func TestCommentBracketDoesNotHideTheMarkerBelowIt(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeypair()
	ctx := context.Background()

	content := []byte("# TODO: wrap this in ENC[\npassword: ENC[hunter2]\nargs: ]\n")

	encrypted, defects, err := EncryptContentWithDefects(content, NaclEncryptor{PublicKey: pub})
	if err != nil {
		t.Fatalf("EncryptContentWithDefects: %v", err)
	}
	if len(defects) != 0 {
		t.Fatalf("prose in a comment is not a defect; got %+v", defects)
	}
	if bytes.Contains(encrypted, []byte("hunter2")) {
		t.Fatalf("the password was left in the clear: %s", encrypted)
	}
	if !bytes.Contains(encrypted, []byte("# TODO: wrap this in ENC[")) {
		t.Errorf("the comment was rewritten: %s", encrypted)
	}
	if !bytes.Contains(encrypted, []byte("args: ]")) {
		t.Errorf("trailing content was disturbed: %s", encrypted)
	}

	stripped, err := DecryptContent(ctx, encrypted, NaclDecryptor{PrivateKey: priv}, false)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}
	if want := "# TODO: wrap this in ENC[\npassword: hunter2\nargs: ]\n"; string(stripped) != want {
		t.Errorf("round trip = %q, want %q", stripped, want)
	}
}

// The same root cause aimed at an already-encrypted file: an unbalanced '[' in
// a comment used to swallow the ENC[v1:...] below it, so `decrypt` emitted the
// literal ciphertext, `check` counted zero markers and passed, and `kms rotate`
// reported success having rotated nothing — after which destroying the old key
// would have made the value unrecoverable. "Existing encrypted files are
// unaffected" has to survive prose being added around them.
func TestCommentBracketDoesNotHideAnExistingCiphertext(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeypair()
	ctx := context.Background()

	inner, err := NaclEncryptor{PublicKey: pub}.EncryptValue([]byte("hunter2"))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	content := []byte("# old form was ENC[pw[1\npassword: ENC[" + inner + "]\n# ...and it ended with ]]\n")

	markers, defects := Scan(content)
	if len(defects) != 0 {
		t.Fatalf("defects: %+v", defects)
	}
	if len(markers) != 1 || !markers[0].Encrypted || markers[0].Raw != inner {
		t.Fatalf("the ciphertext must still be visible to the scanner; got %+v", markers)
	}

	stripped, err := DecryptContent(ctx, content, NaclDecryptor{PrivateKey: priv}, false)
	if err != nil {
		t.Fatalf("DecryptContent: %v", err)
	}
	if !bytes.Contains(stripped, []byte("password: hunter2")) {
		t.Errorf("the ciphertext was not decrypted: %s", stripped)
	}
}

// On the write path, a plaintext body that balanced across lines used to splice
// the whole absorbed region — including a pre-existing ENC[v1:...] — into one
// new marker: three lines of YAML collapsed to one, and ciphertext bytes moved.
// It is now a reported defect, so `encrypt` refuses the file.
func TestEncryptRefusesToAbsorbAnExistingCiphertext(t *testing.T) {
	pub, _, _ := crypto.GenerateKeypair()

	inner, err := NaclEncryptor{PublicKey: pub}.EncryptValue([]byte("api"))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	content := []byte("password: ENC[p@ss[word]\napi_key: ENC[" + inner + "]\npw2: ENC[ab]cd]\n")

	out, defects, err := EncryptContentWithDefects(content, NaclEncryptor{PublicKey: pub})
	if err != nil {
		t.Fatalf("EncryptContentWithDefects: %v", err)
	}
	if len(defects) != 1 || defects[0].Kind != Unterminated {
		t.Fatalf("defects = %+v, want one Unterminated", defects)
	}
	if line, _ := LineCol(content, defects[0].Offset); line != 1 {
		t.Errorf("defect reported on line %d, want 1", line)
	}
	// Even though the caller must not write this output, not one byte of the
	// pre-existing ciphertext may have moved, and the line structure stands.
	if !bytes.Contains(out, []byte("api_key: ENC["+inner+"]")) {
		t.Errorf("the pre-existing ciphertext was rewritten: %s", out)
	}
	if bytes.Count(out, []byte("\n")) != 3 {
		t.Errorf("line structure collapsed: %s", out)
	}
}

// A secret whose plaintext starts with a version prefix used to survive the
// `edit` round trip as cleartext: DecryptContent(keepMarkers) wrote
// ENC[v1:s3cr3t-token], the scanner read it back in ciphertext mode, and
// EncryptContent reported success without touching it — leaving the secret on
// disk in the clear and the file undecryptable.
func TestEditRoundTripOfAVersionPrefixedSecret(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeypair()
	enc := NaclEncryptor{PublicKey: pub}
	dec := NaclDecryptor{PrivateKey: priv}
	ctx := context.Background()

	for _, secret := range []string{"v1:s3cr3t-token", "v0:a]b"} {
		t.Run(secret, func(t *testing.T) {
			original := []byte("TOKEN: " + wrapMarker(escapeMarkerValue(secret)) + "\n")

			encrypted, defects, err := EncryptContentWithDefects(original, enc)
			if err != nil {
				t.Fatalf("EncryptContentWithDefects: %v", err)
			}
			if len(defects) != 0 {
				t.Fatalf("defects: %+v", defects)
			}
			if bytes.Contains(encrypted, []byte(secret)) {
				t.Fatalf("the secret is still in the file as plaintext: %s", encrypted)
			}

			// What `edit` puts in the temp file, then writes back.
			editable, err := DecryptContent(ctx, encrypted, dec, true)
			if err != nil {
				t.Fatalf("DecryptContent(keepMarkers): %v", err)
			}
			if !bytes.Equal(editable, original) {
				t.Fatalf("editable buffer drifted: %q, want %q", editable, original)
			}
			markers, defects := Scan(editable)
			if len(defects) != 0 || len(markers) != 1 {
				t.Fatalf("rescan: markers %+v defects %+v", markers, defects)
			}
			if markers[0].Encrypted {
				t.Fatalf("the plaintext was re-read as ciphertext: %+v", markers[0])
			}

			reencrypted, _, err := EncryptContentWithDefects(editable, enc)
			if err != nil {
				t.Fatalf("re-encrypt: %v", err)
			}
			if bytes.Contains(reencrypted, []byte(secret)) {
				t.Fatalf("re-encrypt left the secret in the clear: %s", reencrypted)
			}

			stripped, err := DecryptContent(ctx, reencrypted, dec, false)
			if err != nil {
				t.Fatalf("final decrypt: %v", err)
			}
			if want := "TOKEN: " + secret + "\n"; string(stripped) != want {
				t.Errorf("final plaintext = %q, want %q", stripped, want)
			}
		})
	}
}

// TestEvidenceRowBareMultiLineMarkerIsADefect is the other half of evidence
// row 3. A plaintext body ends at the first unescaped newline, so a value
// pasted in raw across lines no longer silently survives as cleartext: it is
// reported as an unterminated marker and the write paths refuse the file.
func TestEvidenceRowBareMultiLineMarkerIsADefect(t *testing.T) {
	pub, _, _ := crypto.GenerateKeypair()
	content := []byte("key: ENC[-----BEGIN KEY-----\nMIIEv\n-----END KEY-----]\n")

	markers, defects := Scan(content)
	if len(markers) != 0 {
		t.Errorf("a bare multi-line body must not parse as a marker; got %+v", markers)
	}
	if len(defects) != 1 || defects[0].Kind != Unterminated {
		t.Fatalf("want exactly one Unterminated defect, got %+v", defects)
	}

	if _, got, _ := EncryptContentWithDefects(content, NaclEncryptor{PublicKey: pub}); len(got) != 1 {
		t.Errorf("encrypt must surface the defect, got %+v", got)
	}
}

// --- decrypt-failure semantics (docs/plans/07) ---
//
// A marker that fails to decrypt is an error, never a value. Every case below
// runs through CompositeDecryptor{NaclDecryptor, EnvelopeDecryptor}, the
// composition cmd/keys.go builds for a project holding both key types, because
// that is where a hard error can be mistaken for "not my version" and skipped.

// decryptFailureFixture is a mixed-key project: one NaCl keypair, one RSA
// envelope key, and the composite decryptor over both.
type decryptFailureFixture struct {
	naclEnc   NaclEncryptor
	envEnc    *EnvelopeEncryptor
	composite CompositeDecryptor
	wrapped   int // size of a wrapped data key, in bytes
}

func newDecryptFailureFixture(t *testing.T) decryptFailureFixture {
	t.Helper()
	naclPub, naclPriv, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	rsaPriv, envEnc, envDec := newTestEnvelopeKeys(t)
	return decryptFailureFixture{
		naclEnc: NaclEncryptor{PublicKey: naclPub},
		envEnc:  envEnc,
		composite: CompositeDecryptor{Decryptors: []Decryptor{
			NaclDecryptor{PrivateKey: naclPriv}, envDec,
		}},
		wrapped: rsaPriv.Size(),
	}
}

// flipInnerByte returns inner ("vN:" + base64) with one bit flipped at offset
// in the decoded blob. A negative offset counts back from the end.
func flipInnerByte(t *testing.T, inner string, offset int) string {
	t.Helper()
	blob, err := base64.StdEncoding.DecodeString(inner[3:])
	if err != nil {
		t.Fatalf("flipInnerByte: %v", err)
	}
	if offset < 0 {
		offset += len(blob)
	}
	blob[offset] ^= 0x01
	return inner[:3] + base64.StdEncoding.EncodeToString(blob)
}

// zeroInner is a version prefix followed by valid base64 of n zero bytes.
func zeroInner(prefix string, n int) string {
	return prefix + base64.StdEncoding.EncodeToString(make([]byte, n))
}

// assertDecryptFails checks the three things that make a failed decrypt safe:
// DecryptMarker returns a hard error (not ErrSkip, which callers read as "leave
// it alone and carry on"), DecryptContent returns an error too, and the content
// it hands back still holds the failed marker byte-for-byte rather than an
// empty value where the secret should be.
func assertDecryptFails(t *testing.T, dec Decryptor, badInner, plaintext string) {
	t.Helper()
	ctx := context.Background()

	pt, err := dec.DecryptMarker(ctx, badInner)
	if err == nil {
		t.Fatalf("DecryptMarker succeeded with %q; want an error", pt)
	}
	if errors.Is(err, ErrSkip) {
		t.Errorf("DecryptMarker returned ErrSkip; a failed decrypt must be a hard error")
	}
	if pt != nil {
		t.Errorf("DecryptMarker returned data alongside its error: %q", pt)
	}
	if strings.Contains(err.Error(), plaintext) {
		t.Errorf("the error carries the plaintext: %v", err)
	}

	for _, keepMarkers := range []bool{false, true} {
		content := []byte("BEFORE=1\nBAD=ENC[" + badInner + "]\nAFTER=2\n")
		out, err := DecryptContent(ctx, content, dec, keepMarkers)
		if err == nil {
			t.Errorf("DecryptContent(keepMarkers=%v) reported success", keepMarkers)
		}
		if !bytes.Equal(out, content) {
			t.Errorf("DecryptContent(keepMarkers=%v) rewrote a marker it could not decrypt.\ngot:  %q\nwant: %q",
				keepMarkers, out, content)
		}
	}
}

func TestV1DecryptFailuresAreHardErrors(t *testing.T) {
	const plaintext = "v1-plaintext-must-not-leak"
	fx := newDecryptFailureFixture(t)

	good, err := fx.naclEnc.EncryptValue([]byte(plaintext))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	otherPub, _, _ := crypto.GenerateKeypair()
	foreign, err := NaclEncryptor{PublicKey: otherPub}.EncryptValue([]byte(plaintext))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}

	// Sanity: the untampered marker opens, so every failure below is down to
	// the one thing that case changed.
	if pt, err := fx.composite.DecryptMarker(context.Background(), good); err != nil || string(pt) != plaintext {
		t.Fatalf("baseline decrypt = %q, %v", pt, err)
	}

	cases := map[string]string{
		"wrong_key":               foreign,
		"payload_byte_flipped":    flipInnerByte(t, good, -1),
		"nonce_byte_flipped":      flipInnerByte(t, good, 32),
		"ephemeral_key_flipped":   flipInnerByte(t, good, 0),
		"truncated_three_bytes":   "v1:AAAA",
		"truncated_inside_header": zeroInner("v1:", 40),
		"truncated_one_short":     zeroInner("v1:", 71),
		"truncated_real_marker":   good[:3+48],
		"invalid_base64":          "v1:not-base64-at-all",
		"empty_payload":           "v1:",
		"doubled_version_prefix":  "v1:" + good,
	}
	for name, inner := range cases {
		t.Run(name, func(t *testing.T) {
			assertDecryptFails(t, fx.composite, inner, plaintext)
		})
	}
}

func TestV2DecryptFailuresAreHardErrors(t *testing.T) {
	const plaintext = "v2-plaintext-must-not-leak"
	fx := newDecryptFailureFixture(t)

	good, err := fx.envEnc.EncryptValue([]byte(plaintext))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	// Sealed to a different RSA key: the unwrap itself fails.
	_, otherEnc, _ := newTestEnvelopeKeys(t)
	foreign, err := otherEnc.EncryptValue([]byte(plaintext))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}

	if pt, err := fx.composite.DecryptMarker(context.Background(), good); err != nil || string(pt) != plaintext {
		t.Fatalf("baseline decrypt = %q, %v", pt, err)
	}

	cases := map[string]string{
		"wrong_key": foreign,
		// Past the wrapped key and the nonce: the unwrap succeeds, so only
		// the secretbox tag stands between a corrupt payload and the caller.
		"payload_first_byte_flipped": flipInnerByte(t, good, fx.wrapped+24),
		"payload_last_byte_flipped":  flipInnerByte(t, good, -1),
		"nonce_byte_flipped":         flipInnerByte(t, good, fx.wrapped),
		"wrapped_key_byte_flipped":   flipInnerByte(t, good, 0),
		"truncated_forty_bytes":      zeroInner("v2:", 40),
		"truncated_one_short":        zeroInner("v2:", fx.wrapped+24+16-1),
		"truncated_real_marker":      good[:3+64],
		"invalid_base64":             "v2:!!!not-base64",
		"empty_payload":              "v2:",
	}
	for name, inner := range cases {
		t.Run(name, func(t *testing.T) {
			assertDecryptFails(t, fx.composite, inner, plaintext)
		})
	}
}

// The composite may only fall through on ErrSkip. If it fell through on any
// error, a wrong key in a project with both key types would be downgraded to a
// skip: `decrypt` and `run` would hand the ciphertext downstream as the value
// and exit 0.
func TestCompositeReturnsHardErrorsInsteadOfSkipping(t *testing.T) {
	fx := newDecryptFailureFixture(t)
	ctx := context.Background()

	otherPub, _, _ := crypto.GenerateKeypair()
	foreign, err := NaclEncryptor{PublicKey: otherPub}.EncryptValue([]byte("sealed to someone else"))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}

	pt, err := fx.composite.DecryptMarker(ctx, foreign)
	if err == nil {
		t.Fatalf("a marker sealed to a different key decrypted to %q", pt)
	}
	if errors.Is(err, ErrSkip) {
		t.Fatalf("wrong key was reported as ErrSkip")
	}

	// The member that owns the version decides; a later member is never asked.
	// Order must not matter, and an unknown version is still a skip.
	reversed := CompositeDecryptor{Decryptors: []Decryptor{fx.composite.Decryptors[1], fx.composite.Decryptors[0]}}
	if _, err := reversed.DecryptMarker(ctx, foreign); err == nil || errors.Is(err, ErrSkip) {
		t.Errorf("reversed composite: err = %v, want a hard error", err)
	}
	if _, err := fx.composite.DecryptMarker(ctx, "v9:AAAA"); !errors.Is(err, ErrSkip) {
		t.Errorf("unknown version: err = %v, want ErrSkip", err)
	}
	stop := &recordingDecryptor{err: errors.New("hard failure")}
	after := &recordingDecryptor{}
	if _, err := (CompositeDecryptor{Decryptors: []Decryptor{stop, after}}).DecryptMarker(ctx, "v1:AAAA"); !errors.Is(err, stop.err) {
		t.Errorf("err = %v, want the first member's error", err)
	}
	if after.calls != 0 {
		t.Errorf("a decryptor after the one that failed was consulted %d times", after.calls)
	}
}

// recordingDecryptor returns a fixed result and counts how often it is asked.
type recordingDecryptor struct {
	err   error
	calls int
}

func (r *recordingDecryptor) DecryptMarker(context.Context, string) ([]byte, error) {
	r.calls++
	return nil, r.err
}

// A failed marker must not stop the healthy ones around it from decrypting,
// and must itself survive verbatim: the error, not the output, is what tells
// the caller the file is unusable.
func TestDecryptContentKeepsFailedMarkerAmongGoodOnes(t *testing.T) {
	fx := newDecryptFailureFixture(t)

	goodV1, _ := fx.naclEnc.EncryptValue([]byte("one"))
	goodV2, _ := fx.envEnc.EncryptValue([]byte("two"))
	badV1 := flipInnerByte(t, goodV1, -1)
	badV2 := flipInnerByte(t, goodV2, -1)

	content := []byte("A=ENC[" + goodV1 + "]\nB=ENC[" + badV1 + "]\nC=ENC[" + goodV2 + "]\nD=ENC[" + badV2 + "]\nE=plain\n")
	want := "A=one\nB=ENC[" + badV1 + "]\nC=two\nD=ENC[" + badV2 + "]\nE=plain\n"

	out, err := DecryptContent(context.Background(), content, fx.composite, false)
	if err == nil {
		t.Fatalf("DecryptContent reported success with two corrupt markers")
	}
	if string(out) != want {
		t.Errorf("output mismatch.\ngot:  %q\nwant: %q", out, want)
	}
}

// Decrypt errors are printed, logged and pasted into bug reports. They must
// describe the failure without quoting what was (or would have been) decrypted.
func TestDecryptErrorsExcludePlaintext(t *testing.T) {
	const plaintext = "hunter2-do-not-print"
	ctx := context.Background()

	pub, _, _ := crypto.GenerateKeypair()
	_, wrongPriv, _ := crypto.GenerateKeypair()
	v1Inner, _ := NaclEncryptor{PublicKey: pub}.EncryptValue([]byte(plaintext))

	_, envEnc, _ := newTestEnvelopeKeys(t)
	wrongRSA, _, wrongEnvDec := newTestEnvelopeKeys(t)
	v2Inner, _ := envEnc.EncryptValue([]byte(plaintext))

	wrong := CompositeDecryptor{Decryptors: []Decryptor{NaclDecryptor{PrivateKey: wrongPriv}, wrongEnvDec}}
	// An unwrapper that "succeeds" with the wrong data key, which is what a
	// misrouted KMS key looks like: the failure moves to the secretbox open.
	wrongDK := CompositeDecryptor{Decryptors: []Decryptor{
		NewEnvelopeDecryptor(fixedUnwrapper{dk: make([]byte, 32)}, wrongRSA.Size()),
	}}

	cases := map[string]struct {
		dec   Decryptor
		inner string
	}{
		"v1_wrong_key":       {wrong, v1Inner},
		"v2_wrong_unwrapper": {wrong, v2Inner},
		"v2_wrong_data_key":  {wrongDK, v2Inner},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			content := []byte("SECRET=ENC[" + tc.inner + "]\n")
			out, err := DecryptContent(ctx, content, tc.dec, false)
			if err == nil {
				t.Fatalf("expected an error; got output %q", out)
			}
			if strings.Contains(err.Error(), plaintext) {
				t.Errorf("error text contains the plaintext: %v", err)
			}
			if bytes.Contains(out, []byte(plaintext)) {
				t.Errorf("output contains the plaintext: %q", out)
			}
			if !bytes.Equal(out, content) {
				t.Errorf("the failed marker was rewritten: %q", out)
			}
		})
	}
}

// fixedUnwrapper hands back the same data key whatever it is given.
type fixedUnwrapper struct{ dk []byte }

func (f fixedUnwrapper) Unwrap(context.Context, []byte) ([]byte, error) { return f.dk, nil }

// --- encrypt-side failure (docs/plans/07) ---

// failingEncryptor encrypts like NaclEncryptor except for the values listed in
// fail, for which it returns err — a KMS Wrap error, say.
type failingEncryptor struct {
	NaclEncryptor
	fail map[string]bool
	err  error
}

func (f failingEncryptor) EncryptValue(plaintext []byte) (string, error) {
	if f.fail[string(plaintext)] {
		return "", f.err
	}
	return f.NaclEncryptor.EncryptValue(plaintext)
}

// A failed encrypt leaves that marker in the clear. EncryptContent has to
// return the error, wherever in the file the failure happened, because the
// error is the only thing that stops `encrypt` and `edit` writing the result.
func TestEncryptContentReturnsEncryptorError(t *testing.T) {
	pub, _, _ := crypto.GenerateKeypair()
	wrapErr := errors.New("kms: wrap failed")
	content := []byte("A=ENC[first]\nB=ENC[second]\nC=ENC[third]\n")

	for _, failing := range [][]string{
		{"first"}, {"second"}, {"third"}, {"first", "third"}, {"first", "second", "third"},
	} {
		t.Run(strings.Join(failing, "+"), func(t *testing.T) {
			enc := failingEncryptor{NaclEncryptor: NaclEncryptor{PublicKey: pub}, fail: map[string]bool{}, err: wrapErr}
			for _, v := range failing {
				enc.fail[v] = true
			}

			out, err := EncryptContent(content, enc)
			if !errors.Is(err, wrapErr) {
				t.Fatalf("err = %v, want the encryptor's error", err)
			}
			if _, _, err := EncryptContentWithDefects(content, enc); !errors.Is(err, wrapErr) {
				t.Errorf("EncryptContentWithDefects: err = %v, want the encryptor's error", err)
			}

			// What comes back with the error is not a finished file: each
			// failed marker is still there, verbatim and in the clear, never
			// dropped or emptied. That is exactly why the error must not be
			// lost.
			markers, defects := Scan(out)
			if len(defects) != 0 || len(markers) != 3 {
				t.Fatalf("output no longer holds three markers: %+v %+v\n%s", markers, defects, out)
			}
			for i, value := range []string{"first", "second", "third"} {
				if enc.fail[value] {
					if markers[i].Encrypted || markers[i].Value != value {
						t.Errorf("failed marker %q came back as %+v", value, markers[i])
					}
				} else if !markers[i].Encrypted {
					t.Errorf("marker %q should have been encrypted; got %+v", value, markers[i])
				}
			}
			if !bytes.HasPrefix(out, []byte("A=ENC[")) || bytes.Count(out, []byte("\n")) != 3 {
				t.Errorf("surrounding content was disturbed: %s", out)
			}
		})
	}
}
