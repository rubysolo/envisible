package processor

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

// boundaryWrapSize is deliberately tiny. Real RSA wrappers emit 256+ bytes,
// which hides capacity arithmetic that only goes wrong when the wrapped key is
// the shorter operand.
const boundaryWrapSize = 4

// boundaryWrapper is a kms.Wrapper that emits a fixed, tiny "wrapped key" and
// remembers the data key it was handed, so a test can decrypt without RSA.
type boundaryWrapper struct {
	wrapped []byte
	dk      []byte
}

func (w *boundaryWrapper) Wrap(dk []byte) ([]byte, error) {
	w.dk = append([]byte(nil), dk...)
	return w.wrapped, nil
}

func (w *boundaryWrapper) WrappedSize() int { return len(w.wrapped) }

// boundaryUnwrapper returns a fixed data key and counts how often it is asked.
type boundaryUnwrapper struct {
	dk    []byte
	calls int
}

func (u *boundaryUnwrapper) Unwrap(context.Context, []byte) ([]byte, error) {
	u.calls++
	return u.dk, nil
}

// boundaryV2Blob builds wrapped || nonce || secretbox(plaintext) by hand.
func boundaryV2Blob(wrapped []byte, dk *[32]byte, plaintext []byte) []byte {
	var nonce [24]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	blob := append([]byte(nil), wrapped...)
	blob = append(blob, nonce[:]...)
	return secretbox.Seal(blob, plaintext, &nonce, dk)
}

func boundaryInner(blob []byte) string {
	return "v2:" + base64.StdEncoding.EncodeToString(blob)
}

// --- processor.go: v2 envelope ---

// processor.go:136 — the blob capacity is wrapped+nonce+ct. With a wrapped key
// shorter than the nonce, any sign slip makes the capacity negative and panics.
func TestEnvelopeEncryptEmptyPlaintextWithShortWrappedKey(t *testing.T) {
	w := &boundaryWrapper{wrapped: []byte("WRAP")}
	inner, err := NewEnvelopeEncryptor(w).EncryptValue(nil)
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	if !strings.HasPrefix(inner, "v2:") {
		t.Fatalf("inner = %q, want a v2: prefix", inner)
	}
	blob, err := base64.StdEncoding.DecodeString(inner[3:])
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if want := boundaryWrapSize + 24 + secretbox.Overhead; len(blob) != want {
		t.Fatalf("blob is %d bytes, want exactly %d (wrapped + nonce + tag)", len(blob), want)
	}
	if !bytes.Equal(blob[:boundaryWrapSize], []byte("WRAP")) {
		t.Errorf("blob does not start with the wrapped key: %q", blob[:boundaryWrapSize])
	}

	dec := NewEnvelopeDecryptor(fixedUnwrapper{dk: w.dk}, boundaryWrapSize)
	got, err := dec.DecryptMarker(context.Background(), inner)
	if err != nil {
		t.Fatalf("DecryptMarker: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("round trip = %q, want empty plaintext", got)
	}
}

// processor.go:173-174 — an encrypted empty string is exactly minLen bytes and
// must decrypt; one byte less must be refused by the length check, naming both
// lengths, before the blob is sliced or the KMS is called.
func TestEnvelopeDecryptLengthBoundary(t *testing.T) {
	var dk [32]byte
	for i := range dk {
		dk[i] = byte(0xA0 + i)
	}
	minLen := boundaryWrapSize + 24 + secretbox.Overhead // 44

	exact := boundaryV2Blob([]byte("WRAP"), &dk, nil)
	if len(exact) != minLen {
		t.Fatalf("setup: empty-plaintext blob is %d bytes, want %d", len(exact), minLen)
	}

	t.Run("exactly minimum decrypts to empty", func(t *testing.T) {
		u := &boundaryUnwrapper{dk: dk[:]}
		dec := NewEnvelopeDecryptor(u, boundaryWrapSize)
		got, err := dec.DecryptMarker(context.Background(), boundaryInner(exact))
		if err != nil {
			t.Fatalf("DecryptMarker of a minimum-length blob: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("DecryptMarker = %q, want empty plaintext", got)
		}
		if u.calls != 1 {
			t.Errorf("unwrapper called %d times, want 1", u.calls)
		}
	})

	// Every length below the minimum, down to "not even a whole wrapped key",
	// gets the same error with the exact numbers and never reaches the KMS.
	for _, n := range []int{minLen - 1, boundaryWrapSize + 24, boundaryWrapSize + 24 - 1, boundaryWrapSize + 8, boundaryWrapSize, 0} {
		u := &boundaryUnwrapper{dk: dk[:]}
		dec := NewEnvelopeDecryptor(u, boundaryWrapSize)
		_, err := dec.DecryptMarker(context.Background(), boundaryInner(exact[:n]))
		if err == nil {
			t.Fatalf("len %d: DecryptMarker succeeded, want a too-short error", n)
		}
		want := fmt.Sprintf("envelope: ciphertext too short (%d < %d)", n, minLen)
		if err.Error() != want {
			t.Errorf("len %d: error = %q, want %q", n, err, want)
		}
		if u.calls != 0 {
			t.Errorf("len %d: unwrapper called %d times for a too-short blob, want 0", n, u.calls)
		}
	}
}

// The same boundary with a real-sized (RSA-2048) wrapped key, through the real
// encryptor: 256 + 24 + 16 = 296 decrypts, 295 does not.
func TestEnvelopeDecryptLengthBoundaryRSA(t *testing.T) {
	priv, enc, dec := newTestEnvelopeKeys(t)
	inner, err := enc.EncryptValue(nil)
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	blob, err := base64.StdEncoding.DecodeString(inner[3:])
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	minLen := priv.Size() + 24 + secretbox.Overhead
	if len(blob) != minLen || minLen != 296 {
		t.Fatalf("encrypted empty string is %d bytes, want %d (= 296)", len(blob), minLen)
	}
	got, err := dec.DecryptMarker(context.Background(), inner)
	if err != nil {
		t.Fatalf("DecryptMarker of an encrypted empty string: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("DecryptMarker = %q, want empty plaintext", got)
	}

	_, err = dec.DecryptMarker(context.Background(), boundaryInner(blob[:minLen-1]))
	if err == nil || err.Error() != "envelope: ciphertext too short (295 < 296)" {
		t.Errorf("one byte short: error = %v, want %q", err, "envelope: ciphertext too short (295 < 296)")
	}
}

// --- rewrap.go ---

// rewrap.go:65 — "v2:" with nothing after it is still a v2 marker. It is a
// hard too-short error, not a skip: skipping would let `kms rotate` report
// success over a marker that the new key can never decrypt.
func TestRewrapV2InnerBarePrefixIsAnErrorNotASkip(t *testing.T) {
	w := &boundaryWrapper{wrapped: []byte("NEWW")}
	got, err := rewrapV2Inner(context.Background(), "v2:", fixedUnwrapper{dk: make([]byte, 32)}, boundaryWrapSize, w)
	if errors.Is(err, ErrSkip) {
		t.Fatalf("bare v2: prefix was skipped, want a too-short error")
	}
	if want := "rewrap: ciphertext too short (0 < 44)"; err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if got != "" {
		t.Errorf("inner = %q, want empty on error", got)
	}

	// Anything shorter than the prefix, or a different version, is a skip.
	for _, inner := range []string{"", "v", "v2", "v1:", "v3:AAAA"} {
		if _, err := rewrapV2Inner(context.Background(), inner, fixedUnwrapper{}, boundaryWrapSize, w); !errors.Is(err, ErrSkip) {
			t.Errorf("inner %q: err = %v, want ErrSkip", inner, err)
		}
	}
}

// rewrap.go:72 — rewrap enforces the same minimum as decrypt: wrapped key +
// 24-byte nonce + 16-byte secretbox overhead. It used to require only "longer
// than the wrapped key", so a blob truncated anywhere inside the nonce or the
// payload was re-wrapped and counted as rotated although nothing could ever
// decrypt it. Every too-short length is refused before the KMS is called; the
// minimum itself (an encrypted empty string) is accepted.
func TestRewrapV2InnerRejectsBlobShorterThanDecryptAccepts(t *testing.T) {
	var dk [32]byte
	full := boundaryV2Blob([]byte("OLDW"), &dk, nil)
	minLen := boundaryWrapSize + 24 + secretbox.Overhead
	if len(full) != minLen {
		t.Fatalf("fixture: an encrypted empty string is %d bytes, want the minimum %d", len(full), minLen)
	}

	for _, n := range []int{0, 1, boundaryWrapSize - 1, boundaryWrapSize, boundaryWrapSize + 1, boundaryWrapSize + 24, minLen - 1} {
		u := &boundaryUnwrapper{dk: dk[:]}
		w := &boundaryWrapper{wrapped: []byte("NEWW")}
		got, err := rewrapV2Inner(context.Background(), boundaryInner(full[:n]), u, boundaryWrapSize, w)
		want := fmt.Sprintf("rewrap: ciphertext too short (%d < %d)", n, minLen)
		if err == nil || err.Error() != want {
			t.Errorf("len %d: inner = %q, error = %v, want %q", n, got, err, want)
		}
		if u.calls != 0 {
			t.Errorf("len %d: unwrapper called %d times, want 0", n, u.calls)
		}
		if w.dk != nil {
			t.Errorf("len %d: wrapper was called for a rejected blob", n)
		}

		// rewrap and decrypt agree on what is too short.
		dec := NewEnvelopeDecryptor(&boundaryUnwrapper{dk: dk[:]}, boundaryWrapSize)
		if _, derr := dec.DecryptMarker(context.Background(), boundaryInner(full[:n])); derr == nil {
			t.Errorf("len %d: decrypt accepted a blob rewrap rejects", n)
		}
	}

	u := &boundaryUnwrapper{dk: dk[:]}
	if _, err := rewrapV2Inner(context.Background(), boundaryInner(full), u, boundaryWrapSize, &boundaryWrapper{wrapped: []byte("NEWW")}); err != nil {
		t.Errorf("a blob of exactly the minimum length was rejected: %v", err)
	}
}

// The same defect end to end: a file with one good marker and one truncated
// marker must abort the whole rotation, as RewrapContent documents, instead of
// reporting both as rotated.
func TestRewrapContentAbortsOnATruncatedMarker(t *testing.T) {
	var dk [32]byte
	good := boundaryV2Blob([]byte("OLDW"), &dk, []byte("hunter2"))
	content := []byte("A=ENC[" + boundaryInner(good) + "]\nB=ENC[" + boundaryInner(good[:len(good)-10]) + "]\n")
	if len(good)-10 <= boundaryWrapSize || len(good)-10 >= len(good) {
		t.Fatal("fixture: the truncated blob must keep its wrapped key and lose payload")
	}
	// Truncating 10 bytes from a 7-byte secret's blob leaves it under the minimum.
	if len(good)-10 >= boundaryWrapSize+24+secretbox.Overhead {
		t.Fatal("fixture: the truncated blob is not under the minimum")
	}

	out, rotated, err := RewrapContent(context.Background(), content, &boundaryUnwrapper{dk: dk[:]}, boundaryWrapSize, &boundaryWrapper{wrapped: []byte("NEWW")})
	if err == nil || !strings.Contains(err.Error(), "ciphertext too short") {
		t.Fatalf("RewrapContent: rotated=%d err=%v, want a too-short error", rotated, err)
	}
	if out != nil {
		t.Errorf("RewrapContent returned content alongside the error: %q", out)
	}
}

// rewrap.go:87 — the output is newWrapped || tail. The smallest valid v2 blob
// (an encrypted empty string) rewraps to exactly that, byte for byte, and
// still decrypts. With a new wrapped key shorter than the tail, a sign slip in
// the capacity hint panics.
func TestRewrapMinimumLengthBlobKeepsPayloadBitForBit(t *testing.T) {
	var dk [32]byte
	for i := range dk {
		dk[i] = byte(i)
	}
	blob := boundaryV2Blob([]byte("OLDW"), &dk, nil)
	tail := blob[boundaryWrapSize:]
	if len(tail) != 24+secretbox.Overhead {
		t.Fatalf("setup: tail is %d bytes, want %d", len(tail), 24+secretbox.Overhead)
	}

	w := &boundaryWrapper{wrapped: []byte("NEWW")}
	content := []byte("A=ENC[" + boundaryInner(blob) + "]\n")
	out, rotated, err := RewrapContent(context.Background(), content, fixedUnwrapper{dk: dk[:]}, boundaryWrapSize, w)
	if err != nil {
		t.Fatalf("RewrapContent: %v", err)
	}
	if rotated != 1 {
		t.Errorf("rotated = %d, want 1", rotated)
	}
	want := "A=ENC[" + boundaryInner(append([]byte("NEWW"), tail...)) + "]\n"
	if string(out) != want {
		t.Errorf("rewrapped content:\n got: %q\nwant: %q", out, want)
	}
	if !bytes.Equal(w.dk, dk[:]) {
		t.Errorf("new wrapper was handed %x, want the unwrapped data key %x", w.dk, dk)
	}

	dec := NewEnvelopeDecryptor(fixedUnwrapper{dk: dk[:]}, boundaryWrapSize)
	plain, err := DecryptContent(context.Background(), out, dec, false)
	if err != nil {
		t.Fatalf("DecryptContent of rewrapped output: %v", err)
	}
	if string(plain) != "A=\n" {
		t.Errorf("decrypted rewrapped output = %q, want %q", plain, "A=\n")
	}
}

// The realistic shape of the same hazard: an RSA-2048 wrapped key is 256
// bytes, so any secret over 216 bytes has a tail longer than the wrapped key.
func TestRewrapPayloadLongerThanWrappedKey(t *testing.T) {
	oldPriv, enc, _ := newTestEnvelopeKeys(t)
	newPriv, _, newDec := newTestEnvelopeKeys(t)

	secret := strings.Repeat("k", 217)
	inner, err := enc.EncryptValue([]byte(secret))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	content := []byte("PEM=ENC[" + inner + "]\n")

	out, rotated, err := RewrapContent(context.Background(), content, &localRSAUnwrapper{priv: oldPriv}, oldPriv.Size(), newRSAWrapperForTest(&newPriv.PublicKey))
	if err != nil {
		t.Fatalf("RewrapContent: %v", err)
	}
	if rotated != 1 {
		t.Errorf("rotated = %d, want 1", rotated)
	}
	plain, err := DecryptContent(context.Background(), out, newDec, false)
	if err != nil {
		t.Fatalf("DecryptContent with the new key: %v", err)
	}
	if want := "PEM=" + secret + "\n"; string(plain) != want {
		t.Errorf("decrypted = %q, want %q", plain, want)
	}
}

// --- dotenv.go ---

// dotenv.go:189 — appendAssignment's Grow hint is content+key+value+2. On an
// empty file with an empty value the other terms are all that keep it from
// going negative, and bytes.Buffer.Grow panics on a negative count.
func TestUpsertAppendToEmptyContentWithEmptyValue(t *testing.T) {
	cases := []struct {
		content, key, value, want string
	}{
		{"", "A", "", "A=\n"},                         // 0+1+0+2: `- 2` gives -1
		{"", "LONG_KEY_NAME", "", "LONG_KEY_NAME=\n"}, // `- len(key)` gives -11
		{"X", "LONG_KEY_NAME", "", "X\nLONG_KEY_NAME=\n"},
		{"", "A", "v", "A=v\n"},
	}
	for _, tc := range cases {
		var content []byte
		if tc.content != "" {
			content = []byte(tc.content)
		}
		got, action := Upsert(content, tc.key, tc.value)
		if string(got) != tc.want {
			t.Errorf("Upsert(%q, %q, %q) = %q, want %q", tc.content, tc.key, tc.value, got, tc.want)
		}
		if action != Added {
			t.Errorf("Upsert(%q, %q, %q) action = %v, want added", tc.content, tc.key, tc.value, action)
		}
	}
}

// dotenv.go:267 — valid JSON is refused before the dotenv scanner ever runs,
// so it reports no defects even when a string in it looks like a broken
// marker. Both the object and the array branch matter separately.
func TestLooksLikeDotenvJSONShortCircuitsBeforeScanning(t *testing.T) {
	for _, content := range []string{
		`{"a":"ENC[oops"}`,
		`["ENC[[oops"]`,
		"  \n{\"a\":\"ENC[oops\"}\n",
		"\n[\"ENC[[oops\"]\n",
	} {
		// Guard the premise: scanned as text, this content does have a defect.
		if _, defects := Scan([]byte(content)); len(defects) != 1 || defects[0].Kind != Unterminated {
			t.Fatalf("setup: Scan(%q) defects = %+v, want one Unterminated", content, defects)
		}
		ok, defects := LooksLikeDotenvWithDefects([]byte(content))
		if ok {
			t.Errorf("LooksLikeDotenvWithDefects(%q) = true, want false", content)
		}
		if len(defects) != 0 {
			t.Errorf("LooksLikeDotenvWithDefects(%q) defects = %+v, want none (JSON is not scanned)", content, defects)
		}
	}

	// Not JSON, so it is scanned: `{`/`[` alone must not short-circuit, and a
	// non-bracket first byte must not either.
	for _, content := range []string{
		"{not json\nA=ENC[oops\n",
		"[section]\nA=ENC[[oops\n",
		"\"ENC[oops\"",
	} {
		_, defects := LooksLikeDotenvWithDefects([]byte(content))
		if len(defects) != 1 || defects[0].Kind != Unterminated {
			t.Errorf("LooksLikeDotenvWithDefects(%q) defects = %+v, want one Unterminated", content, defects)
		}
	}
}

// dotenv.go:274 — the YAML document-start check looks at the FIRST significant
// line, not the last one and not only when the file has a single line.
func TestLooksLikeDotenvChecksTheFirstLineForYAMLStart(t *testing.T) {
	cases := []struct {
		content string
		want    bool
	}{
		{"---\nA=1\n", false},            // yaml start, then something assignment-shaped
		{"---\nA=1\nB=2\n", false},       // still the first line that decides
		{"# c\n\n  ---  \nA=1\n", false}, // first *significant* line
		{"A=1\n---\n", true},             // a later --- is just an unparsable line
		{"A=1\nB=2\n---", true},          // ... including as the last line, no newline
		{"---", false},
		{"A=1", true},
	}
	for _, tc := range cases {
		if got := LooksLikeDotenv([]byte(tc.content)); got != tc.want {
			t.Errorf("LooksLikeDotenv(%q) = %v, want %v", tc.content, got, tc.want)
		}
	}
}

// Pins for the walk mutants judged equivalent (dotenv.go:93, :99, :113, :277):
// these are the inputs most likely to tell them apart, and they do not.
func TestWalkEdgeShapes(t *testing.T) {
	type seen struct {
		text, key, value string
		ok               bool
	}
	cases := []struct {
		name    string
		content string
		want    []seen
	}{
		{"empty", "", nil},
		{"only newline", "\n", nil},
		{"key is last line, no trailing newline", "A=1\nB=2", []seen{{"A=1", "A", "1", true}, {"B=2", "B", "2", true}}},
		{"key is last line, trailing newline", "A=1\nB=2\n", []seen{{"A=1", "A", "1", true}, {"B=2", "B", "2", true}}},
		{"leading equals at offset 0", "=v\nA=1\n", []seen{{"=v", "", "", false}, {"A=1", "A", "1", true}}},
		{"leading equals later", "A=1\n=v", []seen{{"A=1", "A", "1", true}, {"=v", "", "", false}}},
		{"crlf", "A=1\r\nB=2\r\n", []seen{{"A=1", "A", "1", true}, {"B=2", "B", "2", true}}},
		{"crlf with comment", "A=1 # c\r\nB=2\t# c\r\n", []seen{{"A=1", "A", "1", true}, {"B=2", "B", "2", true}}},
		{"crlf, no final newline", "A=1\r\nB=2\r", []seen{{"A=1", "A", "1", true}, {"B=2", "B", "2", true}}},
		{"lone cr line", "\r\nA=1\r\n\r", []seen{{"A=1", "A", "1", true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.content)
			p, _ := newEnvParser(content, nil)
			var got []seen
			p.walk(func(l dotenvLine) bool {
				s := seen{text: l.text(content), key: l.key, ok: l.ok}
				if l.ok {
					s.value = string(content[l.valueStart:l.valueEnd])
				}
				got = append(got, s)
				return true
			})
			if len(got) != len(tc.want) {
				t.Fatalf("walk(%q) visited %+v, want %+v", tc.content, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("walk(%q) line %d = %+v, want %+v", tc.content, i, got[i], tc.want[i])
				}
			}
		})
	}
}
