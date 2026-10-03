package processor

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rubysolo/envisible/pkg/crypto"
)

// --- wire-format exemplars ---
//
// testdata/exemplars.env holds one v1 marker written by envisible v0.0.1 and
// one v2 marker written by v0.0.5: the first release to write each format.
// Every other test in the repo encrypts and decrypts with the same build, so a
// change that moves both sides together round-trips perfectly while stranding
// every file ever committed. These are the only bytes today's encoder did not
// produce.
//
// A failing exemplar test means the wire format changed; fix the code, never
// the exemplar. See testdata/README.md.

// The plaintexts the old releases were given. Each carries a NUL, multi-byte
// UTF-8, both brackets and a newline, so decrypting with markers kept also
// exercises today's output escaping.
const (
	exemplarV1Plaintext = "v1 exemplar: nul=\x00 utf8=héllo-日本語 bracket=a]b[c\nsecond line"
	exemplarV2Plaintext = "v2 exemplar: nul=\x00 utf8=héllo-日本語 bracket=a]b[c\nsecond line"
)

func readExemplarFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read exemplar file: %v", err)
	}
	return data
}

// exemplarKeys loads the two fixed, test-only private keys.
func exemplarKeys(t *testing.T) ([32]byte, *rsa.PrivateKey) {
	t.Helper()
	naclPriv, err := crypto.DecodeKey(strings.TrimSpace(string(readExemplarFile(t, "exemplar_v1.key"))))
	if err != nil {
		t.Fatalf("decode exemplar_v1.key: %v", err)
	}
	block, _ := pem.Decode(readExemplarFile(t, "exemplar_v2_rsa.pem"))
	if block == nil {
		t.Fatal("exemplar_v2_rsa.pem holds no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse exemplar_v2_rsa.pem: %v", err)
	}
	rsaPriv, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("exemplar_v2_rsa.pem holds a %T, want an RSA key", key)
	}
	return naclPriv, rsaPriv
}

// exemplarDecryptor is the composition cmd/keys.go builds for a mixed v1/v2
// file — NaCl first, then the envelope — with the fixed RSA key standing in
// for the KMS.
func exemplarDecryptor(t *testing.T) CompositeDecryptor {
	t.Helper()
	naclPriv, rsaPriv := exemplarKeys(t)
	return CompositeDecryptor{Decryptors: []Decryptor{
		NaclDecryptor{PrivateKey: naclPriv},
		NewEnvelopeDecryptor(&localRSAUnwrapper{priv: rsaPriv}, rsaPriv.Size()),
	}}
}

// exemplarLine returns the byte offset and text of the line assigning name.
func exemplarLine(t *testing.T, content []byte, name string) (int, string) {
	t.Helper()
	offset := 0
	for _, line := range strings.SplitAfter(string(content), "\n") {
		if strings.HasPrefix(line, name+"=") {
			return offset, strings.TrimSuffix(line, "\n")
		}
		offset += len(line)
	}
	t.Fatalf("exemplars.env has no %s line", name)
	return 0, ""
}

func TestExemplarsDecrypt(t *testing.T) {
	content := readExemplarFile(t, "exemplars.env")
	dec := exemplarDecryptor(t)
	_, rsaPriv := exemplarKeys(t)
	ctx := context.Background()

	exemplars := []struct {
		name      string
		prefix    string
		plaintext string
		// header is what precedes the sealed payload in the decoded blob:
		// ephemeral pubkey + nonce for v1, wrapped data key + nonce for v2.
		header int
	}{
		{"EXEMPLAR_V1", "v1:", exemplarV1Plaintext, 32 + 24},
		{"EXEMPLAR_V2", "v2:", exemplarV2Plaintext, rsaPriv.Size() + 24},
	}

	// The marker grammar is pinned with the cryptography: the scanner must
	// find exactly these two markers, each running from its "ENC[" to the end
	// of its line.
	markers, defects := Scan(content)
	if len(defects) != 0 {
		t.Fatalf("defects in exemplars.env: %+v", defects)
	}
	if len(markers) != len(exemplars) {
		t.Fatalf("got %d markers, want %d: %+v", len(markers), len(exemplars), markers)
	}

	for i, ex := range exemplars {
		t.Run(ex.name, func(t *testing.T) {
			lineStart, line := exemplarLine(t, content, ex.name)
			m := markers[i]

			wantStart := lineStart + len(ex.name) + 1
			wantEnd := lineStart + len(line)
			if m.Start != wantStart || m.End != wantEnd {
				t.Errorf("marker span = [%d:%d), want [%d:%d)", m.Start, m.End, wantStart, wantEnd)
			}
			if !m.Encrypted {
				t.Errorf("marker was not recognized as ciphertext")
			}
			if want := line[len(ex.name)+1+len(markerPrefix) : len(line)-len(markerSuffix)]; m.Raw != want {
				t.Errorf("marker Raw differs from the bytes between the brackets")
			}
			if !strings.HasPrefix(m.Raw, ex.prefix) {
				t.Fatalf("marker Raw starts %q, want prefix %q", m.Raw[:3], ex.prefix)
			}

			// The layout, independent of any key: header, then the sealed
			// payload, which is the plaintext plus a 16-byte tag.
			blob, err := base64.StdEncoding.DecodeString(m.Raw[len(ex.prefix):])
			if err != nil {
				t.Fatalf("exemplar payload is not standard base64: %v", err)
			}
			if want := ex.header + len(ex.plaintext) + 16; len(blob) != want {
				t.Errorf("decoded blob is %d bytes, want %d", len(blob), want)
			}
			if err := StructureCheck(m.Raw, rsaPriv.Size()); err != nil {
				t.Errorf("StructureCheck: %v", err)
			}

			got, err := dec.DecryptMarker(ctx, m.Raw)
			if err != nil {
				t.Fatalf("DecryptMarker: %v", err)
			}
			if string(got) != ex.plaintext {
				t.Errorf("plaintext = %q, want %q", got, ex.plaintext)
			}
		})
	}
}

// TestExemplarsDecryptContent takes the same bytes through DecryptContent, the
// way `decrypt` and `edit` do, and pins the whole output in both modes.
func TestExemplarsDecryptContent(t *testing.T) {
	content := readExemplarFile(t, "exemplars.env")
	dec := exemplarDecryptor(t)
	ctx := context.Background()

	_, v1Line := exemplarLine(t, content, "EXEMPLAR_V1")
	_, v2Line := exemplarLine(t, content, "EXEMPLAR_V2")

	// want rebuilds the file with each exemplar line swapped for its expected
	// decrypted form, leaving the comments around them byte-for-byte.
	want := func(v1, v2 string) string {
		out := strings.Replace(string(content), v1Line, "EXEMPLAR_V1="+v1, 1)
		return strings.Replace(out, v2Line, "EXEMPLAR_V2="+v2, 1)
	}

	stripped, err := DecryptContent(ctx, content, dec, false)
	if err != nil {
		t.Fatalf("DecryptContent(strip): %v", err)
	}
	if w := want(exemplarV1Plaintext, exemplarV2Plaintext); string(stripped) != w {
		t.Errorf("stripped output mismatch.\ngot:  %q\nwant: %q", stripped, w)
	}

	// With markers kept, the brackets and the newline come back escaped.
	const escapedTail = " exemplar: nul=\x00 utf8=héllo-日本語 bracket=a\\]b\\[c\\\nsecond line"
	kept, err := DecryptContent(ctx, content, dec, true)
	if err != nil {
		t.Fatalf("DecryptContent(keepMarkers): %v", err)
	}
	if w := want("ENC[v1"+escapedTail+"]", "ENC[v2"+escapedTail+"]"); string(kept) != w {
		t.Errorf("kept-markers output mismatch.\ngot:  %q\nwant: %q", kept, w)
	}

	// And that editable form scans back to the same two values, so an `edit`
	// of a file written by an old release loses nothing.
	markers, defects := Scan(kept)
	if len(defects) != 0 || len(markers) != 2 {
		t.Fatalf("rescan of the editable form: markers %+v defects %+v", markers, defects)
	}
	for i, wantValue := range []string{exemplarV1Plaintext, exemplarV2Plaintext} {
		if markers[i].Encrypted || markers[i].Value != wantValue {
			t.Errorf("marker %d rescanned as %+v, want plaintext %q", i, markers[i], wantValue)
		}
	}
}

// Each key opens only its own exemplar. Guards the fixtures themselves: an
// exemplar that decrypted under the wrong key would prove nothing.
func TestExemplarsNeedTheirOwnKeys(t *testing.T) {
	content := readExemplarFile(t, "exemplars.env")
	naclPriv, rsaPriv := exemplarKeys(t)
	ctx := context.Background()

	if out, err := DecryptContent(ctx, content, NaclDecryptor{PrivateKey: naclPriv}, false); err != nil {
		t.Errorf("NaCl-only decrypt: %v", err)
	} else if !bytes.Contains(out, []byte(exemplarV1Plaintext)) || bytes.Contains(out, []byte(exemplarV2Plaintext)) {
		t.Errorf("the NaCl key alone must open the v1 exemplar and only it; got %q", out)
	}

	envDec := NewEnvelopeDecryptor(&localRSAUnwrapper{priv: rsaPriv}, rsaPriv.Size())
	if out, err := DecryptContent(ctx, content, envDec, false); err != nil {
		t.Errorf("envelope-only decrypt: %v", err)
	} else if !bytes.Contains(out, []byte(exemplarV2Plaintext)) || bytes.Contains(out, []byte(exemplarV1Plaintext)) {
		t.Errorf("the RSA key alone must open the v2 exemplar and only it; got %q", out)
	}
}
