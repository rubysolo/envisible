package processor

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/kms"
)

var (
	encRegex      = regexp.MustCompile(`ENC\[(.*?)\]`)
	versionPrefix = regexp.MustCompile(`^v\d+:`)
)

// ErrSkip signals that a Decryptor does not handle a particular marker version.
// Callers (including CompositeDecryptor) treat this as "fall through" rather than failure.
var ErrSkip = errors.New("marker version not handled")

// IsEncryptedInner reports whether the contents of an ENC[...] marker carry a
// version prefix (e.g. "v1:..." or "v2:...").
func IsEncryptedInner(inner string) bool {
	return versionPrefix.MatchString(inner)
}

// StructureCheck validates that the inner bytes of an ENC[...] marker are
// shaped correctly without actually decrypting. Catches truncation, base64
// corruption, and obvious format mismatches at zero KMS-call cost — that's
// the default `envisible check` behavior.
//
// For v2 markers, v2WrappedSize should be the registered key's RSA modulus
// size in bytes (256 for RSA-2048). If the caller doesn't know the registered
// key (e.g. envisible.pub is missing), pass 256 as a floor — markers smaller
// than that are definitely truncated regardless of the actual key size.
func StructureCheck(inner string, v2WrappedSize int) error {
	switch {
	case strings.HasPrefix(inner, "v1:"):
		data, err := base64.StdEncoding.DecodeString(inner[3:])
		if err != nil {
			return fmt.Errorf("v1: base64 decode: %w", err)
		}
		// ephemeral pubkey (32) + nonce (24) + box.Overhead (16) = 72 bytes minimum
		min := 32 + 24 + box.Overhead
		if len(data) < min {
			return fmt.Errorf("v1: ciphertext truncated (%d bytes, need at least %d)", len(data), min)
		}
		return nil
	case strings.HasPrefix(inner, "v2:"):
		data, err := base64.StdEncoding.DecodeString(inner[3:])
		if err != nil {
			return fmt.Errorf("v2: base64 decode: %w", err)
		}
		// wrapped DK + nonce (24) + secretbox.Overhead (16)
		min := v2WrappedSize + 24 + secretbox.Overhead
		if len(data) < min {
			return fmt.Errorf("v2: ciphertext truncated (%d bytes, need at least %d)", len(data), min)
		}
		return nil
	case versionPrefix.MatchString(inner):
		return fmt.Errorf("unknown marker version: %s", inner[:strings.Index(inner, ":")+1])
	default:
		return fmt.Errorf("not a versioned marker")
	}
}

// Encryptor produces the inner (version-prefixed) string for a plaintext value.
type Encryptor interface {
	EncryptValue(plaintext []byte) (inner string, err error)
}

// Decryptor recovers plaintext from the inner string of an ENC[...] marker.
// Implementations return ErrSkip when the version prefix does not match. The
// context is plumbed through so KMS-backed implementations can be canceled.
type Decryptor interface {
	DecryptMarker(ctx context.Context, inner string) (plaintext []byte, err error)
}

// NaclEncryptor emits v1: markers using NaCl sealed box.
type NaclEncryptor struct{ PublicKey [32]byte }

func (e NaclEncryptor) EncryptValue(plaintext []byte) (string, error) {
	ct, err := crypto.Encrypt(plaintext, e.PublicKey)
	if err != nil {
		return "", err
	}
	return "v1:" + ct, nil
}

// NaclDecryptor handles v1: markers using NaCl sealed box. ctx is accepted for
// interface conformance but unused — v1 decryption is purely local.
type NaclDecryptor struct{ PrivateKey [32]byte }

func (d NaclDecryptor) DecryptMarker(_ context.Context, inner string) ([]byte, error) {
	if !strings.HasPrefix(inner, "v1:") {
		return nil, ErrSkip
	}
	return crypto.Decrypt(inner[3:], d.PrivateKey)
}

// EnvelopeEncryptor emits v2: markers via per-value envelope:
//
//	wire = base64( wrap(DK) || nonce[24] || secretbox.Seal(plaintext, nonce, DK) )
//
// Each value gets a fresh 32-byte data key, sealed locally with NaCl secretbox.
// The data key is then wrapped with the KMS public key via local RSA-OAEP — no
// network at encrypt time.
type EnvelopeEncryptor struct{ wrapper kms.Wrapper }

func NewEnvelopeEncryptor(w kms.Wrapper) *EnvelopeEncryptor {
	return &EnvelopeEncryptor{wrapper: w}
}

func (e *EnvelopeEncryptor) EncryptValue(plaintext []byte) (string, error) {
	var dk [32]byte
	if _, err := io.ReadFull(rand.Reader, dk[:]); err != nil {
		return "", fmt.Errorf("envelope: read data key: %w", err)
	}
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("envelope: read nonce: %w", err)
	}
	wrapped, err := e.wrapper.Wrap(dk[:])
	if err != nil {
		return "", fmt.Errorf("envelope: wrap data key: %w", err)
	}
	ct := secretbox.Seal(nil, plaintext, &nonce, &dk)

	blob := make([]byte, 0, len(wrapped)+len(nonce)+len(ct))
	blob = append(blob, wrapped...)
	blob = append(blob, nonce[:]...)
	blob = append(blob, ct...)
	return "v2:" + base64.StdEncoding.EncodeToString(blob), nil
}

// EnvelopeDecryptor consumes v2: markers, calling the configured Unwrapper to
// recover the data key for each value. Within the lifetime of one decryptor, the
// same wrapped data key resolves to the same plaintext DK via an internal cache —
// cheap insurance against duplicate ENC[...] blocks paying a second KMS call.
type EnvelopeDecryptor struct {
	unwrapper   kms.Unwrapper
	wrappedSize int

	mu    sync.Mutex
	cache map[string][]byte
}

func NewEnvelopeDecryptor(u kms.Unwrapper, wrappedSize int) *EnvelopeDecryptor {
	return &EnvelopeDecryptor{
		unwrapper:   u,
		wrappedSize: wrappedSize,
		cache:       map[string][]byte{},
	}
}

func (d *EnvelopeDecryptor) DecryptMarker(ctx context.Context, inner string) ([]byte, error) {
	if !strings.HasPrefix(inner, "v2:") {
		return nil, ErrSkip
	}
	blob, err := base64.StdEncoding.DecodeString(inner[3:])
	if err != nil {
		return nil, fmt.Errorf("envelope: base64 decode: %w", err)
	}
	// wrapped_DK[wrappedSize] || nonce[24] || secretbox_ct (≥ secretbox.Overhead = 16 bytes for an empty plaintext)
	const nonceLen = 24
	minLen := d.wrappedSize + nonceLen + secretbox.Overhead
	if len(blob) < minLen {
		return nil, fmt.Errorf("envelope: ciphertext too short (%d < %d)", len(blob), minLen)
	}

	wrapped := blob[:d.wrappedSize]
	var nonce [24]byte
	copy(nonce[:], blob[d.wrappedSize:d.wrappedSize+nonceLen])
	ct := blob[d.wrappedSize+nonceLen:]

	dkBytes, err := d.unwrapCached(ctx, wrapped)
	if err != nil {
		return nil, err
	}
	var dk [32]byte
	copy(dk[:], dkBytes)

	pt, ok := secretbox.Open(nil, ct, &nonce, &dk)
	if !ok {
		return nil, errors.New("envelope: secretbox open failed (corrupt or wrong key)")
	}
	return pt, nil
}

func (d *EnvelopeDecryptor) unwrapCached(ctx context.Context, wrapped []byte) ([]byte, error) {
	key := string(wrapped)
	d.mu.Lock()
	if cached, ok := d.cache[key]; ok {
		d.mu.Unlock()
		return cached, nil
	}
	d.mu.Unlock()

	dk, err := d.unwrapper.Unwrap(ctx, wrapped)
	if err != nil {
		return nil, fmt.Errorf("envelope: unwrap data key: %w", err)
	}

	d.mu.Lock()
	d.cache[key] = dk
	d.mu.Unlock()
	return dk, nil
}

// CompositeDecryptor tries each decryptor in order; ErrSkip falls through.
// The first non-skip result (success or hard error) is returned. This is how
// mixed v1/v2 files are supported — pass a NaclDecryptor and an EnvelopeDecryptor.
type CompositeDecryptor struct{ Decryptors []Decryptor }

func (c CompositeDecryptor) DecryptMarker(ctx context.Context, inner string) ([]byte, error) {
	for _, d := range c.Decryptors {
		pt, err := d.DecryptMarker(ctx, inner)
		if errors.Is(err, ErrSkip) {
			continue
		}
		return pt, err
	}
	return nil, ErrSkip
}

// EncryptContent scans for ENC[plaintext] markers and rewrites each to ENC[<inner>]
// using enc. Already-encrypted markers (any ENC[vN:...]) are left untouched, which
// makes the operation idempotent and preserves foreign-version ciphertexts.
func EncryptContent(content []byte, enc Encryptor) ([]byte, error) {
	var lastErr error
	result := encRegex.ReplaceAllFunc(content, func(match []byte) []byte {
		inner := string(match[4 : len(match)-1])
		if IsEncryptedInner(inner) {
			return match
		}
		out, err := enc.EncryptValue([]byte(inner))
		if err != nil {
			lastErr = err
			return match
		}
		return []byte(fmt.Sprintf("ENC[%s]", out))
	})
	return result, lastErr
}

// DecryptContent scans for ENC[vN:...] markers and rewrites each using dec.
// If keepMarkers is true, the result wraps the plaintext back in ENC[...]; otherwise
// the wrapper is stripped. Markers the decryptor doesn't recognize (ErrSkip) are left
// untouched, which lets mixed v1/v2 files round-trip safely.
func DecryptContent(ctx context.Context, content []byte, dec Decryptor, keepMarkers bool) ([]byte, error) {
	var lastErr error
	result := encRegex.ReplaceAllFunc(content, func(match []byte) []byte {
		inner := string(match[4 : len(match)-1])
		pt, err := dec.DecryptMarker(ctx, inner)
		if errors.Is(err, ErrSkip) {
			return match
		}
		if err != nil {
			lastErr = err
			return match
		}
		if keepMarkers {
			return []byte(fmt.Sprintf("ENC[%s]", string(pt)))
		}
		return pt
	})
	return result, lastErr
}

// ExtractEnv decrypts content and parses it as a .env-style key=value mapping.
func ExtractEnv(ctx context.Context, content []byte, dec Decryptor) (map[string]string, error) {
	decrypted, err := DecryptContent(ctx, content, dec, false)
	if err != nil {
		return nil, err
	}

	env := make(map[string]string)
	for _, line := range strings.Split(string(decrypted), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)
			env[key] = val
		}
	}
	return env, nil
}
