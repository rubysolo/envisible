package processor

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/rubysolo/envisible/pkg/kms"
)

// RewrapContent rewrites every ENC[v2:...] marker so the wrapped data key is
// re-wrapped against newWrapper instead of being decryptable by oldUnwrapper.
// The secretbox-protected payload (nonce + ciphertext) is left bit-for-bit
// identical — rotation only swaps the wrapped DK, so the plaintext never has
// to be reconstructed in memory.
//
// Markers other than ENC[v2:...] (including ENC[v1:...] and plain ENC[...])
// pass through unchanged, as do markers inside comments — a ciphertext parked
// in a comment for reference is never sent to the KMS, matching DecryptContent.
// If any v2 marker fails to unwrap/rewrap, the whole operation returns an error
// and the caller should not write the result.
func RewrapContent(ctx context.Context, content []byte, oldUnwrapper kms.Unwrapper, oldWrappedSize int, newWrapper kms.Wrapper) ([]byte, int, error) {
	out, rotated, _, err := RewrapContentWithDefects(ctx, content, oldUnwrapper, oldWrappedSize, newWrapper)
	return out, rotated, err
}

// RewrapContentWithDefects is RewrapContent plus the scanner defects found
// outside comments. Rotation is a read path, so `kms rotate` warns on them and
// proceeds.
func RewrapContentWithDefects(ctx context.Context, content []byte, oldUnwrapper kms.Unwrapper, oldWrappedSize int, newWrapper kms.Wrapper) ([]byte, int, []Defect, error) {
	markers, defects := Scan(content)

	var (
		out     bytes.Buffer
		cursor  int
		rotated int
	)
	out.Grow(len(content))
	for _, m := range markers {
		if !m.Encrypted {
			continue
		}
		newInner, err := rewrapV2Inner(ctx, m.Raw, oldUnwrapper, oldWrappedSize, newWrapper)
		if errors.Is(err, ErrSkip) {
			continue
		}
		if err != nil {
			return nil, 0, defects, err
		}
		out.Write(content[cursor:m.Start])
		out.WriteString(wrapMarker(newInner))
		cursor = m.End
		rotated++
	}
	out.Write(content[cursor:])
	return out.Bytes(), rotated, defects, nil
}

// rewrapV2Inner takes the inside of an ENC[...] marker. If it's v2-shaped, it
// re-wraps the data key portion and returns the new inner string. Otherwise it
// returns ErrSkip.
func rewrapV2Inner(ctx context.Context, inner string, oldUnwrapper kms.Unwrapper, oldWrappedSize int, newWrapper kms.Wrapper) (string, error) {
	if len(inner) < 3 || inner[:3] != "v2:" {
		return "", ErrSkip
	}
	blob, err := base64.StdEncoding.DecodeString(inner[3:])
	if err != nil {
		return "", fmt.Errorf("rewrap: base64 decode: %w", err)
	}
	if len(blob) <= oldWrappedSize {
		return "", fmt.Errorf("rewrap: ciphertext too short for wrapped key size %d", oldWrappedSize)
	}
	oldWrapped := blob[:oldWrappedSize]
	tail := blob[oldWrappedSize:] // nonce + secretbox ciphertext, untouched

	dk, err := oldUnwrapper.Unwrap(ctx, oldWrapped)
	if err != nil {
		return "", fmt.Errorf("rewrap: unwrap with old key: %w", err)
	}
	newWrapped, err := newWrapper.Wrap(dk)
	if err != nil {
		return "", fmt.Errorf("rewrap: wrap with new key: %w", err)
	}

	out := make([]byte, 0, len(newWrapped)+len(tail))
	out = append(out, newWrapped...)
	out = append(out, tail...)
	return "v2:" + base64.StdEncoding.EncodeToString(out), nil
}
