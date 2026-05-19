package processor

import (
	"context"
	"encoding/base64"
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
// pass through unchanged. If any v2 marker fails to unwrap/rewrap, the whole
// operation returns an error and the caller should not write the result.
func RewrapContent(ctx context.Context, content []byte, oldUnwrapper kms.Unwrapper, oldWrappedSize int, newWrapper kms.Wrapper) ([]byte, int, error) {
	var lastErr error
	rotated := 0
	result := encRegex.ReplaceAllFunc(content, func(match []byte) []byte {
		inner := string(match[4 : len(match)-1])
		newInner, err := rewrapV2Inner(ctx, inner, oldUnwrapper, oldWrappedSize, newWrapper)
		if err == ErrSkip {
			return match
		}
		if err != nil {
			lastErr = err
			return match
		}
		rotated++
		return []byte(fmt.Sprintf("ENC[%s]", newInner))
	})
	if lastErr != nil {
		return nil, 0, lastErr
	}
	return result, rotated, nil
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
