// Package kms defines the abstraction for cloud-KMS-backed asymmetric encryption.
//
// Encryption is a local operation: a per-value 32-byte data key is wrapped with
// RSA-OAEP-SHA-256 against the registered public key (no network). Decryption
// round-trips the wrapped data key to the cloud KMS to recover it; the actual
// payload is then opened locally with NaCl secretbox.
//
// Wrap and Unwrap are split into separate interfaces so the encrypt path never
// pulls in cloud SDK dependencies — `envisible encrypt` runs entirely on stdlib.
package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// ProviderKind identifies a cloud KMS backend.
type ProviderKind string

const (
	GCP   ProviderKind = "gcp"
	AWS   ProviderKind = "aws"
	Azure ProviderKind = "azure"
)

// Algorithm names the wrap/unwrap scheme. Today only one is supported across all
// providers; the field exists so future algorithms can be added without re-jigging
// the on-disk public-key file.
type Algorithm string

const RSAOAEPSHA256_2048 Algorithm = "RSA-OAEP-SHA256-2048"

// PublicKeyInfo is the everything-needed-to-encrypt descriptor parsed from
// `envisible.pub`. The fields are also enough to instantiate an Unwrapper, since
// the provider package only needs Kind + Resource + a context to call the cloud.
type PublicKeyInfo struct {
	Kind     ProviderKind
	Resource string
	Alg      Algorithm
	PubKey   *rsa.PublicKey
}

// Wrapper performs a local RSA-OAEP-SHA-256 wrap of a 32-byte data key.
type Wrapper interface {
	Wrap(dk []byte) ([]byte, error)
	WrappedSize() int
}

// Unwrapper performs a remote KMS asymmetric decrypt of a wrapped data key.
type Unwrapper interface {
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

// Provider couples wrap and unwrap for commands that round-trip (edit, rotate).
type Provider interface {
	Wrapper
	Unwrapper
	Kind() ProviderKind
	Resource() string
}

// NewRSAWrapper returns a stdlib-only RSA-OAEP-SHA-256 wrapper. All three cloud
// backends use the same wrap path, so providers only need to implement Unwrap.
func NewRSAWrapper(pub *rsa.PublicKey) Wrapper {
	return &rsaWrapper{pub: pub}
}

type rsaWrapper struct{ pub *rsa.PublicKey }

func (r *rsaWrapper) Wrap(dk []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, r.pub, dk, nil)
}

func (r *rsaWrapper) WrappedSize() int {
	return r.pub.Size()
}

// ValidateAlgorithm rejects algorithm/key-size combinations the format does not
// support. Called at init time to fail fast on misconfigured keys.
func ValidateAlgorithm(alg Algorithm, pub *rsa.PublicKey) error {
	switch alg {
	case RSAOAEPSHA256_2048:
		if pub.Size() != 256 {
			return fmt.Errorf("kms: public key is %d-bit, but algorithm %q requires 2048-bit RSA", pub.Size()*8, alg)
		}
		return nil
	default:
		return fmt.Errorf("kms: unsupported algorithm %q", alg)
	}
}
