package kms

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rubysolo/envisible/pkg/crypto"
)

// pubkeyFile is the on-disk JSON shape for v2 (KMS-backed) public keys.
type pubkeyFile struct {
	Version   int    `json:"version"`
	Provider  string `json:"provider"`
	Resource  string `json:"resource"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// LoadPublicKey reads the file at path and returns either v2 KMS metadata or a
// legacy v1 NaCl public key. Exactly one of the two non-error returns is non-nil:
//
//	(info, nil, nil) — v2 KMS-backed (envisible.pub is a JSON descriptor)
//	(nil, &key, nil) — v1 NaCl  (envisible.pub is base64 of a 32-byte key)
//
// The format is detected from the first non-whitespace byte: '{' selects JSON,
// anything else falls through to the legacy base64 decoder. This keeps existing
// v1 projects working unchanged.
func LoadPublicKey(path string) (*PublicKeyInfo, *[32]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		info, err := parseV2PublicKey(trimmed)
		if err != nil {
			return nil, nil, err
		}
		return info, nil, nil
	}

	key, err := crypto.DecodeKey(string(trimmed))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	return nil, &key, nil
}

// WritePublicKey serializes info as the v2 JSON format and writes it to path.
func WritePublicKey(path string, info *PublicKeyInfo) error {
	if err := ValidateAlgorithm(info.Alg, info.PubKey); err != nil {
		return err
	}
	pemStr, err := encodeRSAPublicKeyPEM(info.PubKey)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(pubkeyFile{
		Version:   2,
		Provider:  string(info.Kind),
		Resource:  info.Resource,
		Algorithm: string(info.Alg),
		PublicKey: pemStr,
	}, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return os.WriteFile(path, body, 0644)
}

func parseV2PublicKey(data []byte) (*PublicKeyInfo, error) {
	var f pubkeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("kms: parse public key JSON: %w", err)
	}
	if f.Version != 2 {
		return nil, fmt.Errorf("kms: unsupported public key file version %d", f.Version)
	}
	kind, err := parseProviderKind(f.Provider)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(f.Resource) == "" {
		return nil, errors.New("kms: public key file is missing 'resource'")
	}
	pub, err := ParseRSAPublicKeyPEM(f.PublicKey)
	if err != nil {
		return nil, err
	}
	alg := Algorithm(f.Algorithm)
	if err := ValidateAlgorithm(alg, pub); err != nil {
		return nil, err
	}
	return &PublicKeyInfo{
		Kind:     kind,
		Resource: f.Resource,
		Alg:      alg,
		PubKey:   pub,
	}, nil
}

func parseProviderKind(s string) (ProviderKind, error) {
	switch ProviderKind(s) {
	case GCP, AWS, Azure:
		return ProviderKind(s), nil
	default:
		return "", fmt.Errorf("kms: unknown provider %q", s)
	}
}

// ParseRSAPublicKeyPEM parses a PEM-encoded PKIX public key, asserting it is RSA.
// Provider packages use this when bootstrapping a public key fetched from a KMS
// that hands back PEM (e.g. GCP).
func ParseRSAPublicKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("kms: failed to decode PEM public key")
	}
	return ParseRSAPublicKeyDER(block.Bytes)
}

// ParseRSAPublicKeyDER parses a DER-encoded PKIX public key, asserting it is RSA.
// Used for KMS backends that hand back raw DER (e.g. AWS KMS).
func ParseRSAPublicKeyDER(der []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("kms: parse PKIX public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("kms: public key is not RSA (got %T)", pub)
	}
	return rsaPub, nil
}

func encodeRSAPublicKeyPEM(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("kms: marshal PKIX public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})), nil
}
