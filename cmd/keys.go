package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/kms"
	"github.com/rubysolo/envisible/pkg/processor"
)

// loadEncryptor returns an Encryptor backed by the configured public-key file.
//   - v2 (JSON descriptor pointing at a cloud KMS key) → EnvelopeEncryptor
//   - v1 (legacy base64 NaCl public key)               → NaclEncryptor
func loadEncryptor() (processor.Encryptor, error) {
	info, key, err := kms.LoadPublicKey(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key: %w", err)
	}
	if info != nil {
		return processor.NewEnvelopeEncryptor(kms.NewRSAWrapper(info.PubKey)), nil
	}
	return processor.NaclEncryptor{PublicKey: *key}, nil
}

// loadDecryptor returns a Decryptor capable of opening the markers in the file.
//
//   - v2 pubkey only        → EnvelopeDecryptor (KMS-backed)
//   - v1 pubkey + privkey   → NaclDecryptor (legacy)
//   - v2 pubkey + privkey   → CompositeDecryptor [NaCl, Envelope] (mixed v1/v2 file)
//   - no pubkey + privkey   → NaclDecryptor (legacy, pubkey not required for decrypt)
//
// Reading the v1 envisible.key is best-effort: a project that has fully migrated
// to v2 won't have one and shouldn't be required to.
func loadDecryptor(ctx context.Context) (processor.Decryptor, error) {
	info, _, pubErr := kms.LoadPublicKey(pubKeyPath)
	if pubErr != nil && !errors.Is(pubErr, fs.ErrNotExist) {
		return nil, fmt.Errorf("failed to load public key: %w", pubErr)
	}

	var naclDec processor.NaclDecryptor
	haveNacl := false
	if privData, err := os.ReadFile(privKeyPath); err == nil {
		priv, err := crypto.DecodeKey(strings.TrimSpace(string(privData)))
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key: %w", err)
		}
		naclDec = processor.NaclDecryptor{PrivateKey: priv}
		haveNacl = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	var envDec *processor.EnvelopeDecryptor
	if info != nil {
		unwrapper, err := kms.OpenUnwrapper(ctx, info)
		if err != nil {
			return nil, fmt.Errorf("failed to open KMS unwrapper: %w", err)
		}
		envDec = processor.NewEnvelopeDecryptor(unwrapper, info.PubKey.Size())
	}

	switch {
	case envDec != nil && haveNacl:
		// Mixed file support — try v1 first since it's local and free.
		return processor.CompositeDecryptor{Decryptors: []processor.Decryptor{naclDec, envDec}}, nil
	case envDec != nil:
		return envDec, nil
	case haveNacl:
		return naclDec, nil
	default:
		return nil, fmt.Errorf("no decryption key available (looked for %s and %s)", pubKeyPath, privKeyPath)
	}
}

// loadProvider loads both an Encryptor and Decryptor for commands that round-trip
// (e.g. `edit`, future `kms rotate`).
func loadProvider(ctx context.Context) (processor.Encryptor, processor.Decryptor, error) {
	enc, err := loadEncryptor()
	if err != nil {
		return nil, nil, err
	}
	dec, err := loadDecryptor(ctx)
	if err != nil {
		return nil, nil, err
	}
	return enc, dec, nil
}
