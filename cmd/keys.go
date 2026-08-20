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
	"github.com/rubysolo/envisible/pkg/ui"
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
// The v1 private key may arrive as material (ENVISIBLE_KEY, resolved into
// privKeyMaterial by resolveKeySources) or as a file at privKeyPath. Reading the
// file is best-effort: a project that has fully migrated to v2 won't have one
// and shouldn't be required to.
func loadDecryptor(ctx context.Context) (processor.Decryptor, error) {
	info, _, pubErr := kms.LoadPublicKey(pubKeyPath)
	if pubErr != nil && !errors.Is(pubErr, fs.ErrNotExist) {
		return nil, fmt.Errorf("failed to load public key: %w", pubErr)
	}

	var naclDec processor.NaclDecryptor
	haveNacl := false
	if privKeyMaterial != "" {
		// ENVISIBLE_KEY carries the key itself. Never name the value in an error:
		// crypto.DecodeKey's failures report a byte offset or a length, not content.
		priv, err := crypto.DecodeKey(strings.TrimSpace(privKeyMaterial))
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key from ENVISIBLE_KEY: %w", err)
		}
		naclDec = processor.NaclDecryptor{PrivateKey: priv}
		haveNacl = true
	} else {
		if privData, err := os.ReadFile(privKeyPath); err == nil {
			warnIfKeyFilePermissive(privKeyPath)
			priv, err := crypto.DecodeKey(strings.TrimSpace(string(privData)))
			if err != nil {
				return nil, fmt.Errorf("failed to decode private key: %w", err)
			}
			naclDec = processor.NaclDecryptor{PrivateKey: priv}
			haveNacl = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("failed to read private key: %w", err)
		}
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

// warnIfKeyFilePermissive warns when the private key file is readable by anyone
// other than its owner. keygen writes 0600; a key that has since been copied,
// checked out, or chmod'd loses that and nothing else would notice. This never
// fails the command — breaking a working setup over a permission bit is worse
// than the bit.
func warnIfKeyFilePermissive(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		ui.Warn("private key %s is mode %#o (readable beyond its owner); consider `chmod 600 %s`", path, mode, path)
	}
}
