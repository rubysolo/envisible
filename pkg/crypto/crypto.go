package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// GenerateKeypair creates a new asymmetric keypair.
func GenerateKeypair() (publicKey [32]byte, privateKey [32]byte, err error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	return *pub, *priv, nil
}

// Encrypt encrypts plaintext using the recipient's public key.
// It uses an ephemeral keypair to achieve "sealed box" behavior.
func Encrypt(plaintext []byte, recipientPub [32]byte) (string, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}

	// The message is: ephemeral_pub + nonce + ciphertext
	out := make([]byte, 32+24)
	copy(out[0:32], pub[:])
	copy(out[32:56], nonce[:])

	ciphertext := box.Seal(out, plaintext, &nonce, &recipientPub, priv)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64 encoded ciphertext using the recipient's private key.
func Decrypt(encodedCiphertext string, recipientPriv [32]byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, err
	}

	if len(data) < 32+24+box.Overhead {
		return nil, errors.New("ciphertext too short")
	}

	var ephemeralPub [32]byte
	var nonce [24]byte
	copy(ephemeralPub[:], data[0:32])
	copy(nonce[:], data[32:56])

	plaintext, ok := box.Open(nil, data[56:], &nonce, &ephemeralPub, &recipientPriv)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}

// EncodeKey returns the base64 string representation of a key.
func EncodeKey(key [32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// DecodeKey decodes a base64 string into a [32]byte key.
func DecodeKey(encoded string) ([32]byte, error) {
	var key [32]byte
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return key, err
	}
	if len(data) != 32 {
		return key, fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(data))
	}
	copy(key[:], data)
	return key, nil
}
