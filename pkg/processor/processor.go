package processor

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rubysolo/envisible/pkg/crypto"
)

var encRegex = regexp.MustCompile(`ENC\[(.*?)\]`)

// EncryptContent scans the content for ENC[plaintext] and replaces it with ENC[v1:ciphertext]
func EncryptContent(content []byte, publicKey [32]byte) ([]byte, error) {
	var lastErr error
	result := encRegex.ReplaceAllFunc(content, func(match []byte) []byte {
		// match is "ENC[something]"
		inner := string(match[4 : len(match)-1])

		// Skip if already encrypted
		if strings.HasPrefix(inner, "v1:") {
			return match
		}

		ciphertext, err := crypto.Encrypt([]byte(inner), publicKey)
		if err != nil {
			lastErr = err
			return match
		}

		return []byte(fmt.Sprintf("ENC[v1:%s]", ciphertext))
	})

	return result, lastErr
}

// DecryptContent scans the content for ENC[v1:ciphertext] and replaces it with ENC[plaintext]
// if keepMarkers is true, it replaces it with ENC[plaintext], otherwise just plaintext.
func DecryptContent(content []byte, privateKey [32]byte, keepMarkers bool) ([]byte, error) {
	var lastErr error
	result := encRegex.ReplaceAllFunc(content, func(match []byte) []byte {
		inner := string(match[4 : len(match)-1])

		if !strings.HasPrefix(inner, "v1:") {
			return match
		}

		ciphertext := inner[3:]
		plaintext, err := crypto.Decrypt(ciphertext, privateKey)
		if err != nil {
			lastErr = err
			return match
		}

		if keepMarkers {
			return []byte(fmt.Sprintf("ENC[%s]", string(plaintext)))
		}
		return plaintext
	})

	return result, lastErr
}

// ExtractEnv extracts environment variables from content that are marked with ENC[...]
// It returns a map of decrypted values.
// Note: This expects content in a format that looks like KEY=ENC[...] or similar.
// Actually, it might be better to just decrypt the whole content and then let something else parse it.
func ExtractEnv(content []byte, privateKey [32]byte) (map[string]string, error) {
	// For 'run', we usually want to decrypt the whole file and then parse it as .env
	// But to be generic, let's just decrypt all ENC[...] markers.
	decrypted, err := DecryptContent(content, privateKey, false)
	if err != nil {
		return nil, err
	}

	// Simple .env parser for the decrypted content
	env := make(map[string]string)
	lines := strings.Split(string(decrypted), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			// Strip quotes if present
			val = strings.Trim(val, `"'`)
			env[key] = val
		}
	}

	return env, nil
}
