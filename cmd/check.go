package cmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

var verify bool

var checkCmd = &cobra.Command{
	Use:   "check [file]",
	Short: "Check for unencrypted or invalid ENC[...] markers",
	Long: `Scans a file for ENC[...] markers.
By default, it checks for unencrypted markers (not starting with 'v1:').
If --verify is used, it also attempts to decrypt each marker with the private key to ensure validity.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetFile := filePath
		if len(args) > 0 {
			targetFile = args[0]
		}
		content, err := os.ReadFile(targetFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}

		encRegex := regexp.MustCompile(`ENC\[(.*?)\]`)

		matches := encRegex.FindAllSubmatch(content, -1)
		unencryptedCount := 0
		verificationFailedCount := 0

		// If verification is requested, load the key
		var privKey [32]byte
		if verify {
			privKeyData, err := os.ReadFile(privKeyPath)
			if err != nil {
				return fmt.Errorf("failed to read private key from %s: %w", privKeyPath, err)
			}
			privKey, err = crypto.DecodeKey(strings.TrimSpace(string(privKeyData)))
			if err != nil {
				return fmt.Errorf("failed to decode private key: %w", err)
			}
		}

		for _, match := range matches {
			fullMatch := string(match[0])
			inner := string(match[1])

			// Check 1: Is it unencrypted?
			if !strings.HasPrefix(inner, "v1:") {
				ui.Warn("Unencrypted value found: %s", fullMatch)
				unencryptedCount++
				continue // Cannot verify unencrypted values
			}

			// Check 2: Verification (if requested)
			if verify {
				ciphertext := inner[3:]
				_, err := crypto.Decrypt(ciphertext, privKey)
				if err != nil {
					ui.Error("Verification failed for %s: %v", fullMatch, err)
					verificationFailedCount++
				}
			}
		}

		if unencryptedCount > 0 {
			return fmt.Errorf("found %d unencrypted values in %s", unencryptedCount, targetFile)
		}

		if verificationFailedCount > 0 {
			return fmt.Errorf("found %d invalid/corrupt values in %s", verificationFailedCount, targetFile)
		}

		msg := ""
		if verify {
			msg = "All ENC[...] markers in %s are encrypted and verified."
		} else {
			msg = "All ENC[...] markers in %s appear to be encrypted."
		}

		ui.Success(msg, targetFile)
		return nil
	},
}

func init() {
	checkCmd.Flags().BoolVarP(&verify, "verify", "v", false, "Verify that values can be decrypted with the current key")
	rootCmd.AddCommand(checkCmd)
}
