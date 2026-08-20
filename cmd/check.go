package cmd

import (
	"fmt"

	"github.com/rubysolo/envisible/pkg/kms"
	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

var verify bool

var checkCmd = &cobra.Command{
	Use:   "check [file]",
	Short: "Check for unencrypted or malformed ENC[...] markers",
	Long: `Scans a file for ENC[...] markers.

By default, performs three cheap, offline checks per marker:
  1. Has a recognized vN: prefix (otherwise it's a plaintext marker — must be encrypted).
  2. The inner payload is valid base64.
  3. The decoded bytes are long enough to be a real ciphertext (catches truncation).

With --verify, additionally attempts a full decryption of each marker. For v2
KMS-backed markers this hits the cloud KMS — once per unique wrapped data key
— so use it deliberately rather than in tight loops.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetFile := filePath
		if len(args) > 0 {
			targetFile = args[0]
		}
		content, _, err := readTarget(cmd, targetFile)
		if err != nil {
			return err
		}
		// Messages interpolate the target; stdin has no path to name.
		name := targetName(targetFile)

		// For v2 structure checks, look up the registered key's modulus size so
		// we can require the exact wrapped-DK length. If envisible.pub is missing
		// or v1, fall back to 256 bytes (RSA-2048 minimum) — still catches
		// truncation, just less precisely.
		v2WrappedSize := 256
		if info, _, err := kms.LoadPublicKey(pubKeyPath); err == nil && info != nil {
			v2WrappedSize = info.PubKey.Size()
		}

		markers, defects := processor.Scan(content)
		unencryptedCount := 0
		malformedCount := 0
		verificationFailedCount := 0

		var dec processor.Decryptor
		if verify {
			dec, err = loadDecryptor(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to load key for verification: %w", err)
			}
		}

		for _, m := range markers {
			fullMatch := string(content[m.Start:m.End])

			if !m.Encrypted {
				ui.Warn("Unencrypted value found: %s", fullMatch)
				unencryptedCount++
				// The irreducibly ambiguous shapes in the grammar. Warnings only:
				// the marker is going to be encrypted either way, but the author
				// may have meant more (or less) of the file to be part of it.
				warnAmbiguousMarker(name, content, m)
				continue
			}

			if err := processor.StructureCheck(m.Raw, v2WrappedSize); err != nil {
				ui.Error("Malformed marker %s: %v", fullMatch, err)
				malformedCount++
				continue
			}

			if verify {
				if _, err := dec.DecryptMarker(cmd.Context(), m.Raw); err != nil {
					ui.Error("Verification failed for %s: %v", fullMatch, err)
					verificationFailedCount++
				}
			}
		}

		// Tokens the scanner could not parse at all: an ENC[ that never closes,
		// or a ciphertext marker truncated at a newline. Both used to be
		// invisible — the old regex simply didn't match, so `check` passed.
		// Rendered once, here, by the error main prints.
		if err := defectError(name, content, defects); err != nil {
			return err
		}
		if unencryptedCount > 0 {
			return fmt.Errorf("found %d unencrypted values in %s", unencryptedCount, name)
		}
		if malformedCount > 0 {
			return fmt.Errorf("found %d malformed markers in %s", malformedCount, name)
		}
		if verificationFailedCount > 0 {
			return fmt.Errorf("found %d invalid/corrupt values in %s", verificationFailedCount, name)
		}

		msg := "All ENC[...] markers in %s look well-formed."
		if verify {
			msg = "All ENC[...] markers in %s are encrypted and verified."
		}
		ui.Success(msg, name)
		return nil
	},
}

func init() {
	checkCmd.Flags().BoolVarP(&verify, "verify", "v", false, "Verify that values can be decrypted with the current key (hits KMS for v2)")
	rootCmd.AddCommand(checkCmd)
}
