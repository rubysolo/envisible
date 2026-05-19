package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rubysolo/envisible/pkg/kms"
	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/rubysolo/envisible/pkg/ui"
)

var kmsRotateTo string

var kmsRotateCmd = &cobra.Command{
	Use:   "rotate [file...]",
	Short: "Re-wrap ENC[v2:...] markers against a new KMS key",
	Long: `Rotates a project to a newer KMS key version (or a different key under the
same provider). For each ENC[v2:...] marker in the given files, the wrapped
data key is unwrapped using the currently-registered KMS key, then re-wrapped
against the new key. The secretbox-protected payload is left bit-for-bit
identical — rotation never reconstructs plaintexts in memory.

After all files are rewritten, envisible.pub is updated to point at the new
resource. Files with no v2 markers are left untouched.

Rotation is same-provider only. Cross-provider migration (e.g. GCP -> AWS)
should be done via decrypt + re-encrypt.

Examples:
  envisible kms rotate --to projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2
  envisible kms rotate --to arn:aws:kms:us-east-1:.../key/<new-uuid> .env config.yaml`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if kmsRotateTo == "" {
			return fmt.Errorf("--to is required")
		}

		// 1. Load the currently-registered (old) key. Must be v2 — there's nothing
		// to rotate in a legacy NaCl project.
		oldInfo, _, err := kms.LoadPublicKey(pubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load current public key: %w", err)
		}
		if oldInfo == nil {
			return fmt.Errorf("%s is a legacy v1 NaCl key; `kms rotate` only applies to v2 KMS-backed keys", pubKeyPath)
		}

		// 2. Open an unwrapper for the OLD key. Requires decrypt permission on
		// the old resource — that's the whole point of rotation.
		oldUnwrapper, err := kms.OpenUnwrapper(cmd.Context(), oldInfo)
		if err != nil {
			return fmt.Errorf("failed to open old KMS unwrapper: %w", err)
		}

		// 3. Fetch the NEW public key. Same-provider only; cross-provider would
		// need a separate flag and isn't supported here.
		newInfo, err := kms.BootstrapPublicKey(cmd.Context(), oldInfo.Kind, kmsRotateTo)
		if err != nil {
			return fmt.Errorf("failed to fetch new public key: %w", err)
		}
		newWrapper := kms.NewRSAWrapper(newInfo.PubKey)

		// 4. Default to the global --file if no positional args are given.
		files := args
		if len(files) == 0 {
			files = []string{filePath}
		}

		// 5. Build rewritten content for every file in memory first. If any
		// file fails (unwrap error, bad ciphertext, etc.), abort before touching
		// disk — half-rotated projects are very hard to recover.
		type pending struct {
			path    string
			content []byte
			rotated int
		}
		results := make([]pending, 0, len(files))
		for _, f := range files {
			content, err := os.ReadFile(f)
			if err != nil {
				return fmt.Errorf("read %s: %w", f, err)
			}
			newContent, n, err := processor.RewrapContent(cmd.Context(), content, oldUnwrapper, oldInfo.PubKey.Size(), newWrapper)
			if err != nil {
				return fmt.Errorf("rewrap %s: %w", f, err)
			}
			results = append(results, pending{path: f, content: newContent, rotated: n})
		}

		// 6. Commit. Write files first, then envisible.pub last — that order
		// minimizes the half-rotated failure window, since decrypt failures with
		// the old pubkey still pointing at the old key give clearer errors than
		// the reverse (new pubkey, old wrapped DKs in files).
		total := 0
		for _, r := range results {
			if err := os.WriteFile(r.path, r.content, 0644); err != nil {
				return fmt.Errorf("write %s: %w", r.path, err)
			}
			total += r.rotated
		}
		if err := kms.WritePublicKey(pubKeyPath, newInfo); err != nil {
			return fmt.Errorf("rotated %d marker(s) across %d file(s) but failed to update %s: %w (re-run `envisible kms init --provider %s --resource %s` to fix)",
				total, len(results), pubKeyPath, err, oldInfo.Kind, kmsRotateTo)
		}

		ui.Success("Rotated %d v2 marker(s) across %d file(s)", total, len(results))
		for _, r := range results {
			ui.KV(fmt.Sprintf("  %s", r.path), fmt.Sprintf("%d marker(s)", r.rotated))
		}
		ui.KV("Old resource", oldInfo.Resource)
		ui.KV("New resource", newInfo.Resource)
		ui.KV("Public key updated", pubKeyPath)
		return nil
	},
}

func init() {
	kmsRotateCmd.Flags().StringVar(&kmsRotateTo, "to", "", "Resource string of the new key version (provider-native)")
	_ = kmsRotateCmd.MarkFlagRequired("to")
	kmsCmd.AddCommand(kmsRotateCmd)
}
