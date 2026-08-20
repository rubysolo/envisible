package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

// printKey is the --print-key flag: emit the private key on stdout instead of
// writing envisible.key, so it can be piped straight into a secret store.
var printKey bool

// keygenStdoutIsTTY reports whether the process stdout is attached to a
// terminal. Indirected through a variable so tests can simulate both answers.
var keygenStdoutIsTTY = func() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new asymmetric keypair",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Refuse before generating anything, so a refused run leaves no artifacts.
		// The one thing worse than a key file is a key in scrollback.
		if printKey && keygenStdoutIsTTY() {
			return errors.New("refusing to print the private key to a terminal: redirect stdout, e.g. `envisible keygen --print-key | your-secret-store set envisible-key`")
		}

		pub, priv, err := crypto.GenerateKeypair()
		if err != nil {
			return err
		}

		err = os.WriteFile(pubKeyPath, []byte(crypto.EncodeKey(pub)), 0644)
		if err != nil {
			return err
		}

		if printKey {
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), crypto.EncodeKey(priv)); err != nil {
				return err
			}
			ui.Success("Generated keys")
			ui.KV("Public", pubKeyPath)
			ui.KV("Private", "written to stdout (no file)")
			return nil
		}

		err = os.WriteFile(privKeyPath, []byte(crypto.EncodeKey(priv)), 0600)
		if err != nil {
			return err
		}

		ui.Success("Generated keys")
		ui.KV("Public", pubKeyPath)
		ui.KV("Private", privKeyPath)
		return nil
	},
}

func init() {
	keygenCmd.Flags().BoolVar(&printKey, "print-key", false, "write the private key to stdout instead of a file (refused when stdout is a terminal)")
	rootCmd.AddCommand(keygenCmd)
}
