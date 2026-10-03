package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

// printKey is the --print-key flag: emit the private key on stdout instead of
// writing envisible.key, so it can be piped straight into a secret store.
var printKey bool

// forceKeygen is the --force flag: replace an existing key file. Without it
// keygen refuses, because the old private key is the only thing that can
// decrypt what was encrypted with it.
var forceKeygen bool

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

		// A new keypair over an existing one is not recoverable: every secret
		// encrypted to the old public key needs the old private key, and this
		// is the command that would destroy it. An existing public key alone
		// counts too. It may be the only half this machine is meant to have, or
		// a KMS descriptor, and replacing it silently redirects every future
		// encrypt.
		if !forceKeygen {
			targets := []string{pubKeyPath}
			if !printKey {
				targets = append(targets, privKeyPath)
			}
			if existing := existingPaths(targets); len(existing) > 0 {
				return fmt.Errorf("%s already exist%s: a new keypair cannot decrypt anything encrypted with the old one. Pass --force to replace it",
					strings.Join(existing, " and "), map[bool]string{true: "s", false: ""}[len(existing) == 1])
			}
		}

		pub, priv, err := crypto.GenerateKeypair()
		if err != nil {
			return err
		}

		// The two halves are useless apart, and a new public key beside an old
		// private key is worse than useless: everything encrypted from then on
		// can be decrypted by nothing. So nothing on disk changes until every
		// step that can realistically fail has succeeded.
		pubFile, err := stageFile(pubKeyPath, []byte(crypto.EncodeKey(pub)), 0644, false)
		if err != nil {
			return err
		}

		if printKey {
			// Emit the private key first. If the write fails nobody has the
			// key, so the public half must not be left behind.
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), crypto.EncodeKey(priv)); err != nil {
				pubFile.discard()
				return fmt.Errorf("failed to write the private key to stdout: %w", err)
			}
			if err := pubFile.commit(); err != nil {
				return fmt.Errorf("%w (the private key was already written to stdout; it has no public key on disk, discard it and run keygen again)", err)
			}
			ui.Success("Generated keys")
			ui.KV("Public", pubKeyPath)
			ui.KV("Private", "written to stdout (no file)")
			return nil
		}

		// Always 0600, even over an existing key file with looser permissions.
		privFile, err := stageFile(privKeyPath, []byte(crypto.EncodeKey(priv)), 0600, false)
		if err != nil {
			pubFile.discard()
			return err
		}

		// Public key first: if the private key's rename then fails, the old
		// private key is still on disk and the old public key can be put back,
		// which restores a working pair. The other order would lose the old
		// private key with no way to undo it.
		oldPub, oldPubErr := os.ReadFile(pubKeyPath)
		if err := pubFile.commit(); err != nil {
			privFile.discard()
			return err
		}
		if err := privFile.commit(); err != nil {
			return errors.Join(err, restorePublicKey(oldPub, oldPubErr))
		}

		ui.Success("Generated keys")
		ui.KV("Public", pubKeyPath)
		ui.KV("Private", privKeyPath)
		return nil
	},
}

// existingPaths returns the paths that already exist, in the order given. Lstat,
// so a dangling symlink counts: something is there, and keygen would write
// through or over it.
func existingPaths(paths []string) []string {
	var found []string
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			found = append(found, p)
		}
	}
	return found
}

// restorePublicKey undoes a public-key write after the matching private key
// could not be written: it puts the previous contents back, or removes the file
// if there was none. It returns nil when the public key is back as it was.
func restorePublicKey(old []byte, readErr error) error {
	var err error
	switch {
	case errors.Is(readErr, os.ErrNotExist):
		err = os.Remove(pubKeyPath)
	case readErr != nil:
		err = fmt.Errorf("its previous contents could not be read: %w", readErr)
	default:
		err = writeFileAtomic(pubKeyPath, old, 0644)
	}
	if err != nil {
		return fmt.Errorf("%s now holds a public key with no private key and could not be restored: %w", pubKeyPath, err)
	}
	return nil
}

func init() {
	keygenCmd.Flags().BoolVar(&forceKeygen, "force", false, "replace existing key files (secrets encrypted with the old keypair become undecryptable)")
	keygenCmd.Flags().BoolVar(&printKey, "print-key", false, "write the private key to stdout instead of a file (refused when stdout is a terminal)")
	rootCmd.AddCommand(keygenCmd)
}
