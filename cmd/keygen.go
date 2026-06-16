package cmd

import (
	"os"

	"github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new asymmetric keypair",
	RunE: func(cmd *cobra.Command, args []string) error {
		pub, priv, err := crypto.GenerateKeypair()
		if err != nil {
			return err
		}

		err = os.WriteFile(pubKeyPath, []byte(crypto.EncodeKey(pub)), 0644)
		if err != nil {
			return err
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
	rootCmd.AddCommand(keygenCmd)
}
