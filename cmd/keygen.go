package cmd

import (
	"fmt"
	"os"

	"github.com/rubysolo/envisible/pkg/crypto"
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
			return fmt.Errorf("failed to write public key: %w", err)
		}

		err = os.WriteFile(privKeyPath, []byte(crypto.EncodeKey(priv)), 0600)
		if err != nil {
			return fmt.Errorf("failed to write private key: %w", err)
		}

		fmt.Printf("Generated keys:\n  Public:  %s\n  Private: %s\n", pubKeyPath, privKeyPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(keygenCmd)
}

