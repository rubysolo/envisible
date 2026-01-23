package cmd

import (
	"fmt"
	"os"

	"github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/spf13/cobra"
)

var inplace bool

var encryptCmd = &cobra.Command{
	Use:   "encrypt [file]",
	Short: "Encrypt ENC[...] markers in a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		
		pubKeyData, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read public key: %w", err)
		}
		
		pubKey, err := crypto.DecodeKey(string(pubKeyData))
		if err != nil {
			return fmt.Errorf("failed to decode public key: %w", err)
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}

		encrypted, err := processor.EncryptContent(content, pubKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt content: %w", err)
		}

		if inplace {
			err = os.WriteFile(filePath, encrypted, 0644)
			if err != nil {
				return fmt.Errorf("failed to write file: %w", err)
			}
		} else {
			fmt.Print(string(encrypted))
		}

		return nil
	},
}

func init() {
	encryptCmd.Flags().BoolVarP(&inplace, "inplace", "i", false, "modify the file in place")
	rootCmd.AddCommand(encryptCmd)
}
