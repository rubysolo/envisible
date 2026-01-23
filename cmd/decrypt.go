package cmd

import (
	"fmt"
	"os"

	"github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/spf13/cobra"
)

var stripMarkers bool

var decryptCmd = &cobra.Command{
	Use:   "decrypt [file]",
	Short: "Decrypt ENC[v1:...] markers in a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		
		privKeyData, err := os.ReadFile(privKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}
		
		privKey, err := crypto.DecodeKey(string(privKeyData))
		if err != nil {
			return fmt.Errorf("failed to decode private key: %w", err)
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}

		decrypted, err := processor.DecryptContent(content, privKey, !stripMarkers)
		if err != nil {
			return fmt.Errorf("failed to decrypt content: %w", err)
		}

		if inplace {
			err = os.WriteFile(filePath, decrypted, 0644)
			if err != nil {
				return fmt.Errorf("failed to write file: %w", err)
			}
		} else {
			fmt.Print(string(decrypted))
		}

		return nil
	},
}

func init() {
	decryptCmd.Flags().BoolVarP(&inplace, "inplace", "i", false, "modify the file in place")
	decryptCmd.Flags().BoolVar(&stripMarkers, "strip", false, "strip ENC[...] markers and show only plaintext")
	rootCmd.AddCommand(decryptCmd)
}
