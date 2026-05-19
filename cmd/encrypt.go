package cmd

import (
	"fmt"
	"os"

	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

var inplace bool

var encryptCmd = &cobra.Command{
	Use:   "encrypt [file]",
	Short: "Encrypt ENC[...] markers in a file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetFile := filePath
		if len(args) > 0 {
			targetFile = args[0]
		}

		enc, err := loadEncryptor()
		if err != nil {
			return err
		}

		content, err := os.ReadFile(targetFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}

		encrypted, err := processor.EncryptContent(content, enc)
		if err != nil {
			return fmt.Errorf("failed to encrypt content: %w", err)
		}

		if inplace {
			err = os.WriteFile(targetFile, encrypted, 0644)
			if err != nil {
				return fmt.Errorf("failed to write file: %w", err)
			}
			ui.Success("File %s encrypted in-place.", targetFile)
		} else {
			fmt.Fprint(cmd.OutOrStdout(), string(encrypted))
		}

		return nil
	},
}

func init() {
	encryptCmd.Flags().BoolVarP(&inplace, "inplace", "i", false, "modify the file in place")
	rootCmd.AddCommand(encryptCmd)
}
