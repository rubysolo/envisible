package cmd

import (
	"fmt"
	"os"

	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/spf13/cobra"
)

var (
	stripMarkers bool
	textconv     bool
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt [file]",
	Short: "Decrypt ENC[v1:...] markers in a file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetFile := filePath
		if len(args) > 0 {
			targetFile = args[0]
		}

		content, err := os.ReadFile(targetFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}

		dec, err := loadDecryptor(cmd.Context())
		if err != nil {
			if textconv {
				fmt.Fprint(cmd.OutOrStdout(), string(content))
				return nil
			}
			return err
		}

		decrypted, defects, err := processor.DecryptContentWithDefects(cmd.Context(), content, dec, !stripMarkers)
		warnDefects(targetFile, content, defects)
		if err != nil {
			if textconv {
				fmt.Fprint(cmd.OutOrStdout(), string(content))
				return nil
			}
			return fmt.Errorf("failed to decrypt content: %w", err)
		}

		if inplace {
			err = os.WriteFile(targetFile, decrypted, 0644)
			if err != nil {
				return fmt.Errorf("failed to write file: %w", err)
			}
		} else {
			fmt.Fprint(cmd.OutOrStdout(), string(decrypted))
		}

		return nil
	},
}

func init() {
	decryptCmd.Flags().BoolVarP(&inplace, "inplace", "i", false, "modify the file in place")
	decryptCmd.Flags().BoolVar(&stripMarkers, "strip", false, "strip ENC[...] markers and show only plaintext")
	decryptCmd.Flags().BoolVar(&textconv, "textconv", false, "safely output original content on error (for git diff)")
	rootCmd.AddCommand(decryptCmd)
}
