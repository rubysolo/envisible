package cmd

import (
	"fmt"

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

		content, isStdin, err := readTarget(cmd, targetFile)
		if err != nil {
			return err
		}
		name := targetName(targetFile)

		encrypted, defects, err := processor.EncryptContentWithDefects(content, enc)
		if err != nil {
			return fmt.Errorf("failed to encrypt content: %w", err)
		}
		// Write path: refuse to produce an artifact whose markers don't parse
		// the way they look. Nothing is written.
		if err := defectError(name, content, defects); err != nil {
			return err
		}
		// Parseable but ambiguous shapes. These do not stop the write — both
		// readings are legal grammar — but the author gets told which lines
		// just disappeared into a secret.
		warnAmbiguousMarkers(name, content)

		if inplace && !isStdin {
			if err := writeFileAtomic(targetFile, encrypted, newFileMode); err != nil {
				return err
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
