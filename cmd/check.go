package cmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check [file]",
	Short: "Check for unencrypted ENC[...] markers",
	Long:  `Scans a file and exits with a non-zero status code if it finds any ENC[...] markers that do not appear to be encrypted (i.e., they don't start with 'v1:').`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}

		encRegex := regexp.MustCompile(`ENC\[(.*?)\]`)

		matches := encRegex.FindAllSubmatch(content, -1)
		unencryptedCount := 0

		for _, match := range matches {
			inner := string(match[1])
			if !strings.HasPrefix(inner, "v1:") {
				ui.Warn("Unencrypted value found: %s", match[0])
				unencryptedCount++
			}
		}

		if unencryptedCount > 0 {
			return fmt.Errorf("found %d unencrypted values in %s", unencryptedCount, filePath)
		}

		ui.Success("All ENC[...] markers in %s appear to be encrypted.", filePath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
