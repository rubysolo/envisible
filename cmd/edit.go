package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

var editCmd = &cobra.Command{
	Use:   "edit [file]",
	Short: "Edit an encrypted file in your default editor",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetFile := filePath
		if len(args) > 0 {
			targetFile = args[0]
		}

		// 1. Load keys
		privKeyData, err := os.ReadFile(privKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}
		privKey, err := crypto.DecodeKey(string(privKeyData))
		if err != nil {
			return fmt.Errorf("failed to decode private key: %w", err)
		}

		pubKeyData, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read public key: %w", err)
		}
		pubKey, err := crypto.DecodeKey(string(pubKeyData))
		if err != nil {
			return fmt.Errorf("failed to decode public key: %w", err)
		}

		// 2. Read and decrypt
		content, err := os.ReadFile(targetFile)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to read file: %w", err)
		}
		if os.IsNotExist(err) {
			content = []byte{}
		}

		decrypted, err := processor.DecryptContent(content, privKey, true)
		if err != nil {
			return fmt.Errorf("failed to decrypt content: %w", err)
		}

		// 3. Create temp file
		tmpFile, err := os.CreateTemp("", "envisible-*")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		defer os.Remove(tmpPath)

		if _, err := tmpFile.Write(decrypted); err != nil {
			return fmt.Errorf("failed to write to temp file: %w", err)
		}
		tmpFile.Close()

		// 4. Open editor
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vim"
		}

		ui.Info("Opening %s in %s...", targetFile, editor)
		editorCmd := exec.Command(editor, tmpPath)
		editorCmd.Stdin = os.Stdin
		editorCmd.Stdout = cmd.OutOrStdout()
		editorCmd.Stderr = cmd.ErrOrStderr()
		if err := editorCmd.Run(); err != nil {
			return fmt.Errorf("editor failed: %w", err)
		}

		// 5. Read back and encrypt
		editedContent, err := os.ReadFile(tmpPath)
		if err != nil {
			return fmt.Errorf("failed to read edited content: %w", err)
		}

		encrypted, err := processor.EncryptContent(editedContent, pubKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt content: %w", err)
		}

		// 6. Write back to original file
		err = os.WriteFile(targetFile, encrypted, 0644)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}

		ui.Success("File %s updated and encrypted.", targetFile)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(editCmd)
}
