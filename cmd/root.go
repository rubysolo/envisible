package cmd

import (
	"os"

	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	privKeyPath string
	pubKeyPath  string
	filePath    string
)

var rootCmd = &cobra.Command{
	Use:           "envisible",
	Short:         "Envisible is a tool for managing encrypted secrets in environment files",
	Long:          `A CLI tool to manage encryption / decryption of sensitive data in env files (e.g. yaml, toml, json, .env) using explicit ENC[...] markers.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&privKeyPath, "key", "k", os.Getenv("ENVISIBLE_KEY_PATH"), "path to private key file (default: envisible.key)")
	rootCmd.PersistentFlags().StringVarP(&pubKeyPath, "pub", "p", os.Getenv("ENVISIBLE_PUB_PATH"), "path to public key file (default: envisible.pub)")
	rootCmd.PersistentFlags().StringVarP(&filePath, "file", "f", os.Getenv("ENVISIBLE_FILE"), "path to env file (default: .env)")
	rootCmd.PersistentFlags().BoolVarP(&ui.Quiet, "quiet", "q", false, "suppress informational output")

	// Set defaults if not provided
	if privKeyPath == "" {
		privKeyPath = "envisible.key"
	}
	if pubKeyPath == "" {
		pubKeyPath = "envisible.pub"
	}
	if filePath == "" {
		filePath = ".env"
	}
}
