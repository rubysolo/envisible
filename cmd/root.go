package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	privKeyPath string
	pubKeyPath  string
)

var rootCmd = &cobra.Command{
	Use:   "envisible",
	Short: "Envisible is a tool for managing encrypted secrets in environment files",
	Long: `A CLI tool to manage encryption / decryption of sensitive data in env files 
(e.g. yaml, toml, json, .env) using explicit ENC[...] markers.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&privKeyPath, "key", os.Getenv("ENVISIBLE_KEY_PATH"), "path to private key file (default: envisible.key)")
	rootCmd.PersistentFlags().StringVar(&pubKeyPath, "pub", os.Getenv("ENVISIBLE_PUB_PATH"), "path to public key file (default: envisible.pub)")

	// Set defaults if not provided
	if privKeyPath == "" {
		privKeyPath = "envisible.key"
	}
	if pubKeyPath == "" {
		pubKeyPath = "envisible.pub"
	}
}
