package cmd

import (
	"os"
	"strings"

	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	privKeyPath string
	pubKeyPath  string
	filePath    string

	// privKeyMaterial holds the v1 private key as base64 *material* (the same
	// string `keygen` writes), supplied via ENVISIBLE_KEY. An empty value means
	// "no material was supplied; fall back to the key file at privKeyPath".
	//
	// It is resolved in PersistentPreRunE and consumed by loadDecryptor. It must
	// never be interpolated into an error, a log line, or argv.
	privKeyMaterial string
)

var rootCmd = &cobra.Command{
	Use:           "envisible",
	Short:         "Envisible is a tool for managing encrypted secrets in environment files",
	Long:          `A CLI tool to manage encryption / decryption of sensitive data in env files (e.g. yaml, toml, json, .env) using explicit ENC[...] markers.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		resolveKeySources(cmd)
		return nil
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&privKeyPath, "key", "k", "", "path to private key file (default: envisible.key, or $ENVISIBLE_KEY_PATH)")
	rootCmd.PersistentFlags().StringVarP(&pubKeyPath, "pub", "p", "", "path to public key file (default: envisible.pub, or $ENVISIBLE_PUB_PATH)")
	rootCmd.PersistentFlags().StringVarP(&filePath, "file", "f", "", "path to env file (default: .env, or $ENVISIBLE_FILE)")
	rootCmd.PersistentFlags().BoolVarP(&ui.Quiet, "quiet", "q", false, "suppress informational output")
}

// resolveKeySources fills in privKeyPath, pubKeyPath, filePath and
// privKeyMaterial from the flags, the environment, and the built-in defaults.
//
// This deliberately runs at execute time rather than in init(): the private key
// resolution order needs to distinguish "--key was passed" from "the flag
// happens to hold the value of ENVISIBLE_KEY_PATH", and only
// cmd.Flags().Changed can tell those apart after parsing. The public key and env
// file paths are resolved in the same place so that all three defaults live
// together rather than being split across init() and here.
//
// Private key resolution order, highest wins:
//
//  1. --key / -k explicitly passed on the command line  (a path)
//  2. ENVISIBLE_KEY                                     (key material)
//  3. ENVISIBLE_KEY_PATH                                (a path)
//  4. envisible.key                                     (the default path)
func resolveKeySources(cmd *cobra.Command) {
	if !flagChanged(cmd, "key") {
		privKeyPath = envOrDefault("ENVISIBLE_KEY_PATH", "envisible.key")
	}
	if !flagChanged(cmd, "pub") {
		pubKeyPath = envOrDefault("ENVISIBLE_PUB_PATH", "envisible.pub")
	}
	if !flagChanged(cmd, "file") {
		filePath = envOrDefault("ENVISIBLE_FILE", ".env")
	}
	privKeyMaterial = resolvePrivateKeyMaterial(cmd)
}

// resolvePrivateKeyMaterial returns the private key material supplied via
// ENVISIBLE_KEY, or "" when none is available. An explicitly passed --key wins
// over the ambient env var, which gives an operator a way to override an
// inherited ENVISIBLE_KEY without unsetting it.
func resolvePrivateKeyMaterial(cmd *cobra.Command) string {
	if flagChanged(cmd, "key") {
		return ""
	}
	return strings.TrimSpace(os.Getenv("ENVISIBLE_KEY"))
}

// flagChanged reports whether the named flag was explicitly set on the command
// line. A nil command (or an unregistered flag) counts as "not passed".
func flagChanged(cmd *cobra.Command, name string) bool {
	if cmd == nil {
		return false
	}
	return cmd.Flags().Changed(name)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
