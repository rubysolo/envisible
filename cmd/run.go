package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/spf13/cobra"
)

var envFile string

var runCmd = &cobra.Command{
	Use:   "run -- [command]",
	Short: "Run a command with decrypted environment variables",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load and decrypt env file
		privKeyData, err := os.ReadFile(privKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}
		
		privKey, err := crypto.DecodeKey(string(privKeyData))
		if err != nil {
			return fmt.Errorf("failed to decode private key: %w", err)
		}

		content, err := os.ReadFile(envFile)
		if err != nil {
			// If default .env is missing, maybe it's fine?
			// But if explicitly provided and missing, it's an error.
			if envFile != ".env" || !os.IsNotExist(err) {
				return fmt.Errorf("failed to read env file: %w", err)
			}
			// If .env is missing, just continue with current env
			content = []byte{}
		}

		extraEnv, err := processor.ExtractEnv(content, privKey)
		if err != nil {
			return fmt.Errorf("failed to process env file: %w", err)
		}

		// Prepare command
		childCmd := exec.Command(args[0], args[1:]...)
		childCmd.Env = os.Environ()
		for k, v := range extraEnv {
			childCmd.Env = append(childCmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
		childCmd.Stdin = os.Stdin
		childCmd.Stdout = cmd.OutOrStdout()
		childCmd.Stderr = cmd.ErrOrStderr()

		// Handle signals
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigs
			if childCmd.Process != nil {
				childCmd.Process.Signal(sig)
			}
		}()

		err = childCmd.Run()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return err
		}

		return nil
	},
}

func init() {
	runCmd.Flags().StringVarP(&envFile, "env", "e", ".env", "env file to load")
	rootCmd.AddCommand(runCmd)
}
