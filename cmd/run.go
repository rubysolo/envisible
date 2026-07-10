package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run [command]",
	Short: "Run a command with decrypted environment variables",
	Long: `Run a command with decrypted environment variables.

Flag parsing stops at the command, so the child command's own flags pass
through untouched:

  envisible run ruby -r./config/environment script.rb
  envisible run -f prod.env -- printenv DATABASE_URL

envisible's own flags (-f, -k) must come before the command; a '--'
separator is accepted but not required.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dec, err := loadDecryptor(cmd.Context())
		if err != nil {
			return err
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			// If .env default (no env var set, no flag) is missing, maybe it's fine?
			// But if explicitly provided via flag or ENVISIBLE_FILE env var and missing, it's an error.
			defaultNotSet := os.Getenv("ENVISIBLE_FILE") == "" && !cmd.Flags().Changed("file")
			if !defaultNotSet || !os.IsNotExist(err) {
				return fmt.Errorf("failed to read env file: %w", err)
			}
			// If default .env is missing, just continue with current env
			content = []byte{}
		} else {
			ui.Info("Loading environment from %s", filePath)
		}

		extraEnv, err := processor.ExtractEnv(cmd.Context(), content, dec)
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

		ui.Success("Starting: %s", strings.Join(args, " "))
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
	// Stop flag parsing at the first positional so the child command's flags
	// (e.g. `ruby -e ...`) are never mistaken for envisible flags.
	runCmd.Flags().SetInterspersed(false)
	rootCmd.AddCommand(runCmd)
}
