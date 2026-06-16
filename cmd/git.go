package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var gitCmd = &cobra.Command{
	Use:   "git",
	Short: "Git integration commands",
	Long:  `Helper commands to integrate Envisible with Git.`,
}

var gitSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure git diff to show decrypted secrets",
	Long: `Configures local git repository to use 'envisible decrypt --textconv' as a diff driver.
This allows 'git diff' to show decrypted values instead of ciphertext.

This command executes:
  git config diff.envisible.textconv "envisible decrypt --textconv"
  git config diff.envisible.cachetextconv true
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check if we are in a git repo
		if _, err := os.Stat(".git"); os.IsNotExist(err) {
			return fmt.Errorf("not a git repository (no .git directory found)")
		}

		// Configure textconv
		fmt.Fprintln(cmd.OutOrStdout(), "Configuring git diff driver...")

		if err := runGit("config", "diff.envisible.textconv", "envisible decrypt --textconv"); err != nil {
			return fmt.Errorf("failed to set diff.envisible.textconv: %w", err)
		}

		if err := runGit("config", "diff.envisible.cachetextconv", "true"); err != nil {
			return fmt.Errorf("failed to set diff.envisible.cachetextconv: %w", err)
		}

		fmt.Fprintln(cmd.OutOrStdout(), "Git configuration updated.")
		fmt.Fprintln(cmd.OutOrStdout(), "\nTo enable this for your files, add the following to your .gitattributes file:")
		fmt.Fprintln(cmd.OutOrStdout(), "\n  *.yaml diff=envisible")
		fmt.Fprintln(cmd.OutOrStdout(), "  *.json diff=envisible")
		fmt.Fprintln(cmd.OutOrStdout(), "  .env diff=envisible")

		// Optional: Check if .gitattributes exists and suggest checking it
		if _, err := os.Stat(".gitattributes"); err == nil {
			fmt.Fprintln(cmd.OutOrStdout(), "\n(Found existing .gitattributes)")
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "\n(.gitattributes does not exist yet)")
		}

		return nil
	},
}

func runGit(args ...string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	c := exec.Command("git", args...)
	c.Dir = wd
	return c.Run()
}

var gitInstallHookCmd = &cobra.Command{
	Use:   "install-hook",
	Short: "Install pre-commit hook",
	Long:  `Installs a git pre-commit hook that runs 'envisible check' to prevent committing unencrypted secrets.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := os.Stat(".git"); os.IsNotExist(err) {
			return fmt.Errorf("not a git repository")
		}

		hookDir := filepath.Join(".git", "hooks")
		if err := os.MkdirAll(hookDir, 0755); err != nil {
			return fmt.Errorf("failed to create hooks directory: %w", err)
		}

		hookPath := filepath.Join(hookDir, "pre-commit")

		// Simple hook script
		script := `#!/bin/sh
	# envisible pre-commit hook
	# Checks for unencrypted ENC[...] markers
	
	if command -v envisible >/dev/null 2>&1;
	 then
	    # Find all staged files that we want to check.
	    # For simplicity, we'll check files that might contain secrets.
	    # A better approach usually involves checking 'git diff --cached --name-only'
	    
	    # We will run 'envisible check' on modified files.
	    # This loop gets staged files
	    FILES=$(git diff --cached --name-only --diff-filter=ACM)
	    
	    if [ -n "$FILES" ]; then
	        # Check only if we have files.
	        # We process line by line to handle spaces in filenames (mostly)
	        # but for simplicity passing to envisible check individually or in batch.
	        
	        # We need to distinguish binary files or ignored files, but 'envisible check' scans text.
	        # Let's just try checking them.
	        
	        PASS=true
	        for file in $FILES;
	         do
	             # Only check files that exist (they should, as per diff filter)
	             if [ -f "$file" ]; then
	                 if ! envisible check "$file" >/dev/null; then
	                     echo "Envisible: Unencrypted secrets found in $file"
	                     PASS=false
	                 fi
	             fi
	        done
	        
	        if [ "$PASS" = "false" ]; then
	            echo "Commit rejected."
	            exit 1
	        fi
	    fi
	else
	    echo "Warning: envisible not found in PATH. Skipping pre-commit check."
	fi
	
	exit 0
	`
		// Check if hook already exists
		if _, err := os.Stat(hookPath); err == nil {
			return fmt.Errorf("pre-commit hook already exists at %s. Please edit manually", hookPath)
		}

		if err := os.WriteFile(hookPath, []byte(script), 0755); err != nil {
			return fmt.Errorf("failed to write pre-commit hook: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Pre-commit hook installed to %s\n", hookPath)
		return nil
	},
}

func init() {
	gitCmd.AddCommand(gitSetupCmd)
	gitCmd.AddCommand(gitInstallHookCmd)
	rootCmd.AddCommand(gitCmd)
}
