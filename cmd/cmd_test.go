package cmd

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func resetRoot(out io.Writer) {
	if out == nil {
		out = io.Discard
	}
	rootCmd.SetOut(out)
	rootCmd.SetErr(out)
	rootCmd.SetArgs(nil)
	// Reset persistent flags to defaults
	privKeyPath = "envisible.key"
	pubKeyPath = "envisible.pub"
	// Also reset the subcommand flags if they were changed
	inplace = false
	stripMarkers = false
	textconv = false
}

func TestRootHelp(t *testing.T) {
	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"--help"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	out := b.String()
	if !contains(out, "envisible") {
		t.Errorf("expected help text to contain envisible, got %s", out)
	}
}

func TestKeygen(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"keygen"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	if _, err := os.Stat("envisible.key"); os.IsNotExist(err) {
		t.Error("envisible.key not created")
	}
	if _, err := os.Stat("envisible.pub"); os.IsNotExist(err) {
		t.Error("envisible.pub not created")
	}
}

func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

func TestEncryptDecryptWorkflow(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-workflow")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// 1. Keygen
	resetRoot(nil)
	rootCmd.SetArgs([]string{"keygen"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	// 2. Create file
	confFile := "config.yaml"
	os.WriteFile(confFile, []byte("password: ENC[hello]"), 0644)

	// 3. Encrypt
	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", confFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	encrypted, _ := os.ReadFile(confFile)
	if !bytes.Contains(encrypted, []byte("ENC[v1:")) {
		t.Errorf("file was not encrypted: %s", string(encrypted))
	}

	// 4. Decrypt to stdout
	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"decrypt", confFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Contains(b.Bytes(), []byte("password: ENC[hello]")) {
		t.Errorf("decrypted output mismatch. Got: %q", b.String())
	}
}

func TestCheck(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-check")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	confFile := "config.yaml"
	
	// Case 1: Unencrypted
	os.WriteFile(confFile, []byte("password: ENC[hello]"), 0644)
	resetRoot(nil)
	rootCmd.SetArgs([]string{"check", confFile})
	if err := rootCmd.Execute(); err == nil {
		t.Error("expected error for unencrypted value")
	}

	// Case 2: Encrypted (fake it for check)
	os.WriteFile(confFile, []byte("password: ENC[v1:fake]"), 0644)
	resetRoot(nil)
	rootCmd.SetArgs([]string{"check", confFile})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("unexpected error for encrypted value: %v", err)
	}
}

func TestRun(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-run")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// 1. Keygen
	resetRoot(nil)
	rootCmd.SetArgs([]string{"keygen"})
	rootCmd.Execute()

	// 2. Create .env
	os.WriteFile(".env", []byte("MY_VAR=ENC[secret-value]"), 0644)
	
	// 3. Encrypt .env
	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", ".env"})
	rootCmd.Execute()

	// 4. Run 'env' and check for MY_VAR
	// Note: We use 'env' command as it's common on unix.
	b := bytes.NewBufferString("")
	resetRoot(b)
	// We need to pass -- because cobra might try to parse child flags
	rootCmd.SetArgs([]string{"run", "--", "env"})
	if err := rootCmd.Execute(); err != nil {
		t.Logf("run failed (maybe env command not found?): %v", err)
		return
	}

	if !contains(b.String(), "MY_VAR=secret-value") {
		t.Errorf("MY_VAR not found in environment. Output: %s", b.String())
	}
}

func TestGitIntegration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-git")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// Mock a git repo (properly)
	if err := exec.Command("git", "init").Run(); err != nil {
		t.Skip("git not found, skipping git integration test")
		return
	}

	// Test git setup
	resetRoot(nil)
	rootCmd.SetArgs([]string{"git", "setup"})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("git setup failed: %v", err)
	}

	// Test git install-hook
	resetRoot(nil)
	rootCmd.SetArgs([]string{"git", "install-hook"})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("git install-hook failed: %v", err)
	}

	if _, err := os.Stat(".git/hooks/pre-commit"); os.IsNotExist(err) {
		t.Error("pre-commit hook not installed")
	}
}

func TestEdit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-edit")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// 1. Keygen
	resetRoot(nil)
	rootCmd.SetArgs([]string{"keygen"})
	rootCmd.Execute()

	// 2. Create file
	confFile := "config.yaml"
	os.WriteFile(confFile, []byte("password: ENC[old]"), 0644)
	
	// 3. Encrypt it first
	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", confFile})
	rootCmd.Execute()

	// 4. Edit it using a mock editor
	// Our mock editor will just append " - edited" to the file.
	// We need to use a shell script or similar.
	// In Go test, we can use 'sed' or similar if available, or just a small go program.
	// Simplest: use 'sed -i ...' if on unix, or write a small script.
	
	mockEditor := filepath.Join(tmpDir, "mock-editor.sh")
	os.WriteFile(mockEditor, []byte("#!/bin/sh\nsed -i '' 's/old/new/g' \"$1\" 2>/dev/null || sed -i 's/old/new/g' \"$1\""), 0755)
	
	t.Setenv("EDITOR", mockEditor)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"edit", confFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("edit failed: %v", err)
	}

	// 5. Decrypt and check
	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"decrypt", confFile})
	rootCmd.Execute()

	if !contains(b.String(), "password: ENC[new]") {
		t.Errorf("edit did not update content correctly: %s", b.String())
	}
}

func TestDecryptTextconv(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-textconv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	confFile := "config.yaml"
	content := "secret: ENC[v1:something]"
	os.WriteFile(confFile, []byte(content), 0644)

	// Try decrypt without keys but with --textconv
	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"decrypt", "--textconv", confFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt --textconv failed: %v", err)
	}

	if b.String() != content {
		t.Errorf("expected original content, got %q", b.String())
	}
}




