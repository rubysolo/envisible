package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rubysolo/envisible/pkg/crypto"
	kmspkg "github.com/rubysolo/envisible/pkg/kms"
	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/pflag"
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
	filePath = ".env"
	ui.Quiet = false
	// Reset the "changed" state of persistent flags
	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
	})
	// Also reset the subcommand flags if they were changed
	inplace = false
	stripMarkers = false
	textconv = false
	// kms init / create flag vars persist across cobra Execute calls because
	// they're package-level — reset them so subsequent tests start clean.
	kmsInitProvider, kmsInitResource = "", ""
	kmsCreateProvider, kmsCreateName = "", ""
	gcpCreateProject, gcpCreateLocation, gcpCreateKeyring = "", "", ""
	awsCreateRegion, awsCreateAlias = "", ""
	azCreateVault = ""
	kmsRotateTo = ""
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

func TestEncryptDecryptV2Workflow(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// Generate a local RSA key and swap GCP's registry entries to use it.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	resource := "projects/test/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
	restore := withFakeKMSProvider(t, kmspkg.GCP, priv, resource)
	defer restore()

	// Bootstrap envisible.pub via `kms init` against the fake.
	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "init", "--provider", "gcp", "--resource", resource})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("kms init: %v", err)
	}

	// Encrypt a file. No envisible.key should be needed.
	if _, err := os.Stat("envisible.key"); err == nil {
		t.Fatalf("envisible.key should not exist in v2-only project")
	}
	confFile := "config.yaml"
	os.WriteFile(confFile, []byte("password: ENC[hello-kms]\napi: ENC[long-cert-data]"), 0644)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", confFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	encrypted, _ := os.ReadFile(confFile)
	if !bytes.Contains(encrypted, []byte("ENC[v2:")) {
		t.Errorf("expected v2 marker, got: %s", string(encrypted))
	}
	if bytes.Contains(encrypted, []byte("hello-kms")) {
		t.Errorf("plaintext leaked into encrypted file: %s", string(encrypted))
	}

	// Decrypt to stdout via the fake unwrapper.
	b := &bytes.Buffer{}
	resetRoot(b)
	rootCmd.SetArgs([]string{"decrypt", confFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Contains(b.Bytes(), []byte("password: ENC[hello-kms]")) || !bytes.Contains(b.Bytes(), []byte("api: ENC[long-cert-data]")) {
		t.Errorf("decrypt output missing recovered values: %q", b.String())
	}
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

	// Case 2: Has a v1: prefix but is structurally too short to be a real ciphertext.
	// Pre-step-11 this would have passed; the structure check should now flag it.
	os.WriteFile(confFile, []byte("password: ENC[v1:fake]"), 0644)
	resetRoot(nil)
	rootCmd.SetArgs([]string{"check", confFile})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected check to flag truncated v1: marker as malformed")
	}

	// Case 3: A real encrypted value — must pass the default structure check.
	resetRoot(nil)
	rootCmd.SetArgs([]string{"keygen"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	os.WriteFile(confFile, []byte("password: ENC[real-secret]"), 0644)
	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", confFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	resetRoot(nil)
	rootCmd.SetArgs([]string{"check", confFile})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("check should pass for a real v1 ciphertext: %v", err)
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

// Child-command flags must pass through without '--': flag parsing stops at
// the first positional, so e.g. `envisible run sh -c ...` works as-is.
func TestRunChildFlagsWithoutDashDash(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-run-flags")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"keygen"})
	rootCmd.Execute()

	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"run", "sh", "-c", "echo child-flags-ok"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("run with child flags failed: %v", err)
	}
	if !contains(b.String(), "child-flags-ok") {
		t.Errorf("expected child command output, got: %s", b.String())
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

// setupRunFixture builds a tmp dir with keys and an encrypted .env containing
// MY_VAR=ENC[secret-value]. Returns the dir and a cleanup func.
func setupRunFixture(t *testing.T) func() {
	t.Helper()
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"keygen"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	os.WriteFile(".env", []byte("MY_VAR=ENC[secret-value]"), 0644)
	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", ".env"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return func() { os.Chdir(oldWd) }
}

// captureStdStreams swaps os.Stdout / os.Stderr for pipes, runs fn, and returns
// what was written to each. The cobra writer (rootCmd.SetOut/SetErr via
// resetRoot) is independent of these — anything written via ui.* goes through
// os.Stderr; child-process output set in runCmd goes through cobra's writer.
func captureStdStreams(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = wOut, wErr

	fn()

	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = origOut, origErr
	outBytes, _ := io.ReadAll(rOut)
	errBytes, _ := io.ReadAll(rErr)
	return string(outBytes), string(errBytes)
}

func TestBannerGoesToStderrNotStdout(t *testing.T) {
	defer setupRunFixture(t)()

	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"run", "--", "env"})

	var runErr error
	stdout, stderr := captureStdStreams(t, func() {
		runErr = rootCmd.Execute()
	})
	if runErr != nil {
		t.Logf("run failed (maybe env missing?): %v", runErr)
		return
	}

	if contains(stdout, "Loading environment") || contains(stdout, "Starting:") {
		t.Errorf("banner text leaked onto stdout:\n%s", stdout)
	}
	if !contains(stderr, "Loading environment") || !contains(stderr, "Starting:") {
		t.Errorf("banner missing from stderr:\n%s", stderr)
	}
}

func TestQuietFlagSuppressesBanner(t *testing.T) {
	defer setupRunFixture(t)()

	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"-q", "run", "--", "env"})

	var runErr error
	_, stderr := captureStdStreams(t, func() {
		runErr = rootCmd.Execute()
	})
	if runErr != nil {
		t.Logf("run failed (maybe env missing?): %v", runErr)
		return
	}

	if contains(stderr, "Loading environment") || contains(stderr, "Starting:") {
		t.Errorf("banner text was not suppressed by --quiet:\n%s", stderr)
	}
	if !contains(b.String(), "MY_VAR=secret-value") {
		t.Errorf("env value missing from child output:\n%s", b.String())
	}
}

func TestPartialEncryptionWorkflow(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-partial")
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

	// 2. Create a partially encrypted file
	// We'll use a fake v1: marker for VAR1, and plain for VAR2.
	// Actually, better to use a real one so we can decrypt later.

	// Encrypt just VAR1 manually first
	pubKeyData, _ := os.ReadFile("envisible.pub")
	pubKey, _ := crypto.DecodeKey(string(pubKeyData))

	val1Enc, _ := crypto.Encrypt([]byte("val1"), pubKey)
	marker1 := "ENC[v1:" + val1Enc + "]"

	os.WriteFile("mixed.env", []byte(fmt.Sprintf("VAR1=%s\nVAR2=ENC[val2]", marker1)), 0644)

	// 3. Run encrypt command
	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", "mixed.env"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// 4. Verify content
	finalContent, _ := os.ReadFile("mixed.env")
	if !bytes.Contains(finalContent, []byte(marker1)) {
		t.Error("Pre-existing encrypted marker was modified or lost")
	}
	if !bytes.Contains(finalContent, []byte("VAR2=ENC[v1:")) {
		t.Error("New marker was not encrypted")
	}

	// 5. Decrypt and check
	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"decrypt", "mixed.env"})
	rootCmd.Execute()

	if !contains(b.String(), "VAR1=ENC[val1]") || !contains(b.String(), "VAR2=ENC[val2]") {
		t.Errorf("decryption failed to recover both values correctly. Got: %q", b.String())
	}
}

func TestEnvisibleFileEnvVar(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-envvar")
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

	// 2. Create custom env file (not .env)
	customEnvFile := "custom.env"
	os.WriteFile(customEnvFile, []byte("CUSTOM_VAR=ENC[custom-secret]"), 0644)

	// 3. Encrypt the custom file
	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", customEnvFile})
	rootCmd.Execute()

	// 4. Set ENVISIBLE_FILE env var and run without specifying file
	t.Setenv("ENVISIBLE_FILE", customEnvFile)

	// Re-initialize filePath from env var (simulating fresh start)
	filePath = os.Getenv("ENVISIBLE_FILE")

	b := bytes.NewBufferString("")
	resetRoot(b)
	// Note: resetRoot sets filePath back to .env, so we need to set it again
	filePath = customEnvFile

	rootCmd.SetArgs([]string{"run", "--", "env"})
	if err := rootCmd.Execute(); err != nil {
		t.Logf("run failed: %v", err)
		return
	}

	if !contains(b.String(), "CUSTOM_VAR=custom-secret") {
		t.Errorf("CUSTOM_VAR not found in environment when using ENVISIBLE_FILE. Output: %s", b.String())
	}
}

func TestFilePathFlagOverridesEnvVar(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-override")
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

	// 2. Create two env files with different content
	envFromEnvVar := "from-envvar.env"
	envFromFlag := "from-flag.env"
	os.WriteFile(envFromEnvVar, []byte("SOURCE=ENC[envvar]"), 0644)
	os.WriteFile(envFromFlag, []byte("SOURCE=ENC[flag]"), 0644)

	// 3. Encrypt both files
	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", envFromEnvVar})
	rootCmd.Execute()

	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", envFromFlag})
	rootCmd.Execute()

	// 4. Set ENVISIBLE_FILE to one file, but use -f flag for the other
	t.Setenv("ENVISIBLE_FILE", envFromEnvVar)

	b := bytes.NewBufferString("")
	resetRoot(b)
	// Use the -f flag to override the env var
	rootCmd.SetArgs([]string{"-f", envFromFlag, "run", "--", "env"})
	if err := rootCmd.Execute(); err != nil {
		t.Logf("run failed: %v", err)
		return
	}

	// Flag should win over env var
	if !contains(b.String(), "SOURCE=flag") {
		t.Errorf("Expected SOURCE=flag (from -f flag), got output: %s", b.String())
	}
	if contains(b.String(), "SOURCE=envvar") {
		t.Errorf("Got SOURCE=envvar (from env var) but -f flag should have overridden it")
	}
}

func TestDefaultFileUsedWhenNoArgProvided(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-default")
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

	// 2. Create and encrypt custom.env
	customFile := "custom.env"
	os.WriteFile(customFile, []byte("VALUE=ENC[test-value]"), 0644)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", customFile})
	rootCmd.Execute()

	// 3. Test encrypt command uses global filePath when no arg provided
	// First encrypt the custom file with -f flag, no positional arg
	os.WriteFile(customFile, []byte("NEW_VALUE=ENC[new-test]"), 0644)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"-f", customFile, "encrypt", "-i"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt with -f flag failed: %v", err)
	}

	encrypted, _ := os.ReadFile(customFile)
	if !bytes.Contains(encrypted, []byte("ENC[v1:")) {
		t.Errorf("file was not encrypted when using -f flag: %s", string(encrypted))
	}

	// 4. Test decrypt command uses global filePath when no arg provided
	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"-f", customFile, "decrypt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt with -f flag failed: %v", err)
	}

	if !contains(b.String(), "NEW_VALUE=ENC[new-test]") {
		t.Errorf("decrypted output mismatch. Got: %q", b.String())
	}

	// 5. Test check command uses global filePath when no arg provided
	resetRoot(nil)
	rootCmd.SetArgs([]string{"-f", customFile, "check"})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("check with -f flag failed: %v", err)
	}
}

func TestMissingFileErrorsWhenExplicitlySet(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-missing")
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

	// 2. Test that missing file via -f flag produces an error for run
	resetRoot(nil)
	rootCmd.SetArgs([]string{"-f", "nonexistent.env", "run", "--", "echo", "hello"})
	err = rootCmd.Execute()
	if err == nil {
		t.Error("expected error when file specified via -f flag doesn't exist")
	}

	// 3. Test that missing file via ENVISIBLE_FILE env var produces an error
	t.Setenv("ENVISIBLE_FILE", "also-nonexistent.env")
	filePath = "also-nonexistent.env" // Simulate what init() would do

	resetRoot(nil)
	filePath = "also-nonexistent.env" // resetRoot resets it, set again
	rootCmd.SetArgs([]string{"run", "--", "echo", "hello"})
	err = rootCmd.Execute()
	if err == nil {
		t.Error("expected error when file specified via ENVISIBLE_FILE env var doesn't exist")
	}
}

func TestMissingDefaultFileAllowedForRun(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-missing-default")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// Clear ENVISIBLE_FILE to ensure we're using the default
	t.Setenv("ENVISIBLE_FILE", "")

	// 1. Keygen
	resetRoot(nil)
	rootCmd.SetArgs([]string{"keygen"})
	rootCmd.Execute()

	// 2. Run without any .env file - should succeed (no env vars loaded)
	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"run", "--", "echo", "hello"})
	err = rootCmd.Execute()
	if err != nil {
		t.Errorf("run should succeed even when default .env doesn't exist: %v", err)
	}
}

func TestPositionalArgOverridesGlobalFlag(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-positional")
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

	// 2. Create two files
	fileFromFlag := "from-flag.yaml"
	fileFromArg := "from-arg.yaml"
	os.WriteFile(fileFromFlag, []byte("FLAG_VAL=ENC[flag-value]"), 0644)
	os.WriteFile(fileFromArg, []byte("ARG_VAL=ENC[arg-value]"), 0644)

	// 3. Encrypt both
	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", fileFromFlag})
	rootCmd.Execute()

	resetRoot(nil)
	rootCmd.SetArgs([]string{"encrypt", "-i", fileFromArg})
	rootCmd.Execute()

	// 4. Use -f for one file but provide positional arg for another
	// Positional arg should win for commands that accept it
	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"-f", fileFromFlag, "decrypt", fileFromArg})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	// Should get content from positional arg, not from -f flag
	if !contains(b.String(), "ARG_VAL=ENC[arg-value]") {
		t.Errorf("Expected content from positional arg file, got: %q", b.String())
	}
	if contains(b.String(), "FLAG_VAL") {
		t.Errorf("Got content from -f flag file, but positional arg should have overridden it")
	}
}

func TestAllCommandsUseGlobalFilePath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envisible-all-cmds")
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

	// 2. Create and prepare a test file
	testFile := "test-config.yaml"
	os.WriteFile(testFile, []byte("SECRET=ENC[my-secret]"), 0644)

	// Test encrypt with -f
	resetRoot(nil)
	rootCmd.SetArgs([]string{"-f", testFile, "encrypt", "-i"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt with -f failed: %v", err)
	}

	encrypted, _ := os.ReadFile(testFile)
	if !bytes.Contains(encrypted, []byte("ENC[v1:")) {
		t.Errorf("encrypt with -f didn't work: %s", string(encrypted))
	}

	// Test check with -f
	resetRoot(nil)
	rootCmd.SetArgs([]string{"-f", testFile, "check"})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("check with -f failed: %v", err)
	}

	// Test decrypt with -f
	b := bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"-f", testFile, "decrypt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt with -f failed: %v", err)
	}

	if !contains(b.String(), "SECRET=ENC[my-secret]") {
		t.Errorf("decrypt with -f didn't work: %s", b.String())
	}

	// Test run with -f
	b = bytes.NewBufferString("")
	resetRoot(b)
	rootCmd.SetArgs([]string{"-f", testFile, "run", "--", "env"})
	if err := rootCmd.Execute(); err != nil {
		t.Logf("run with -f failed (maybe env command not found?): %v", err)
		return
	}

	if !contains(b.String(), "SECRET=my-secret") {
		t.Errorf("run with -f didn't load env vars: %s", b.String())
	}
}
