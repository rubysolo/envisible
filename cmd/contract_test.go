package cmd

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	envcrypto "github.com/rubysolo/envisible/pkg/crypto"
)

// --- plan 10: the CLI's documented contracts ----------------------------------

// printMyVar is a child command for `run` that echoes MY_VAR with no trailing
// newline, so the child's stdout is exactly the decrypted value.
var printMyVar = []string{"sh", "-c", `printf '%s' "$MY_VAR"`}

// TestPayloadGoesToStdoutAndChatterToStderr pins the stream contract from
// AGENTS.md for every command that produces a payload: the payload is on stdout
// and not on stderr, and under -q stderr is empty, so `$(envisible ...)` and
// pipes stay clean.
func TestPayloadGoesToStdoutAndChatterToStderr(t *testing.T) {
	const secret = "stream-secret"

	cases := []struct {
		name  string
		stdin string
		args  []string
		// want must appear on stdout and must not appear on stderr. Empty means
		// the whole of stdout is the payload (keygen --print-key).
		want string
		// wantErr: `set --dry-run` exits non-zero when it would change something.
		wantErr bool
	}{
		{name: "decrypt", args: []string{"decrypt", ".env"}, want: "MY_VAR=ENC[" + secret + "]"},
		{name: "decrypt --strip", args: []string{"decrypt", "--strip", ".env"}, want: "MY_VAR=" + secret},
		{name: "encrypt -", stdin: "password: ENC[hello]\n", args: []string{"encrypt", "-"}, want: "password: ENC[v1:"},
		{name: "keygen --print-key", args: []string{"keygen", "--print-key"}},
		{
			name:    "set --dry-run",
			stdin:   `{"BRAND_NEW":"b"}`,
			args:    []string{"set", ".env", "--dry-run", "--from-json", "-"},
			want:    "added\tBRAND_NEW\t.env\n",
			wantErr: true,
		},
		{name: "run -- printf", args: append([]string{"run", "--"}, printMyVar...), want: secret},
	}

	for _, c := range cases {
		for _, quiet := range []bool{false, true} {
			name := c.name
			args := c.args
			if quiet {
				name += " -q"
				args = append([]string{"-q"}, args...)
			}
			t.Run(name, func(t *testing.T) {
				f := newEnvFileFixture(t, ".env", secret)
				f.writeKeyFile(t, "envisible.key", f.priv)
				withKeygenStdoutTTY(t, false)
				// resetSet rather than resetRoot: it also clears `set`'s own
				// flags, so --dry-run cannot leak into a later test.
				t.Cleanup(func() { resetSet(t, nil, "") })

				var out bytes.Buffer
				resetSet(t, &out, c.stdin)
				stdout, stderr, err := executeRoot(t, &out, args...)
				if (err != nil) != c.wantErr {
					t.Fatalf("err = %v, want an error: %v", err, c.wantErr)
				}

				want := c.want
				if want == "" {
					want = strings.TrimSuffix(stdout, "\n")
					if _, err := envcrypto.DecodeKey(want); err != nil {
						t.Fatalf("stdout %q is not a private key: %v", stdout, err)
					}
				}
				if !strings.Contains(stdout, want) {
					t.Errorf("payload missing from stdout:\nstdout %q\nstderr %q", stdout, stderr)
				}
				if strings.Contains(stderr, want) {
					t.Errorf("payload reached stderr: %q", stderr)
				}
				if quiet && stderr != "" {
					t.Errorf("-q left output on stderr: %q", stderr)
				}
			})
		}
	}
}

// TestVersionPrintsToTheCommandsStdout: the version line is the payload, and it
// goes through cobra's writer rather than straight to os.Stdout.
func TestVersionPrintsToTheCommandsStdout(t *testing.T) {
	var out bytes.Buffer
	resetRoot(&out)
	rootCmd.SetArgs([]string{"version"})
	var err error
	rawStdout, stderr := captureStdStreams(t, func() { err = rootCmd.Execute() })
	if err != nil {
		t.Fatalf("version: %v", err)
	}

	if want := "envisible " + Version + " (" + Commit + ") " + Date + "\n"; out.String() != want {
		t.Errorf("stdout = %q, want %q", out.String(), want)
	}
	if rawStdout != "" {
		t.Errorf("version bypassed the command's writer: %q", rawStdout)
	}
	if stderr != "" {
		t.Errorf("version wrote to stderr: %q", stderr)
	}
}

// newEnvFileFixture is newEnvKeyFixture with the sealed file under a name of the
// caller's choosing and a value of the caller's choosing. No .env is left behind
// unless name is ".env", so a command that falls back to the default finds
// nothing.
func newEnvFileFixture(t *testing.T, name, value string) envKeyFixture {
	t.Helper()
	f := newEnvKeyFixture(t)
	if err := os.Remove(".env"); err != nil {
		t.Fatal(err)
	}
	f.writeEnvFile(t, name, value)
	return f
}

// writeEnvFile writes name holding MY_VAR sealed to the fixture's public key.
func (f envKeyFixture) writeEnvFile(t *testing.T, name, value string) {
	t.Helper()
	pubData, err := os.ReadFile(filepath.Join(f.dir, "envisible.pub"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := envcrypto.DecodeKey(string(pubData))
	if err != nil {
		t.Fatal(err)
	}
	env := "MY_VAR=ENC[" + sealV1(t, pub, value) + "]\n"
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestEnvFileResolution pins "--file / -f, then ENVISIBLE_FILE, then .env" the
// way TestKeySourcePrecedence pins the key sources: the secret lives only in the
// file the winning source names, and no .env exists, so a command that ignores
// the source either fails or reads the wrong value.
func TestEnvFileResolution(t *testing.T) {
	const wrongValue = "from-the-wrong-file"

	fixture := func(t *testing.T) envKeyFixture {
		f := newEnvFileFixture(t, "custom.env", envKeyFixtureSecret)
		f.writeKeyFile(t, "envisible.key", f.priv)
		return f
	}

	t.Run("ENVISIBLE_FILE is the target of decrypt", func(t *testing.T) {
		fixture(t)
		t.Setenv("ENVISIBLE_FILE", "custom.env")

		stdout, _, err := runRoot(t, "decrypt", "--strip")
		assertDecryptsWithRightKey(t, stdout, err)
	})

	t.Run("ENVISIBLE_FILE is the env file of run", func(t *testing.T) {
		fixture(t)
		t.Setenv("ENVISIBLE_FILE", "custom.env")

		stdout, _, err := runRoot(t, append([]string{"-q", "run", "--"}, printMyVar...)...)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if stdout != envKeyFixtureSecret {
			t.Errorf("child saw MY_VAR=%q, want %q", stdout, envKeyFixtureSecret)
		}
	})

	t.Run("ENVISIBLE_FILE is the target of set", func(t *testing.T) {
		fixture(t)
		t.Setenv("ENVISIBLE_FILE", "custom.env")

		if err, _, _ := runSet(t, "new-value", "NEW_KEY", "-"); err != nil {
			t.Fatalf("set: %v", err)
		}
		if got := envOf(t, "custom.env")["NEW_KEY"]; got != "new-value" {
			t.Errorf("NEW_KEY in custom.env = %q, want %q", got, "new-value")
		}
		if _, err := os.Stat(".env"); !os.IsNotExist(err) {
			t.Errorf("set wrote the default .env instead of $ENVISIBLE_FILE, stat err = %v", err)
		}
	})

	for _, flag := range []string{"-f", "--file"} {
		t.Run(flag+" beats ENVISIBLE_FILE", func(t *testing.T) {
			f := fixture(t)
			f.writeEnvFile(t, "wrong.env", wrongValue)
			t.Setenv("ENVISIBLE_FILE", "wrong.env")

			stdout, _, err := runRoot(t, flag, "custom.env", "decrypt", "--strip")
			assertDecryptsWithRightKey(t, stdout, err)
			if contains(stdout, wrongValue) {
				t.Errorf("%s lost to ENVISIBLE_FILE: %q", flag, stdout)
			}
		})
	}

	t.Run("ENVISIBLE_FILE beats .env", func(t *testing.T) {
		f := fixture(t)
		f.writeEnvFile(t, ".env", wrongValue)
		t.Setenv("ENVISIBLE_FILE", "custom.env")

		stdout, _, err := runRoot(t, "decrypt", "--strip")
		assertDecryptsWithRightKey(t, stdout, err)
		if contains(stdout, wrongValue) {
			t.Errorf("ENVISIBLE_FILE lost to .env: %q", stdout)
		}
	})
}

// TestPublicKeyResolution pins "--pub / -p, then ENVISIBLE_PUB_PATH, then
// envisible.pub". The right keypair lives under keys/, away from the default
// path, and every source that should lose names a different keypair's public
// key. Decrypting what `encrypt -` produced with the right private key shows
// which public key was used.
func TestPublicKeyResolution(t *testing.T) {
	const plaintext = "V=ENC[pub-secret]\n"

	// fixture leaves keys/x.pub + keys/x.key (right) and keys/other.pub +
	// keys/other.key (wrong) in a fresh working dir with no envisible.pub.
	fixture := func(t *testing.T) {
		t.Helper()
		t.Chdir(t.TempDir())
		if err := os.Mkdir("keys", 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"x", "other"} {
			pub, priv := mustKeypair(t)
			writeFile(t, filepath.Join("keys", name+".pub"), envcrypto.EncodeKey(pub), 0o644)
			writeFile(t, filepath.Join("keys", name+".key"), envcrypto.EncodeKey(priv), 0o600)
		}
	}

	// opensWith decrypts ciphertext using the named private key file.
	opensWith := func(t *testing.T, ciphertext, keyFile string) (string, error) {
		t.Helper()
		stdout, _, err := runRootWithStdin(t, ciphertext, "-k", keyFile, "decrypt", "--strip", "-")
		return stdout, err
	}

	assertSealedToX := func(t *testing.T, ciphertext string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("encrypt failed (was the public key source ignored?): %v", err)
		}
		if contains(ciphertext, "pub-secret") {
			t.Fatalf("encrypt left the plaintext in its output: %q", ciphertext)
		}
		got, err := opensWith(t, ciphertext, "keys/x.key")
		if err != nil {
			t.Fatalf("keys/x.key cannot open the output, so another public key was used: %v", err)
		}
		if got != "V=pub-secret\n" {
			t.Errorf("decrypted %q, want %q", got, "V=pub-secret\n")
		}
		// The control: a key that should not open it does not.
		if got, err := opensWith(t, ciphertext, "keys/other.key"); err == nil {
			t.Errorf("keys/other.key opened the output too: %q", got)
		}
	}

	t.Run("ENVISIBLE_PUB_PATH", func(t *testing.T) {
		fixture(t)
		t.Setenv("ENVISIBLE_PUB_PATH", "keys/x.pub")

		stdout, _, err := runRootWithStdin(t, plaintext, "encrypt", "-")
		assertSealedToX(t, stdout, err)
	})

	for _, flag := range []string{"-p", "--pub"} {
		t.Run(flag, func(t *testing.T) {
			fixture(t)

			stdout, _, err := runRootWithStdin(t, plaintext, flag, "keys/x.pub", "encrypt", "-")
			assertSealedToX(t, stdout, err)
		})

		t.Run(flag+" beats ENVISIBLE_PUB_PATH", func(t *testing.T) {
			fixture(t)
			t.Setenv("ENVISIBLE_PUB_PATH", "keys/other.pub")

			stdout, _, err := runRootWithStdin(t, plaintext, flag, "keys/x.pub", "encrypt", "-")
			assertSealedToX(t, stdout, err)
		})
	}

	t.Run("ENVISIBLE_PUB_PATH beats envisible.pub", func(t *testing.T) {
		fixture(t)
		writeFile(t, "envisible.pub", string(readFile(t, "keys/other.pub")), 0o644)
		t.Setenv("ENVISIBLE_PUB_PATH", "keys/x.pub")

		stdout, _, err := runRootWithStdin(t, plaintext, "encrypt", "-")
		assertSealedToX(t, stdout, err)
	})

	t.Run("envisible.pub is the default", func(t *testing.T) {
		fixture(t)
		writeFile(t, "envisible.pub", string(readFile(t, "keys/x.pub")), 0o644)

		stdout, _, err := runRootWithStdin(t, plaintext, "encrypt", "-")
		assertSealedToX(t, stdout, err)
	})
}

// newWrongKeyFixture is a working dir whose .env is sealed to one keypair while
// envisible.key holds another: a key is present, loads fine, and cannot open
// the value.
func newWrongKeyFixture(t *testing.T) envKeyFixture {
	t.Helper()
	f := newEnvKeyFixture(t)
	_, wrong := mustKeypair(t)
	f.writeKeyFile(t, "envisible.key", wrong)
	return f
}

// TestCheckVerifyReportsAValueTheKeyCannotOpen: the marker is well-formed, so
// only --verify can tell it is sealed to a key nobody here holds.
func TestCheckVerifyReportsAValueTheKeyCannotOpen(t *testing.T) {
	// --verify is a package-level flag var that resetRoot does not clear.
	t.Cleanup(func() { verify = false })
	const verified = "are encrypted and verified"

	t.Run("wrong key", func(t *testing.T) {
		newWrongKeyFixture(t)

		// Without --verify the structure checks pass: this is the gap it closes.
		if _, _, err := runRoot(t, "check", ".env"); err != nil {
			t.Fatalf("plain check should pass on a well-formed marker: %v", err)
		}

		_, stderr, err := runRoot(t, "check", "--verify", ".env")
		if err == nil {
			t.Fatalf("check --verify passed on a value the key cannot open; stderr %q", stderr)
		}
		if !contains(err.Error(), "found 1 invalid/corrupt values in .env") {
			t.Errorf("error should count the invalid/corrupt value: %v", err)
		}
		if !contains(stderr, "Verification failed") {
			t.Errorf("stderr should name the failing marker: %q", stderr)
		}
		if contains(stderr, verified) || contains(stderr, "look well-formed") {
			t.Errorf("success line printed alongside a failure: %q", stderr)
		}
	})

	t.Run("right key", func(t *testing.T) {
		f := newEnvKeyFixture(t)
		f.writeKeyFile(t, "envisible.key", f.priv)

		_, stderr, err := runRoot(t, "check", "--verify", ".env")
		if err != nil {
			t.Fatalf("check --verify: %v", err)
		}
		if !contains(stderr, verified) {
			t.Errorf("success line missing from stderr: %q", stderr)
		}
	})
}

// TestDecryptTextconvFallsBackWhenDecryptionFails: git runs the textconv driver
// for every diff, on every clone. With a key that loads but cannot open the
// file, the diff must degrade to the raw ciphertext rather than break.
func TestDecryptTextconvFallsBackWhenDecryptionFails(t *testing.T) {
	newWrongKeyFixture(t)
	raw := string(readFile(t, ".env"))

	// Without --textconv the same input is an error.
	if _, _, err := runRoot(t, "decrypt", ".env"); err == nil {
		t.Fatal("fixture is wrong: decrypt succeeded with a key that should not open .env")
	}

	stdout, _, err := runRoot(t, "decrypt", "--textconv", ".env")
	if err != nil {
		t.Fatalf("decrypt --textconv must exit 0 when decryption fails: %v", err)
	}
	if stdout != raw {
		t.Errorf("stdout = %q, want the raw content %q", stdout, raw)
	}
}

// isolateGit keeps real `git` invocations from reading the developer's global
// and system config. An init.templateDir that ships its own pre-commit hook, for
// one, makes `install-hook` refuse.
func isolateGit(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_TEMPLATE_DIR", "")
}

// initGitRepo chdirs into a fresh, isolated git repository.
func initGitRepo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}
	isolateGit(t)
	t.Chdir(t.TempDir())
	mustGit(t, "init")
}

// mustGit runs git in the working dir and returns its trimmed stdout.
func mustGit(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

// TestGitSetupConfiguresTheDiffDriver reads the config back: the driver command
// is what git will execute, so its exact text is the contract.
func TestGitSetupConfiguresTheDiffDriver(t *testing.T) {
	initGitRepo(t)

	stdout, stderr, err := runRoot(t, "git", "setup")
	if err != nil {
		t.Fatalf("git setup: %v", err)
	}
	if got, want := mustGit(t, "config", "diff.envisible.textconv"), "envisible decrypt --textconv"; got != want {
		t.Errorf("diff.envisible.textconv = %q, want %q", got, want)
	}
	if got := mustGit(t, "config", "diff.envisible.cachetextconv"); got != "true" {
		t.Errorf("diff.envisible.cachetextconv = %q, want %q", got, "true")
	}

	// The progress banner is chatter: stderr, and silenced by -q.
	const banner = "Configuring git diff driver"
	if contains(stdout, banner) {
		t.Errorf("banner on stdout: %q", stdout)
	}
	if !contains(stderr, banner) {
		t.Errorf("banner missing from stderr: %q", stderr)
	}
	if _, stderr, err := runRoot(t, "-q", "git", "setup"); err != nil || stderr != "" {
		t.Errorf("-q git setup: err = %v, stderr = %q, want none", err, stderr)
	}
}

// testPkgDir is the package directory, captured before any test chdirs away.
var testPkgDir, _ = os.Getwd()

var (
	cliBuildOnce sync.Once
	cliBinDir    string // removed by TestMain
	cliBuildErr  error
)

// builtCLIDir builds the envisible binary once per test process and returns the
// directory holding it, for tests that need `envisible` on PATH.
func builtCLIDir(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not found on PATH; cannot build envisible for the hook to call")
	}
	cliBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "envisible-cli")
		if err != nil {
			cliBuildErr = err
			return
		}
		cliBinDir = dir
		build := exec.Command("go", "build", "-o", filepath.Join(dir, "envisible"), ".")
		build.Dir = filepath.Dir(testPkgDir)
		if out, err := build.CombinedOutput(); err != nil {
			cliBuildErr = errors.New("go build: " + err.Error() + "\n" + string(out))
		}
	})
	if cliBuildErr != nil {
		t.Fatalf("building envisible: %v", cliBuildErr)
	}
	return cliBinDir
}

// runPreCommitHook executes the installed hook the way git would and returns
// its exit code and combined output.
func runPreCommitHook(t *testing.T) (int, string) {
	t.Helper()
	out, err := exec.Command(filepath.Join(".git", "hooks", "pre-commit")).CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), string(out)
	default:
		t.Fatalf("running the pre-commit hook: %v", err)
		return 0, ""
	}
}

// TestPreCommitHookBlocksUnencryptedSecrets runs the installed hook script
// against a real index, with a real envisible on PATH: rejected while a staged
// file holds a plaintext marker, accepted once it is encrypted.
func TestPreCommitHookBlocksUnencryptedSecrets(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not found on PATH; the hook is a shell script")
	}
	binDir := builtCLIDir(t)
	initGitRepo(t)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if _, _, err := runRoot(t, "keygen"); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, _, err := runRoot(t, "git", "install-hook"); err != nil {
		t.Fatalf("git install-hook: %v", err)
	}

	writeFile(t, "secrets.env", "API_KEY=ENC[plaintext]\n", 0o644)
	mustGit(t, "add", "secrets.env")

	code, out := runPreCommitHook(t)
	if code != 1 {
		t.Errorf("hook exit code = %d with an unencrypted secret staged, want 1\n%s", code, out)
	}
	if !contains(out, "Commit rejected.") || !contains(out, "secrets.env") {
		t.Errorf("hook should reject and name the file:\n%s", out)
	}

	if _, _, err := runRoot(t, "encrypt", "-i", "secrets.env"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	mustGit(t, "add", "secrets.env")

	code, out = runPreCommitHook(t)
	if code != 0 {
		t.Errorf("hook exit code = %d with the secret encrypted, want 0\n%s", code, out)
	}
	if contains(out, "Commit rejected.") {
		t.Errorf("hook rejected an encrypted file:\n%s", out)
	}
	// Exit 0 is also what the hook does when it cannot find envisible at all.
	if contains(out, "not found in PATH") {
		t.Errorf("hook passed only because it skipped the check:\n%s", out)
	}
}

// TestInstallHookRefusesToOverwriteAnExistingHook: a second install must not
// clobber a hook the user may have edited since the first.
func TestInstallHookRefusesToOverwriteAnExistingHook(t *testing.T) {
	initGitRepo(t)

	if _, _, err := runRoot(t, "git", "install-hook"); err != nil {
		t.Fatalf("git install-hook: %v", err)
	}
	hookPath := filepath.Join(".git", "hooks", "pre-commit")
	writeFile(t, hookPath, "#!/bin/sh\n# edited by hand\n", 0o755)

	_, _, err := runRoot(t, "git", "install-hook")
	if err == nil {
		t.Fatal("second install-hook succeeded; it should refuse")
	}
	if !contains(err.Error(), "already exists") {
		t.Errorf("error should say the hook already exists: %v", err)
	}
	if got := string(readFile(t, hookPath)); got != "#!/bin/sh\n# edited by hand\n" {
		t.Errorf("the existing hook was overwritten: %q", got)
	}
}
