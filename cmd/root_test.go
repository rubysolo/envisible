package cmd

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	envcrypto "github.com/rubysolo/envisible/pkg/crypto"
	"github.com/rubysolo/envisible/pkg/ui"
)

// TestMain clears the key-locating environment variables before any test runs.
// The command tests create envisible.key / envisible.pub in a temp dir and rely
// on the defaults finding them; a developer shell that exports ENVISIBLE_KEY
// (which outranks envisible.key) or ENVISIBLE_KEY_PATH would silently swap in a
// different key and fail them for reasons that have nothing to do with the code.
// Tests that exercise these variables set them with t.Setenv.
//
// With runAsCLIEnv set the test binary is not running tests at all: it is a
// child re-executed by runCLISubprocess, standing in for the envisible binary.
func TestMain(m *testing.M) {
	if os.Getenv(runAsCLIEnv) == "1" {
		// main() in miniature. Arguments are taken raw, before the testing
		// package would try to parse them as its own flags.
		rootCmd.SetArgs(os.Args[1:])
		if err := Execute(); err != nil {
			ui.Error("%v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	for _, name := range []string{"ENVISIBLE_KEY", "ENVISIBLE_KEY_PATH", "ENVISIBLE_PUB_PATH", "ENVISIBLE_FILE"} {
		os.Unsetenv(name)
	}
	code := m.Run()
	// The CLI binary the pre-commit hook tests build, if any of them ran.
	if cliBinDir != "" {
		os.RemoveAll(cliBinDir)
	}
	os.Exit(code)
}

// runAsCLIEnv switches the test binary into behaving as the envisible CLI; see
// TestMain.
const runAsCLIEnv = "ENVISIBLE_TEST_RUN_AS_CLI"

// runCLISubprocess runs `envisible args...` as a real child process, in the
// current directory, and returns its exit code and stdout. It exists for the
// paths that end in os.Exit, which cannot run inside the test process.
func runCLISubprocess(t *testing.T, args ...string) (exitCode int, stdout string) {
	t.Helper()
	child := exec.Command(os.Args[0], args...)
	child.Env = append(os.Environ(), runAsCLIEnv+"=1")
	var out, errOut bytes.Buffer
	child.Stdout, child.Stderr = &out, &errOut
	err := child.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String()
	case errors.As(err, &exitErr):
		t.Logf("child stderr: %s", errOut.String())
		return exitErr.ExitCode(), out.String()
	default:
		t.Fatalf("re-executing the test binary as envisible: %v", err)
		return 0, ""
	}
}

// TestRunPropagatesTheChildExitCode: `run` is a wrapper, so a caller (a
// Procfile, CI, `set -e`) must see the wrapped command's own status. run.go
// does that with os.Exit, hence the subprocess. 3 is neither success nor the 1
// that main() exits with for an ordinary error.
func TestRunPropagatesTheChildExitCode(t *testing.T) {
	setupRunFixture(t)

	code, stdout := runCLISubprocess(t, "-q", "run", "--", "sh", "-c", `printf '%s' "$MY_VAR"; exit 3`)
	if code != 3 {
		t.Errorf("exit code = %d, want the child's 3", code)
	}
	if stdout != "secret-value" {
		t.Errorf("child stdout = %q, want the decrypted value: the child may not have run", stdout)
	}

	// The controls: a child that succeeds exits 0, and envisible's own failure
	// (no such env file) is main()'s 1, not a child status.
	if code, _ := runCLISubprocess(t, "-q", "run", "--", "sh", "-c", "exit 0"); code != 0 {
		t.Errorf("exit code = %d for a child that succeeded, want 0", code)
	}
	if code, _ := runCLISubprocess(t, "-q", "-f", "missing.env", "run", "--", "sh", "-c", "exit 3"); code != 1 {
		t.Errorf("exit code = %d when the env file is missing, want 1", code)
	}
}

// envKeyFixture is a temp working dir holding envisible.pub and a .env whose one
// value is sealed to that public key. Nothing in it can decrypt the value: each
// test decides where the matching private key comes from.
type envKeyFixture struct {
	dir  string
	priv [32]byte // the key that opens .env
}

const envKeyFixtureSecret = "from-the-right-key"

func newEnvKeyFixture(t *testing.T) envKeyFixture {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)

	pub, priv := mustKeypair(t)
	if err := os.WriteFile("envisible.pub", []byte(envcrypto.EncodeKey(pub)), 0o644); err != nil {
		t.Fatal(err)
	}
	env := "MY_VAR=ENC[" + sealV1(t, pub, envKeyFixtureSecret) + "]\n"
	if err := os.WriteFile(".env", []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}
	return envKeyFixture{dir: dir, priv: priv}
}

// writeKeyFile writes priv to name inside the fixture dir, mode 0600, and
// returns its path.
func (f envKeyFixture) writeKeyFile(t *testing.T, name string, priv [32]byte) string {
	t.Helper()
	path := filepath.Join(f.dir, name)
	if err := os.WriteFile(path, []byte(envcrypto.EncodeKey(priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// decryptStripped runs `envisible decrypt --strip .env` through the real
// command tree, so PersistentPreRunE resolves the key sources from flags and the
// process environment exactly as the binary does.
func decryptStripped(t *testing.T, extraArgs ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	resetRoot(&out)
	rootCmd.SetArgs(append(append([]string{}, extraArgs...), "decrypt", "--strip", ".env"))
	err := rootCmd.Execute()
	return out.String(), err
}

// assertDecryptsWithRightKey fails unless decrypt succeeded and printed the
// fixture's secret. Every precedence test is built so that only the key the
// winning source supplies can open .env, so this alone shows which source won.
func assertDecryptsWithRightKey(t *testing.T, out string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("decrypt failed (did the wrong key source win?): %v", err)
	}
	if !contains(out, "MY_VAR="+envKeyFixtureSecret) {
		t.Errorf("decrypt output %q does not contain the secret", out)
	}
}

func TestEnvisibleKeyDecryptsWithNoKeyFile(t *testing.T) {
	f := newEnvKeyFixture(t)
	t.Setenv("ENVISIBLE_KEY", envcrypto.EncodeKey(f.priv))

	if _, err := os.Stat("envisible.key"); !os.IsNotExist(err) {
		t.Fatalf("fixture should have no envisible.key, stat err = %v", err)
	}
	out, err := decryptStripped(t)
	assertDecryptsWithRightKey(t, out, err)
}

func TestEnvisibleKeyInjectedByRun(t *testing.T) {
	f := newEnvKeyFixture(t)
	t.Setenv("ENVISIBLE_KEY", envcrypto.EncodeKey(f.priv))

	var out bytes.Buffer
	resetRoot(&out)
	rootCmd.SetArgs([]string{"-q", "run", "--", "sh", "-c", `printf '%s' "$MY_VAR"`})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.String() != envKeyFixtureSecret {
		t.Errorf("child saw MY_VAR=%q, want %q", out.String(), envKeyFixtureSecret)
	}
}

// TestKeySourcePrecedence pins the four-level resolution order documented on
// resolveKeySources, end to end. In each case every source that should lose
// holds a different, wrong key, so decrypt succeeds only if the right source won.
func TestKeySourcePrecedence(t *testing.T) {
	_, wrong := mustKeypair(t)
	wrongMaterial := envcrypto.EncodeKey(wrong)

	t.Run("--key beats ENVISIBLE_KEY", func(t *testing.T) {
		f := newEnvKeyFixture(t)
		keyFile := f.writeKeyFile(t, "explicit.key", f.priv)
		t.Setenv("ENVISIBLE_KEY", wrongMaterial)

		out, err := decryptStripped(t, "--key", keyFile)
		assertDecryptsWithRightKey(t, out, err)
	})

	t.Run("-k beats ENVISIBLE_KEY", func(t *testing.T) {
		f := newEnvKeyFixture(t)
		keyFile := f.writeKeyFile(t, "explicit.key", f.priv)
		t.Setenv("ENVISIBLE_KEY", wrongMaterial)

		out, err := decryptStripped(t, "-k", keyFile)
		assertDecryptsWithRightKey(t, out, err)
	})

	t.Run("--key naming the default path still beats ENVISIBLE_KEY", func(t *testing.T) {
		// The case that needs cmd.Flags().Changed: the flag's value equals the
		// default, so only "was it passed" can tell an explicit override apart.
		f := newEnvKeyFixture(t)
		f.writeKeyFile(t, "envisible.key", f.priv)
		t.Setenv("ENVISIBLE_KEY", wrongMaterial)

		out, err := decryptStripped(t, "--key", "envisible.key")
		assertDecryptsWithRightKey(t, out, err)
	})

	t.Run("ENVISIBLE_KEY beats ENVISIBLE_KEY_PATH", func(t *testing.T) {
		f := newEnvKeyFixture(t)
		t.Setenv("ENVISIBLE_KEY", envcrypto.EncodeKey(f.priv))
		t.Setenv("ENVISIBLE_KEY_PATH", f.writeKeyFile(t, "wrong.key", wrong))

		out, err := decryptStripped(t)
		assertDecryptsWithRightKey(t, out, err)
	})

	t.Run("ENVISIBLE_KEY beats envisible.key", func(t *testing.T) {
		f := newEnvKeyFixture(t)
		f.writeKeyFile(t, "envisible.key", wrong)
		t.Setenv("ENVISIBLE_KEY", envcrypto.EncodeKey(f.priv))

		out, err := decryptStripped(t)
		assertDecryptsWithRightKey(t, out, err)
	})

	t.Run("ENVISIBLE_KEY_PATH beats envisible.key", func(t *testing.T) {
		f := newEnvKeyFixture(t)
		f.writeKeyFile(t, "envisible.key", wrong)
		t.Setenv("ENVISIBLE_KEY_PATH", f.writeKeyFile(t, "elsewhere.key", f.priv))

		out, err := decryptStripped(t)
		assertDecryptsWithRightKey(t, out, err)
	})

	t.Run("envisible.key is the default", func(t *testing.T) {
		f := newEnvKeyFixture(t)
		f.writeKeyFile(t, "envisible.key", f.priv)

		out, err := decryptStripped(t)
		assertDecryptsWithRightKey(t, out, err)
	})
}

// TestBlankEnvisibleKeyFallsBackToKeyFile: an exported-but-empty ENVISIBLE_KEY
// (a CI secret that resolved to nothing, `export ENVISIBLE_KEY=`) means "not
// supplied", not "a malformed key". It must fall through to the key file.
func TestBlankEnvisibleKeyFallsBackToKeyFile(t *testing.T) {
	for name, value := range map[string]string{
		"empty":           "",
		"whitespace only": " \t\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newEnvKeyFixture(t)
			f.writeKeyFile(t, "envisible.key", f.priv)
			t.Setenv("ENVISIBLE_KEY", value)

			out, err := decryptStripped(t)
			assertDecryptsWithRightKey(t, out, err)
		})
	}
}

func TestResolvePrivateKeyMaterialTrimsWhitespace(t *testing.T) {
	_, priv := mustKeypair(t)
	material := envcrypto.EncodeKey(priv)
	t.Setenv("ENVISIBLE_KEY", "\n  "+material+"\t\n")

	if got := resolvePrivateKeyMaterial(nil); got != material {
		t.Errorf("resolvePrivateKeyMaterial = %q, want the trimmed key", got)
	}
}
