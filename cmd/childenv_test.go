package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	envcrypto "github.com/rubysolo/envisible/pkg/crypto"
)

// The tests below are the regression for a key leak: `run`, `edit` and the git
// helpers used to hand their child the whole environment, ENVISIBLE_KEY
// included, so the program being launched received the private key along with
// (or instead of) the decrypted values.

// writeEnvRecorder writes an executable script that records whether
// ENVISIBLE_KEY is present in its environment, and returns the script path and
// the path it records to. The record is "unset" or "set:<value>".
func writeEnvRecorder(t *testing.T, dir, name string) (script, record string) {
	t.Helper()
	script = filepath.Join(dir, name)
	record = filepath.Join(dir, name+".seen")
	body := "#!/bin/sh\n" +
		`if [ "${ENVISIBLE_KEY+x}" = x ]; then printf 'set:%s' "$ENVISIBLE_KEY"; else printf unset; fi > "` + record + "\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, record
}

func readRecord(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the child never ran (no record at %s): %v", path, err)
	}
	return string(data)
}

func TestRunDoesNotPassPrivateKeyToChild(t *testing.T) {
	f := newEnvKeyFixture(t)
	material := envcrypto.EncodeKey(f.priv)
	t.Setenv("ENVISIBLE_KEY", material)
	t.Setenv("ENVISIBLE_KEY_PATH", "some/path.key")
	t.Setenv("UNRELATED_VAR", "kept")

	var out bytes.Buffer
	resetRoot(&out)
	// ${VAR-unset} distinguishes "absent" from "present but empty": the key
	// must be gone from the child's environment, not merely blanked.
	rootCmd.SetArgs([]string{"-q", "run", "--", "sh", "-c",
		`printf '%s|%s|%s|%s' "${ENVISIBLE_KEY-unset}" "$MY_VAR" "$UNRELATED_VAR" "$ENVISIBLE_KEY_PATH"`})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := out.String()
	if strings.Contains(got, material) {
		t.Fatalf("the child process received the private key: %q", got)
	}
	// The key was still used to decrypt MY_VAR, the rest of the environment is
	// inherited, and the path variable (not a secret) passes through.
	want := "unset|" + envKeyFixtureSecret + "|kept|some/path.key"
	if got != want {
		t.Errorf("child environment = %q, want %q", got, want)
	}
	// Stripping is for the child only; this process still has its key.
	if os.Getenv("ENVISIBLE_KEY") != material {
		t.Error("run modified envisible's own environment")
	}
}

// TestRunPassesAnEnvisibleKeyDefinedInTheFile: only the *inherited* key is
// dropped. A file that defines a variable named ENVISIBLE_KEY is asking for the
// child to have it, the same as any other entry.
func TestRunPassesAnEnvisibleKeyDefinedInTheFile(t *testing.T) {
	f := newEnvKeyFixture(t)
	env, err := os.ReadFile(".env")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".env", append(env, []byte("ENVISIBLE_KEY=from-the-file\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENVISIBLE_KEY", envcrypto.EncodeKey(f.priv))

	var out bytes.Buffer
	resetRoot(&out)
	rootCmd.SetArgs([]string{"-q", "run", "--", "sh", "-c", `printf '%s' "${ENVISIBLE_KEY-unset}"`})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.String() != "from-the-file" {
		t.Errorf("child ENVISIBLE_KEY = %q, want the value the env file defines", out.String())
	}
}

func TestEditDoesNotPassPrivateKeyToEditor(t *testing.T) {
	f := newEnvKeyFixture(t)
	editor, record := writeEnvRecorder(t, f.dir, "recording-editor.sh")
	t.Setenv("EDITOR", editor)
	t.Setenv("ENVISIBLE_KEY", envcrypto.EncodeKey(f.priv))

	resetRoot(nil)
	rootCmd.SetArgs([]string{"-q", "edit", ".env"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("edit: %v", err)
	}
	if got := readRecord(t, record); got != "unset" {
		t.Errorf("$EDITOR saw ENVISIBLE_KEY (%q); it must not be in the editor's environment", got)
	}
}

func TestGitHelperDoesNotPassPrivateKeyToGit(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	_, priv := mustKeypair(t)
	// A stand-in `git` first on PATH, so the test sees exactly what runGit
	// hands its child without depending on the real git or its config.
	_, record := writeEnvRecorder(t, dir, "git")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ENVISIBLE_KEY", envcrypto.EncodeKey(priv))

	if err := runGit("config", "diff.envisible.textconv", "envisible decrypt --textconv"); err != nil {
		t.Fatalf("runGit: %v", err)
	}
	if got := readRecord(t, record); got != "unset" {
		t.Errorf("git saw ENVISIBLE_KEY (%q); it must not be in git's environment", got)
	}
}

func TestChildEnvironStripsOnlyThePrivateKey(t *testing.T) {
	t.Setenv("ENVISIBLE_KEY", "the-key")
	t.Setenv("ENVISIBLE_KEY_PATH", "a/path")
	t.Setenv("ENVISIBLE_PUB_PATH", "a/pub")
	t.Setenv("ENVISIBLE_FILE", "a.env")
	t.Setenv("ENVISIBLE_KEYRING", "prefix-collision")
	t.Setenv("MY_ENVISIBLE_KEY", "suffix-collision")

	got := map[string]string{}
	for _, kv := range childEnviron() {
		name, value, _ := strings.Cut(kv, "=")
		got[name] = value
	}
	if v, ok := got["ENVISIBLE_KEY"]; ok {
		t.Errorf("ENVISIBLE_KEY survived with value %q", v)
	}
	for name, want := range map[string]string{
		"ENVISIBLE_KEY_PATH": "a/path",
		"ENVISIBLE_PUB_PATH": "a/pub",
		"ENVISIBLE_FILE":     "a.env",
		"ENVISIBLE_KEYRING":  "prefix-collision",
		"MY_ENVISIBLE_KEY":   "suffix-collision",
	} {
		if got[name] != want {
			t.Errorf("%s = %q, want %q (only the exact name ENVISIBLE_KEY is dropped)", name, got[name], want)
		}
	}
	if len(got) != len(os.Environ())-1 {
		t.Errorf("childEnviron dropped %d variables, want exactly 1", len(os.Environ())-len(got))
	}
}

// runChild runs `envisible <args...>` in-process and returns what the child
// command wrote to stdout.
func runChild(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	resetRoot(&out)
	rootCmd.SetArgs(args)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("envisible %s: %v", strings.Join(args, " "), err)
	}
	return out.String()
}

const printKeyAndVar = `printf '%s|%s' "${ENVISIBLE_KEY-unset}" "$MY_VAR"`

// TestRunPassKeyLeavesTheKeyInTheChildEnvironment: --pass-key is the opt-in for
// a child that needs to decrypt on its own. The key arrives byte for byte, and
// the decrypted values are injected as usual.
func TestRunPassKeyLeavesTheKeyInTheChildEnvironment(t *testing.T) {
	f := newEnvKeyFixture(t)
	material := envcrypto.EncodeKey(f.priv)
	t.Setenv("ENVISIBLE_KEY", material)

	got := runChild(t, "-q", "run", "--pass-key", "--", "sh", "-c", printKeyAndVar)
	if want := material + "|" + envKeyFixtureSecret; got != want {
		t.Errorf("child environment = %q, want the key and the decrypted value", got)
	}
}

// TestRunPassKeyIsOffByDefaultAndDoesNotStick: the flag applies to the one
// invocation it is passed on. A later run without it strips the key again.
func TestRunPassKeyIsOffByDefaultAndDoesNotStick(t *testing.T) {
	f := newEnvKeyFixture(t)
	material := envcrypto.EncodeKey(f.priv)
	t.Setenv("ENVISIBLE_KEY", material)
	stripped := "unset|" + envKeyFixtureSecret

	if got := runChild(t, "-q", "run", "--", "sh", "-c", printKeyAndVar); got != stripped {
		t.Fatalf("default run: child environment = %q, want %q", got, stripped)
	}
	if got := runChild(t, "-q", "run", "--pass-key", "--", "sh", "-c", printKeyAndVar); !strings.HasPrefix(got, material) {
		t.Fatalf("--pass-key run: child environment = %q, want the key", got)
	}
	if got := runChild(t, "-q", "run", "--", "sh", "-c", printKeyAndVar); got != stripped {
		t.Errorf("run after a --pass-key run: child environment = %q, want %q", got, stripped)
	}
}

// TestRunPassKeyAfterTheCommandBelongsToTheCommand: flag parsing stops at the
// command, so a --pass-key among the child's own arguments is the child's, and
// cannot switch the key on by accident (or by an attacker-influenced argument).
func TestRunPassKeyAfterTheCommandBelongsToTheCommand(t *testing.T) {
	f := newEnvKeyFixture(t)
	t.Setenv("ENVISIBLE_KEY", envcrypto.EncodeKey(f.priv))

	// "$1" is the first argument after the script name: the literal --pass-key.
	got := runChild(t, "-q", "run", "sh", "-c", `printf '%s|%s' "${ENVISIBLE_KEY-unset}" "$1"`, "sh", "--pass-key")
	if got != "unset|--pass-key" {
		t.Errorf("child saw %q, want the key stripped and --pass-key as its own argument", got)
	}
}

// TestRunPassKeyDoesNotInventAKey: the flag leaves an inherited variable alone;
// it does not copy a key that came from a file into the environment.
func TestRunPassKeyDoesNotInventAKey(t *testing.T) {
	f := newEnvKeyFixture(t)
	f.writeKeyFile(t, "envisible.key", f.priv)

	got := runChild(t, "-q", "run", "--pass-key", "--", "sh", "-c", printKeyAndVar)
	if want := "unset|" + envKeyFixtureSecret; got != want {
		t.Errorf("child environment = %q, want %q (key file must not become an env var)", got, want)
	}
}

// TestRunPassKeyLetsTheChildDecrypt is the use case end to end: a command under
// `run` that calls envisible itself. Without the flag the inner call has no key;
// with it, the inner call decrypts.
func TestRunPassKeyLetsTheChildDecrypt(t *testing.T) {
	bin := builtCLIDir(t)
	f := newEnvKeyFixture(t)
	t.Setenv("ENVISIBLE_KEY", envcrypto.EncodeKey(f.priv))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	// `|| printf` keeps the child's exit status zero: a failing child makes
	// `run` call os.Exit, which would end the test binary.
	inner := `envisible -q decrypt --strip .env 2>/dev/null || printf 'INNER-DECRYPT-FAILED'`

	if got := runChild(t, "-q", "run", "--", "sh", "-c", inner); got != "INNER-DECRYPT-FAILED" {
		t.Errorf("without --pass-key the nested envisible printed %q, want it to have no key", got)
	}
	got := runChild(t, "-q", "run", "--pass-key", "--", "sh", "-c", inner)
	if !strings.Contains(got, "MY_VAR="+envKeyFixtureSecret) {
		t.Errorf("with --pass-key the nested envisible printed %q, want the decrypted file", got)
	}
}

// TestPassKeyIsARunFlagOnly: an editor and git never need the key, so the
// opt-in does not exist for them.
func TestPassKeyIsARunFlagOnly(t *testing.T) {
	newEnvKeyFixture(t)
	for _, args := range [][]string{
		{"edit", "--pass-key", ".env"},
		{"git", "setup", "--pass-key"},
	} {
		resetRoot(nil)
		rootCmd.SetArgs(args)
		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "unknown flag: --pass-key") {
			t.Errorf("envisible %s: err = %v, want unknown flag", strings.Join(args, " "), err)
		}
	}
}
