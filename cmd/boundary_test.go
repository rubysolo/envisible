package cmd

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Tests for the error paths and boundaries that mutation testing found nothing
// was holding in place: mostly `if err != nil` after a write, where inverting
// the comparison turned a failed write into a reported success.

// readOnlyDirWithFile creates dir/name holding content, then makes dir
// unwritable so writeFileAtomic cannot create its temp file there. The file
// itself stays readable. Skipped for root, which ignores directory modes.
func readOnlyDirWithFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions; the write cannot be made to fail")
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// lockDir drops write permission on dir for the rest of the test.
func lockDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
}

// assertWriteRefused checks the three things a failed in-place write owes its
// caller: the error names the failing step, nothing claims success, and the
// file is byte-for-byte what it was.
func assertWriteRefused(t *testing.T, err error, stderr, successText, path, before string) {
	t.Helper()
	if err == nil {
		t.Fatalf("the write failed but the command reported success (stderr %q)", stderr)
	}
	if !strings.Contains(err.Error(), "failed to create temp file") {
		t.Errorf("error = %q, want it to name the failed temp-file creation", err)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("error = %v, want it to wrap the permission error", err)
	}
	if strings.Contains(stderr, successText) {
		t.Errorf("stderr claims success (%q) for a write that failed: %q", successText, stderr)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read %s back: %v", path, readErr)
	}
	if string(after) != before {
		t.Errorf("%s changed although the write failed:\nbefore %q\n after %q", path, before, after)
	}
	if entries := dirEntries(t, filepath.Dir(path)); entries != filepath.Base(path)+"\n" {
		t.Errorf("directory holds more than the original file after a failed write: %q", entries)
	}
}

// decrypt.go:51 — `decrypt -i` must surface a failed write.
func TestDecryptInPlaceReportsAFailedWrite(t *testing.T) {
	setupKeyedTempDir(t)
	path := readOnlyDirWithFile(t, "locked", "app.env", "A=ENC[one]\n")
	mustRun(t, "encrypt", "-i", path)
	before := string(readFile(t, path))
	lockDir(t, "locked")

	stdout, stderr, err := runRoot(t, "decrypt", "-i", path)

	assertWriteRefused(t, err, stderr, "decrypted", path, before)
	if strings.Contains(stdout, "one") {
		t.Errorf("the plaintext went to stdout instead: %q", stdout)
	}
}

// encrypt.go:49 — `encrypt -i` must surface a failed write and not announce
// "encrypted in-place" over a file that still holds the plaintext.
func TestEncryptInPlaceReportsAFailedWrite(t *testing.T) {
	setupKeyedTempDir(t)
	const before = "A=ENC[one]\n"
	path := readOnlyDirWithFile(t, "locked", "app.env", before)
	lockDir(t, "locked")

	_, stderr, err := runRoot(t, "encrypt", "-i", path)

	assertWriteRefused(t, err, stderr, "encrypted in-place", path, before)
}

// The control for the two above: the same commands on a writable directory
// succeed, and encrypt says so. Without it, a writer that always failed would
// pass both.
func TestInPlaceWritesSucceedOnAWritableDirectory(t *testing.T) {
	setupKeyedTempDir(t)
	path := readOnlyDirWithFile(t, "open", "app.env", "A=ENC[one]\n")

	_, stderr, err := runRoot(t, "encrypt", "-i", path)
	if err != nil {
		t.Fatalf("encrypt -i: %v", err)
	}
	if !strings.Contains(stderr, "File "+path+" encrypted in-place.") {
		t.Errorf("stderr = %q, want the in-place confirmation", stderr)
	}
	if got := string(readFile(t, path)); !strings.HasPrefix(got, "A=ENC[v1:") {
		t.Errorf("file after encrypt -i = %q, want a v1 marker", got)
	}
	if _, _, err := runRoot(t, "decrypt", "-i", path); err != nil {
		t.Fatalf("decrypt -i: %v", err)
	}
	if got := string(readFile(t, path)); got != "A=ENC[one]\n" {
		t.Errorf("file after decrypt -i = %q, want the plaintext marker back", got)
	}
}

// edit.go:99 — `edit` must surface a failed write-back instead of reporting
// "updated and encrypted" for an edit that was thrown away.
func TestEditReportsAFailedWriteBack(t *testing.T) {
	editor, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no `true` on PATH to stand in for $EDITOR")
	}
	setupKeyedTempDir(t)
	path := readOnlyDirWithFile(t, "locked", "app.env", "A=ENC[one]\n")
	mustRun(t, "encrypt", "-i", path)
	before := string(readFile(t, path))
	lockDir(t, "locked")
	t.Setenv("EDITOR", editor)

	_, stderr, err := runRoot(t, "edit", path)

	assertWriteRefused(t, err, stderr, "updated and encrypted", path, before)
}

// git.go:53 — the closing hint says whether .gitattributes exists; each answer
// must go with the right state of the working tree.
func TestGitSetupReportsWhetherGitattributesExists(t *testing.T) {
	const found, missing = "(Found existing .gitattributes)", "(.gitattributes does not exist yet)"

	initGitRepo(t)
	stdout, _, err := runRoot(t, "git", "setup")
	if err != nil {
		t.Fatalf("git setup: %v", err)
	}
	if !strings.Contains(stdout, missing) || strings.Contains(stdout, found) {
		t.Errorf("with no .gitattributes, stdout = %q, want only %q", stdout, missing)
	}

	writeFile(t, ".gitattributes", ".env diff=envisible\n", 0o644)
	stdout, _, err = runRoot(t, "git", "setup")
	if err != nil {
		t.Fatalf("git setup: %v", err)
	}
	if !strings.Contains(stdout, found) || strings.Contains(stdout, missing) {
		t.Errorf("with a .gitattributes, stdout = %q, want only %q", stdout, found)
	}
}

// closedFile returns an *os.File whose Stat fails.
func closedFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "closed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f
}

// openDevNull returns the null device, which is a character device just as a
// terminal is — the one such device a test can open without a pty.
func openDevNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		t.Skipf("%s is not a character device on this platform", os.DevNull)
	}
	return f
}

// openRegularFile returns an open, ordinary file.
func openRegularFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "regular"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// input.go:28 — the real isTerminal, not a stub: a character device is a
// terminal, a regular file is not, and a file that cannot be stat'ed is "not a
// terminal" rather than a nil dereference.
func TestIsTerminalClassifiesRealFiles(t *testing.T) {
	if !isTerminal(openDevNull(t)) {
		t.Error("isTerminal(character device) = false, want true")
	}
	if isTerminal(openRegularFile(t)) {
		t.Error("isTerminal(regular file) = true, want false")
	}
	if isTerminal(closedFile(t)) {
		t.Error("isTerminal(file whose Stat fails) = true, want false")
	}
}

// keygen.go:21 and :24 — the real keygenStdoutIsTTY, which every other test
// replaces. It reads os.Stdout, so each case points os.Stdout at a real file.
func TestKeygenStdoutIsTTYReadsTheRealStdout(t *testing.T) {
	cases := []struct {
		name string
		file *os.File
		want bool
	}{
		{"character device", openDevNull(t), true},
		{"regular file", openRegularFile(t), false},
		{"stat fails", closedFile(t), false},
	}
	orig := os.Stdout
	t.Cleanup(func() { os.Stdout = orig })
	for _, tc := range cases {
		os.Stdout = tc.file
		got := keygenStdoutIsTTY()
		os.Stdout = orig
		if got != tc.want {
			t.Errorf("keygenStdoutIsTTY() with stdout a %s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// failingWriter refuses every write with err.
type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// keygen.go:48 — with --print-key the private key exists only on stdout, so a
// failed write there means the key is gone: that has to be an error, and
// keygen must not go on to announce the key as generated.
func TestKeygenPrintKeyReportsAFailedStdoutWrite(t *testing.T) {
	t.Chdir(t.TempDir())
	withKeygenStdoutTTY(t, false)
	errBrokenPipe := errors.New("stdout: broken pipe")

	resetRoot(failingWriter{errBrokenPipe})
	t.Cleanup(func() { resetRoot(nil) })
	rootCmd.SetArgs([]string{"keygen", "--print-key"})
	var err error
	_, stderr := captureStdStreams(t, func() { err = rootCmd.Execute() })

	if !errors.Is(err, errBrokenPipe) {
		t.Errorf("keygen --print-key error = %v, want the stdout write error", err)
	}
	if strings.Contains(stderr, "Generated keys") {
		t.Errorf("stderr announces a key nobody received: %q", stderr)
	}
	if _, statErr := os.Stat("envisible.key"); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("--print-key left an envisible.key behind (stat err = %v)", statErr)
	}
}

// The control: the same command with a working stdout succeeds and says so.
func TestKeygenPrintKeyAnnouncesSuccessOnStderr(t *testing.T) {
	t.Chdir(t.TempDir())
	withKeygenStdoutTTY(t, false)

	stdout, stderr, err := runRoot(t, "keygen", "--print-key")
	if err != nil {
		t.Fatalf("keygen --print-key: %v", err)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Error("no private key on stdout")
	}
	for _, want := range []string{"Generated keys", "written to stdout (no file)"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr, want)
		}
	}
}

// keygen.go:58 — a private key that could not be written is an error, not a
// "Generated keys" banner pointing at a file that is not there.
func TestKeygenReportsAFailedPrivateKeyWrite(t *testing.T) {
	t.Chdir(t.TempDir())
	keyPath := filepath.Join("no-such-dir", "envisible.key")

	_, stderr, err := runRoot(t, "--key", keyPath, "keygen")

	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("keygen error = %v, want the failed write of %s", err, keyPath)
	}
	if !strings.Contains(err.Error(), keyPath) {
		t.Errorf("error = %q, want it to name %s", err, keyPath)
	}
	if strings.Contains(stderr, "Generated keys") {
		t.Errorf("stderr announces a key that was never written: %q", stderr)
	}
}

// The control: a writable --key path gets the key, and the banner names it.
func TestKeygenAnnouncesTheKeyFilesItWrote(t *testing.T) {
	t.Chdir(t.TempDir())

	_, stderr, err := runRoot(t, "--key", "custom.key", "keygen")
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	info, err := os.Stat("custom.key")
	if err != nil {
		t.Fatalf("private key not written: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private key mode = %#o, want 0600", info.Mode().Perm())
	}
	for _, want := range []string{"Generated keys", "custom.key", "envisible.pub"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr, want)
		}
	}
}

// set.go:400 — the dry-run verdict counts the keys that would change. Two of
// the three keys here differ from the file; the third is already current.
func TestSetDryRunCountsTheKeysThatWouldChange(t *testing.T) {
	setupKeyedTempDir(t)
	if err, _, _ := runSet(t, "KEEP=same\nOLD=before\n", ".env", "--from-env", "-"); err != nil {
		t.Fatalf("seeding .env: %v", err)
	}
	before := string(readFile(t, ".env"))

	stdout, _, err := runRootWithStdin(t, "KEEP=same\nOLD=after\nNEW=added\n", "set", ".env", "--dry-run", "--if-changed", "--from-env", "-")

	const want = "dry run: 2 key(s) would change in .env, nothing written"
	if err == nil || err.Error() != want {
		t.Errorf("dry-run error = %v, want %q", err, want)
	}
	for _, line := range []string{"unchanged\tKEEP\t.env\n", "updated\tOLD\t.env\n", "added\tNEW\t.env\n"} {
		if !strings.Contains(stdout, line) {
			t.Errorf("dry-run report %q is missing the line %q", stdout, line)
		}
	}
	if after := string(readFile(t, ".env")); after != before {
		t.Errorf("--dry-run wrote to the file:\nbefore %q\n after %q", before, after)
	}
}

// run.go:98 — `run` forwards SIGINT/SIGTERM to the command it wraps. Driven in
// a subprocess so the signal goes to an envisible process and not to the test
// binary. The child traps the signal and exits 0 on either path: when the
// signal is forwarded it records that first, when it is not it gives up after
// its own deadline — so `run` never sees a non-zero child.
func TestRunForwardsSIGTERMToTheChild(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not found on PATH")
	}
	setupRunFixture(t)

	const script = `trap 'echo forwarded > got-signal; exit 0' TERM
: > ready
i=0
while [ "$i" -lt 100 ]; do sleep 0.05; i=$((i+1)); done
exit 0`
	child := exec.Command(os.Args[0], "-q", "run", "--", "sh", "-c", script)
	// GORACE: under `go test -race` the re-executed binary is race-instrumented
	// too, and run.go's signal goroutine reads childCmd.Process with no
	// synchronisation against exec.Cmd.Start writing it. The detector reports
	// that and would turn the exit status into 66; this test is about whether
	// the signal is forwarded, so the report is kept out of the exit code.
	child.Env = append(os.Environ(), runAsCLIEnv+"=1", "GORACE=exitcode=0")
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if err := child.Start(); err != nil {
		t.Fatalf("starting envisible run: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			child.Process.Kill()
			child.Wait()
		}
	})

	// "ready" appears only once sh is running with its trap installed, which is
	// also after `run` has registered its own signal handler.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat("ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the child never became ready; stderr: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	if err := child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signalling envisible run: %v", err)
	}
	err := child.Wait()
	waited = true

	if err != nil {
		t.Errorf("envisible run exited with %v, want 0 (the child handled the signal); stderr: %s", err, stderr.String())
	}
	got, readErr := os.ReadFile("got-signal")
	if readErr != nil || string(got) != "forwarded\n" {
		t.Errorf("the child never received SIGTERM: got-signal = %q (%v); stderr: %s", got, readErr, stderr.String())
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Errorf("run took %v to exit after SIGTERM; the child ran to its own deadline instead of being signalled", elapsed)
	}
}
