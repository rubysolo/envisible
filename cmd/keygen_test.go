package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	envcrypto "github.com/rubysolo/envisible/pkg/crypto"
)

// withKeygenStdoutTTY makes keygen believe stdout is (or is not) a terminal for
// the duration of a test.
func withKeygenStdoutTTY(t *testing.T, isTTY bool) {
	t.Helper()
	orig := keygenStdoutIsTTY
	keygenStdoutIsTTY = func() bool { return isTTY }
	t.Cleanup(func() { keygenStdoutIsTTY = orig })
}

func runKeygen(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	resetRoot(&out)
	rootCmd.SetArgs(append([]string{"keygen"}, args...))
	err := rootCmd.Execute()
	return out.String(), err
}

// TestKeygenPrintKeyRoundTrips: --print-key writes envisible.pub, puts the
// private key on stdout instead of in envisible.key, and that printed key,
// handed back as ENVISIBLE_KEY, decrypts what the public key encrypted. This is
// the whole secret-store workflow with no key file ever touching disk.
func TestKeygenPrintKeyRoundTrips(t *testing.T) {
	t.Chdir(t.TempDir())
	withKeygenStdoutTTY(t, false)

	out, err := runKeygen(t, "--print-key")
	if err != nil {
		t.Fatalf("keygen --print-key: %v", err)
	}
	if _, err := os.Stat("envisible.key"); !os.IsNotExist(err) {
		t.Errorf("--print-key must not write envisible.key, stat err = %v", err)
	}
	pubData, err := os.ReadFile("envisible.pub")
	if err != nil {
		t.Fatalf("envisible.pub not written: %v", err)
	}

	// stdout is exactly one line: the key, nothing else to strip off in a pipe.
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("stdout should be a single newline-terminated line, got %q", out)
	}
	material := strings.TrimSuffix(out, "\n")
	if _, err := envcrypto.DecodeKey(material); err != nil {
		t.Fatalf("stdout is not a decodable private key: %v", err)
	}

	pub, err := envcrypto.DecodeKey(string(pubData))
	if err != nil {
		t.Fatalf("decode envisible.pub: %v", err)
	}
	if err := os.WriteFile(".env", []byte("MY_VAR=ENC["+sealV1(t, pub, "round-trip")+"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENVISIBLE_KEY", material)
	got, err := decryptStripped(t)
	if err != nil {
		t.Fatalf("decrypt with the printed key: %v", err)
	}
	if !contains(got, "MY_VAR=round-trip") {
		t.Errorf("printed key did not open a value sealed to envisible.pub, got %q", got)
	}
}

// TestKeygenPrintKeyRefusesTTY: printing a private key into a terminal puts it
// in scrollback. The refusal happens before generating anything, so a refused
// run leaves no envisible.pub behind to mismatch a key that was never saved.
func TestKeygenPrintKeyRefusesTTY(t *testing.T) {
	t.Chdir(t.TempDir())
	withKeygenStdoutTTY(t, true)

	out, err := runKeygen(t, "--print-key")
	if err == nil {
		t.Fatal("expected keygen --print-key to refuse a terminal stdout")
	}
	if !strings.Contains(err.Error(), "refusing to print the private key to a terminal") {
		t.Errorf("unexpected error: %v", err)
	}
	// Cobra may echo usage on error; that's fine. A decodable key is not.
	for _, line := range strings.Split(out, "\n") {
		if _, decErr := envcrypto.DecodeKey(strings.TrimSpace(line)); decErr == nil {
			t.Errorf("a private key reached stdout despite the refusal: %q", line)
		}
	}
	for _, name := range []string{"envisible.pub", "envisible.key"} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Errorf("refused run must leave no %s, stat err = %v", name, err)
		}
	}
}

// TestKeygenWithoutPrintKeyIgnoresTTY: the TTY check guards --print-key only.
// A plain keygen in an interactive shell is the normal case and must work.
func TestKeygenWithoutPrintKeyIgnoresTTY(t *testing.T) {
	t.Chdir(t.TempDir())
	withKeygenStdoutTTY(t, true)

	out, err := runKeygen(t)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("plain keygen should print nothing to stdout, got %q", out)
	}
	info, err := os.Stat("envisible.key")
	if err != nil {
		t.Fatalf("envisible.key not written: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("envisible.key mode = %#o, want 0600", mode)
	}
}

// The failed-write tests below pass --force wherever a key file already exists:
// without it keygen stops at the overwrite refusal and never reaches the write
// they are about.

// The tests below pin keygen's all-or-nothing write. The two key files are
// useless apart, and the failure this guards against is worse than useless:
// keygen used to write envisible.pub first, so a failed private-key write left
// a new public key beside the old private key, and everything encrypted from
// then on could be decrypted by nothing.

// existingKeypair generates a working keypair in a fresh temp working dir and
// returns a marker sealed to it, which only that pair can open.
func existingKeypair(t *testing.T) (sealed string) {
	t.Helper()
	t.Chdir(t.TempDir())
	if _, err := runKeygen(t); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubData, err := os.ReadFile("envisible.pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := envcrypto.DecodeKey(string(pubData))
	if err != nil {
		t.Fatal(err)
	}
	return "MY_VAR=ENC[" + sealV1(t, pub, "still-readable") + "]\n"
}

// assertPairStillWorks encrypts with the public key on disk and decrypts with
// the private key on disk: the property a failed keygen must not break.
func assertPairStillWorks(t *testing.T, sealedBefore string) {
	t.Helper()
	if err := os.WriteFile("probe.env", []byte("NEW=ENC[fresh-secret]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "encrypt", "-i", "probe.env")
	out, _, err := runRoot(t, "decrypt", "--strip", "probe.env")
	if err != nil || !strings.Contains(out, "NEW=fresh-secret") {
		t.Errorf("a value encrypted with envisible.pub no longer decrypts with envisible.key: out=%q err=%v", out, err)
	}
	if err := os.WriteFile("probe.env", []byte(sealedBefore), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, err = runRoot(t, "decrypt", "--strip", "probe.env")
	if err != nil || !strings.Contains(out, "MY_VAR=still-readable") {
		t.Errorf("a value encrypted before the failed keygen no longer decrypts: out=%q err=%v", out, err)
	}
	os.Remove("probe.env")
}

func TestKeygenFailedPrivateKeyWriteLeavesTheExistingPairIntact(t *testing.T) {
	sealed := existingKeypair(t)
	before := snapshotDir(t)

	_, _, err := runRoot(t, "--key", filepath.Join("no-such-dir", "envisible.key"), "keygen", "--force")
	if err == nil {
		t.Fatal("keygen succeeded with an unwritable private key path")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("keygen error = %v, want the failed write (not the overwrite refusal)", err)
	}
	assertDirUnchanged(t, before)
	assertPairStillWorks(t, sealed)
}

func TestKeygenFailedPublicKeyWriteLeavesTheExistingPairIntact(t *testing.T) {
	sealed := existingKeypair(t)
	before := snapshotDir(t)

	_, _, err := runRoot(t, "--pub", filepath.Join("no-such-dir", "envisible.pub"), "keygen", "--force")
	if err == nil {
		t.Fatal("keygen succeeded with an unwritable public key path")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("keygen error = %v, want the failed write (not the overwrite refusal)", err)
	}
	assertDirUnchanged(t, before)
	assertPairStillWorks(t, sealed)
}

// With no keys yet, a failed write of either half leaves nothing at all.
func TestKeygenFailedWriteCreatesNeitherFile(t *testing.T) {
	for name, args := range map[string][]string{
		"private key path unwritable": {"--key", filepath.Join("no-such-dir", "envisible.key"), "keygen"},
		"public key path unwritable":  {"--pub", filepath.Join("no-such-dir", "envisible.pub"), "keygen"},
		"private key path is a dir":   {"--key", "a-directory", "keygen", "--force"},
		"public key path is a dir":    {"--pub", "a-directory", "keygen", "--force"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.Mkdir("a-directory", 0o755); err != nil {
				t.Fatal(err)
			}
			before := snapshotDir(t)
			if _, _, err := runRoot(t, args...); err == nil {
				t.Fatal("keygen succeeded")
			}
			assertDirUnchanged(t, before)
		})
	}
}

// --print-key: if the private key cannot be written to stdout, nobody has it,
// so the public key must not appear (or replace an existing one).
func TestKeygenPrintKeyFailedStdoutWritesNoPublicKey(t *testing.T) {
	for name, withExistingPair := range map[string]bool{"no keys yet": false, "existing pair": true} {
		t.Run(name, func(t *testing.T) {
			sealed := ""
			if withExistingPair {
				sealed = existingKeypair(t)
			} else {
				t.Chdir(t.TempDir())
			}
			withKeygenStdoutTTY(t, false)
			before := snapshotDir(t)

			resetRoot(failingWriter{errors.New("stdout: broken pipe")})
			t.Cleanup(func() { resetRoot(nil) })
			// --force so the existing-pair case reaches the write rather than
			// stopping at the overwrite refusal.
			rootCmd.SetArgs([]string{"keygen", "--print-key", "--force"})
			var err error
			captureStdStreams(t, func() { err = rootCmd.Execute() })
			if err == nil {
				t.Fatal("keygen --print-key succeeded with a failing stdout")
			}
			assertDirUnchanged(t, before)
			if withExistingPair {
				assertPairStillWorks(t, sealed)
			}
		})
	}
}

// The last step is two renames. If the public key's lands and the private
// key's does not, the old private key is still on disk, so the old public key
// is put back and the pair works again.
func TestKeygenRollsBackThePublicKeyWhenThePrivateKeyRenameFails(t *testing.T) {
	failPrivateRename := func(t *testing.T) {
		t.Helper()
		orig := renameFile
		renameFile = func(from, to string) error {
			if filepath.Base(to) == "envisible.key" {
				return errors.New("rename refused")
			}
			return orig(from, to)
		}
		t.Cleanup(func() { renameFile = orig })
	}

	t.Run("existing pair", func(t *testing.T) {
		sealed := existingKeypair(t)
		before := snapshotDir(t)
		failPrivateRename(t)

		_, _, err := runRoot(t, "keygen", "--force")
		if err == nil || !strings.Contains(err.Error(), "rename refused") {
			t.Fatalf("keygen error = %v, want the rename failure", err)
		}
		if strings.Contains(err.Error(), "could not be restored") {
			t.Errorf("rollback reported a failure: %v", err)
		}
		assertDirUnchanged(t, before)
		assertPairStillWorks(t, sealed)
	})

	t.Run("no keys yet", func(t *testing.T) {
		t.Chdir(t.TempDir())
		before := snapshotDir(t)
		failPrivateRename(t)

		if _, _, err := runRoot(t, "keygen"); err == nil {
			t.Fatal("keygen succeeded although the private key rename failed")
		}
		assertDirUnchanged(t, before)
	})
}

// A new private key is 0600 even when it replaces a key file that had been
// loosened, and the new pair works.
func TestKeygenReplacesALoosePrivateKeyWithAnOwnerOnlyOne(t *testing.T) {
	existingKeypair(t)
	if err := os.Chmod("envisible.key", 0o644); err != nil {
		t.Fatal(err)
	}
	oldPub, _ := os.ReadFile("envisible.pub")

	if _, err := runKeygen(t, "--force"); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	info, err := os.Stat("envisible.key")
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("envisible.key mode = %#o, want 0600", mode)
	}
	if newPub, _ := os.ReadFile("envisible.pub"); string(newPub) == string(oldPub) {
		t.Error("envisible.pub was not replaced by a successful keygen")
	}
	if err := os.WriteFile("probe.env", []byte("NEW=ENC[fresh-secret]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "encrypt", "-i", "probe.env")
	if out, _, err := runRoot(t, "decrypt", "--strip", "probe.env"); err != nil || !strings.Contains(out, "NEW=fresh-secret") {
		t.Errorf("the new pair does not round-trip: out=%q err=%v", out, err)
	}
}

// keygen refuses to replace a key file unless told to. The old private key is
// the only thing that can decrypt what was encrypted with it, and this is the
// command that would destroy it.
func TestKeygenRefusesToOverwriteExistingKeys(t *testing.T) {
	cases := map[string]struct {
		setup func(t *testing.T)
		args  []string
		names []string // every path the error must name
	}{
		"both key files exist": {
			setup: func(t *testing.T) {},
			args:  []string{"keygen"},
			names: []string{"envisible.pub", "envisible.key"},
		},
		"only the private key exists": {
			setup: func(t *testing.T) { os.Remove("envisible.pub") },
			args:  []string{"keygen"},
			names: []string{"envisible.key"},
		},
		// A machine that only encrypts, or a KMS project: there is no private
		// key file, and the public key is still not keygen's to replace.
		"only the public key exists": {
			setup: func(t *testing.T) { os.Remove("envisible.key") },
			args:  []string{"keygen"},
			names: []string{"envisible.pub"},
		},
		"--print-key with an existing public key": {
			setup: func(t *testing.T) { os.Remove("envisible.key") },
			args:  []string{"keygen", "--print-key"},
			names: []string{"envisible.pub"},
		},
		"custom paths": {
			setup: func(t *testing.T) {
				os.Rename("envisible.pub", "team.pub")
				os.Rename("envisible.key", "team.key")
			},
			args:  []string{"--pub", "team.pub", "--key", "team.key", "keygen"},
			names: []string{"team.pub", "team.key"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			sealed := existingKeypair(t)
			withKeygenStdoutTTY(t, false)
			tc.setup(t)
			before := snapshotDir(t)

			stdout, _, err := runRoot(t, tc.args...)
			if err == nil {
				t.Fatal("keygen replaced an existing key without --force")
			}
			if !strings.Contains(err.Error(), "--force") {
				t.Errorf("error = %q, want it to say how to proceed (--force)", err)
			}
			for _, n := range tc.names {
				if !strings.Contains(err.Error(), n) {
					t.Errorf("error = %q, want it to name %s", err, n)
				}
			}
			if strings.TrimSpace(stdout) != "" {
				t.Errorf("a refused keygen wrote to stdout: %q", stdout)
			}
			assertDirUnchanged(t, before)
			if name == "both key files exist" {
				assertPairStillWorks(t, sealed)
			}
		})
	}
}

// A dangling symlink at the key path is still something in the way: the check
// uses Lstat, so keygen refuses rather than writing through or over the link.
func TestKeygenRefusesADanglingSymlinkAtTheKeyPath(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Symlink("nowhere", "envisible.key"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, _, err := runRoot(t, "keygen")
	if err == nil || !strings.Contains(err.Error(), "envisible.key already exists") {
		t.Fatalf("keygen error = %v, want a refusal naming envisible.key", err)
	}
	if target, lerr := os.Readlink("envisible.key"); lerr != nil || target != "nowhere" {
		t.Errorf("the symlink was replaced: target=%q err=%v", target, lerr)
	}
	if _, serr := os.Stat("envisible.pub"); !errors.Is(serr, os.ErrNotExist) {
		t.Errorf("a refused keygen created envisible.pub (stat err = %v)", serr)
	}
}

// With --print-key no private key file is written, so one that happens to
// exist is not in the way: only the public key path is checked.
func TestKeygenPrintKeyIgnoresAnExistingPrivateKeyFile(t *testing.T) {
	existingKeypair(t)
	withKeygenStdoutTTY(t, false)
	oldKey, _ := os.ReadFile("envisible.key")
	if err := os.Remove("envisible.pub"); err != nil {
		t.Fatal(err)
	}

	out, err := runKeygen(t, "--print-key")
	if err != nil {
		t.Fatalf("keygen --print-key: %v", err)
	}
	if strings.TrimSpace(out) == "" {
		t.Error("no private key on stdout")
	}
	if now, _ := os.ReadFile("envisible.key"); string(now) != string(oldKey) {
		t.Error("--print-key modified the existing envisible.key")
	}
}

// --force replaces both files with a new, working pair.
func TestKeygenForceReplacesTheKeypair(t *testing.T) {
	existingKeypair(t)
	oldPub, _ := os.ReadFile("envisible.pub")
	oldKey, _ := os.ReadFile("envisible.key")

	if _, err := runKeygen(t, "--force"); err != nil {
		t.Fatalf("keygen --force: %v", err)
	}
	newPub, _ := os.ReadFile("envisible.pub")
	newKey, _ := os.ReadFile("envisible.key")
	if string(newPub) == string(oldPub) || string(newKey) == string(oldKey) {
		t.Fatal("keygen --force did not replace both key files")
	}
	if err := os.WriteFile("probe.env", []byte("NEW=ENC[fresh-secret]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "encrypt", "-i", "probe.env")
	if out, _, err := runRoot(t, "decrypt", "--strip", "probe.env"); err != nil || !strings.Contains(out, "NEW=fresh-secret") {
		t.Errorf("the new pair does not round-trip: out=%q err=%v", out, err)
	}
}

// A first keygen, with nothing on disk, needs no flag.
func TestKeygenNeedsNoForceInAnEmptyDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := runKeygen(t); err != nil {
		t.Fatalf("keygen in an empty directory: %v", err)
	}
}
