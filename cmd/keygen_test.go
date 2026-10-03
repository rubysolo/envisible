package cmd

import (
	"bytes"
	"os"
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
