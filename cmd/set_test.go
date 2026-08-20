package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rubysolo/envisible/pkg/kms"
	"github.com/rubysolo/envisible/pkg/processor"
)

// --- plan 05: `envisible set` ------------------------------------------------

// setOwnFlags are the flags declared by `set` itself. Named explicitly so the
// reset below cannot reach the root's persistent flags, which resetRoot owns.
var setOwnFlags = []string{"from-json", "from-env", "dry-run", "if-changed", "raw", "allow-empty"}

// resetSet wires stdin and clears `set`'s own flags. Cobra keeps a flag's value
// on the command object between Execute calls, so without this a --dry-run in
// one test would silently make a later test write nothing.
func resetSet(t *testing.T, out io.Writer, stdin string) {
	t.Helper()
	resetRootWithStdin(t, out, stdin)
	for _, name := range setOwnFlags {
		f := setCmd.Flags().Lookup(name)
		if f == nil {
			t.Fatalf("set has no --%s flag", name)
		}
		if err := f.Value.Set(f.DefValue); err != nil {
			t.Fatalf("reset --%s: %v", name, err)
		}
		f.Changed = false
	}
}

// runSet executes `envisible set ...` with stdin, returning the error and
// everything the command printed to the real stdout/stderr (where ui writes).
func runSet(t *testing.T, stdin string, args ...string) (err error, stdout, stderr string) {
	t.Helper()
	resetSet(t, nil, stdin)
	rootCmd.SetArgs(append([]string{"set"}, args...))
	stdout, stderr = captureStdStreams(t, func() { err = rootCmd.Execute() })
	return err, stdout, stderr
}

// envOf decrypts the file with whatever key the working directory offers and
// returns the variables `run` would export. Assertions about a value go through
// here — the point of `set` is that the value is not otherwise readable.
func envOf(t *testing.T, path string) map[string]string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	dec, err := loadDecryptor(context.Background())
	if err != nil {
		t.Fatalf("loadDecryptor: %v", err)
	}
	env, err := processor.ExtractEnv(context.Background(), content, dec)
	if err != nil {
		t.Fatalf("ExtractEnv(%s): %v", path, err)
	}
	return env
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

// --- core --------------------------------------------------------------------

func TestSetAppendsANewKeyAndLeavesTheRestOfTheFileAlone(t *testing.T) {
	setupKeyedTempDir(t)
	original := "# a comment worth keeping\nFIRST=one\n\nexport SECOND=two # inline\n"
	writeFile(t, ".env", original, 0644)

	err, _, _ := runSet(t, "sk_live_abc", ".env", "API_KEY", "-")
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	got := string(readFile(t, ".env"))
	if !strings.HasPrefix(got, original) {
		t.Errorf("the existing file was not preserved byte-for-byte:\n got %q\nwant prefix %q", got, original)
	}
	if !strings.Contains(got, "API_KEY=ENC[v1:") {
		t.Errorf("no v1 marker was appended: %q", got)
	}
	if strings.Contains(got, "sk_live_abc") {
		t.Fatalf("plaintext landed in the file: %q", got)
	}
	if env := envOf(t, ".env"); env["API_KEY"] != "sk_live_abc" {
		t.Errorf("API_KEY = %q, want %q", env["API_KEY"], "sk_live_abc")
	}
}

func TestSetUpdatesAnExistingKeyInPlace(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, ".env", "  export API_KEY=old-value   # rotate me\nOTHER=untouched\n", 0644)

	err, _, _ := runSet(t, "new-value\n", ".env", "API_KEY", "-")
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	got := string(readFile(t, ".env"))
	if !strings.HasPrefix(got, "  export API_KEY=ENC[v1:") {
		t.Errorf("indentation or the export prefix was lost: %q", got)
	}
	if !strings.Contains(got, "]   # rotate me\n") {
		t.Errorf("the inline comment and its spacing were lost: %q", got)
	}
	if !strings.HasSuffix(got, "OTHER=untouched\n") {
		t.Errorf("the unrelated line was disturbed: %q", got)
	}
	if strings.Contains(got, "old-value") || strings.Contains(got, "new-value") {
		t.Errorf("a plaintext value survived in the file: %q", got)
	}
	if env := envOf(t, ".env"); env["API_KEY"] != "new-value" {
		t.Errorf("API_KEY = %q, want %q", env["API_KEY"], "new-value")
	}
}

func TestSetCreatesAMissingFileWith0644AndOneTrailingNewline(t *testing.T) {
	setupKeyedTempDir(t)

	err, _, _ := runSet(t, "value", "fresh.env", "API_KEY", "-")
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	info, err := os.Stat("fresh.env")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0644 {
		t.Errorf("new file mode = %#o, want 0644", mode)
	}
	got := string(readFile(t, "fresh.env"))
	if !strings.HasSuffix(got, "]\n") || strings.HasSuffix(got, "\n\n") {
		t.Errorf("want exactly one trailing newline, got %q", got)
	}
	if strings.Count(got, "\n") != 1 {
		t.Errorf("want a single line, got %q", got)
	}
}

func TestSetPreservesTheExistingFileMode(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, ".env", "A=1\n", 0600)

	err, _, _ := runSet(t, "value", ".env", "API_KEY", "-")
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	info, err := os.Stat(".env")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("mode = %#o, want 0600 preserved", mode)
	}
}

func TestSetFromJSONWritesEveryKeyInOnePass(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, ".env", "EXISTING=plain\n", 0644)

	payload := `{"STRIPE_KEY":"sk_live_1","AWS_REGION":"us-east-1","EXISTING":"now encrypted"}`
	err, _, stderr := runSet(t, payload, ".env", "--from-json", "-")
	if err != nil {
		t.Fatalf("set --from-json: %v", err)
	}

	env := envOf(t, ".env")
	for key, want := range map[string]string{
		"STRIPE_KEY": "sk_live_1",
		"AWS_REGION": "us-east-1",
		"EXISTING":   "now encrypted",
	} {
		if env[key] != want {
			t.Errorf("%s = %q, want %q", key, env[key], want)
		}
	}
	if !contains(stderr, "EXISTING (updated)") || !contains(stderr, "STRIPE_KEY (added)") {
		t.Errorf("per-key report missing added/updated: %q", stderr)
	}
	if contains(stderr, "sk_live_1") {
		t.Errorf("a value reached stderr: %q", stderr)
	}
}

func TestSetFromEnvReadsDotenvShapedInput(t *testing.T) {
	setupKeyedTempDir(t)

	payload := "# a comment\nexport ALPHA=one\nBETA=\"two words\"\n"
	err, _, _ := runSet(t, payload, ".env", "--from-env", "-")
	if err != nil {
		t.Fatalf("set --from-env: %v", err)
	}

	env := envOf(t, ".env")
	if env["ALPHA"] != "one" {
		t.Errorf("ALPHA = %q, want %q", env["ALPHA"], "one")
	}
	if env["BETA"] != "two words" {
		t.Errorf("BETA = %q, want %q", env["BETA"], "two words")
	}
	if got := string(readFile(t, ".env")); contains(got, "two words") {
		t.Errorf("plaintext landed in the file: %q", got)
	}
}

// countingUnwrapper is the fake KMS. Encryption is supposed to be a purely
// local RSA-OAEP wrap, so any call here during `set` is a bug worth failing on.
type countingUnwrapper struct {
	priv  *rsa.PrivateKey
	calls *int
}

func (u countingUnwrapper) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	*u.calls++
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, u.priv, wrapped, nil)
}

// withCountingKMS is withFakeKMSProvider plus a call counter on the unwrap
// path.
func withCountingKMS(t *testing.T, priv *rsa.PrivateKey, resource string, calls *int) {
	t.Helper()
	oldUnwrap := kms.ReplaceUnwrapper(kms.GCP, func(_ context.Context, _ *kms.PublicKeyInfo) (kms.Unwrapper, error) {
		return countingUnwrapper{priv: priv, calls: calls}, nil
	})
	oldBootstrap := kms.ReplaceBootstrap(kms.GCP, func(_ context.Context, res string) (*kms.PublicKeyInfo, error) {
		return &kms.PublicKeyInfo{
			Kind:     kms.GCP,
			Resource: res,
			Alg:      kms.RSAOAEPSHA256_2048,
			PubKey:   &priv.PublicKey,
		}, nil
	})
	t.Cleanup(func() {
		kms.ReplaceUnwrapper(kms.GCP, oldUnwrap)
		kms.ReplaceBootstrap(kms.GCP, oldBootstrap)
	})
}

func TestSetInKMSModeWritesV2MarkersWithoutCallingTheKMS(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(oldWd) })

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	unwrapCalls := 0
	resource := "projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
	withCountingKMS(t, priv, resource, &unwrapCalls)

	resetRoot(nil)
	rootCmd.SetArgs([]string{"kms", "init", "--provider", "gcp", "--resource", resource})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("kms init: %v", err)
	}

	if err, _, _ := runSet(t, "kms-secret", ".env", "API_KEY", "-"); err != nil {
		t.Fatalf("set: %v", err)
	}

	got := string(readFile(t, ".env"))
	if !contains(got, "API_KEY=ENC[v2:") {
		t.Errorf("expected a v2 marker, got %q", got)
	}
	if contains(got, "kms-secret") {
		t.Errorf("plaintext landed in the file: %q", got)
	}
	if unwrapCalls != 0 {
		t.Errorf("set made %d KMS call(s); encryption must be local", unwrapCalls)
	}

	// And the value is recoverable by someone who does hold decrypt rights.
	if env := envOf(t, ".env"); env["API_KEY"] != "kms-secret" {
		t.Errorf("API_KEY = %q, want %q", env["API_KEY"], "kms-secret")
	}
}

// The headline capability: a developer with envisible.pub and no private key
// can still add and rotate secrets.
func TestSetWorksWithOnlyThePublicKeyPresent(t *testing.T) {
	setupKeyedTempDir(t)
	if err := os.Remove("envisible.key"); err != nil {
		t.Fatalf("remove private key: %v", err)
	}
	if _, err := os.Stat("envisible.key"); !os.IsNotExist(err) {
		t.Fatalf("the private key is still present; this test proves nothing")
	}

	err, _, _ := runSet(t, "no-private-key-needed", ".env", "API_KEY", "-")
	if err != nil {
		t.Fatalf("set with only envisible.pub: %v", err)
	}

	got := string(readFile(t, ".env"))
	if !contains(got, "API_KEY=ENC[v1:") {
		t.Errorf("expected ciphertext, got %q", got)
	}
	if contains(got, "no-private-key-needed") {
		t.Errorf("plaintext landed in the file: %q", got)
	}
}

// --- value fidelity ----------------------------------------------------------

func TestSetRoundTripsValuesExactly(t *testing.T) {
	cases := map[string]string{
		"closing bracket":  "secret]value",
		"open bracket":     "secret[value",
		"json blob":        `{"scopes":["a","b"]}`,
		"backslashes":      `C:\Users\me\key`,
		"equals and hash":  "a=b # not a comment",
		"quotes":           `"double" and 'single'`,
		"multi line pem":   "-----BEGIN KEY-----\nMIIEvQIBADAN\n-----END KEY-----",
		"leading spaces":   "   padded",
		"non utf8":         "\xff\xfe\x00binary",
		"looks like a var": "v1:not-ciphertext",
	}

	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			setupKeyedTempDir(t)

			err, stdout, stderr := runSet(t, plaintext, ".env", "SECRET", "-")
			if err != nil {
				t.Fatalf("set: %v", err)
			}
			got := string(readFile(t, ".env"))
			if contains(got, plaintext) {
				t.Fatalf("plaintext landed in the file: %q", got)
			}
			if contains(got, `\]`) || contains(got, `\[`) || contains(got, `\\`) {
				t.Errorf("the file carries escape sequences; the plaintext never entered the marker grammar: %q", got)
			}
			if contains(stdout, plaintext) || contains(stderr, plaintext) {
				t.Errorf("the value reached the terminal:\nstdout %q\nstderr %q", stdout, stderr)
			}
			if env := envOf(t, ".env"); env["SECRET"] != plaintext {
				t.Errorf("round trip mismatch:\n got %q\nwant %q", env["SECRET"], plaintext)
			}
		})
	}
}

func TestSetTrimsExactlyOneTrailingNewlineAndRawKeepsIt(t *testing.T) {
	cases := []struct {
		name  string
		stdin string
		raw   bool
		want  string
	}{
		{"one newline trimmed", "token\n", false, "token"},
		{"only one of two trimmed", "token\n\n", false, "token\n"},
		{"no newline unchanged", "token", false, "token"},
		{"raw keeps the newline", "token\n", true, "token\n"},
		{"multi line keeps shape", "line1\nline2\n", false, "line1\nline2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupKeyedTempDir(t)
			args := []string{".env", "TOKEN", "-"}
			if tc.raw {
				args = append([]string{"--raw"}, args...)
			}
			if err, _, _ := runSet(t, tc.stdin, args...); err != nil {
				t.Fatalf("set: %v", err)
			}
			if got := envOf(t, ".env")["TOKEN"]; got != tc.want {
				t.Errorf("TOKEN = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- guards ------------------------------------------------------------------

// The failure being guarded against is a destructive write: a producer that
// dies in a pipe closes it with no bytes, and a shell pipeline reports the last
// command's status. So the bytes of the file are the assertion, not the exit
// code alone.
func TestSetOnEmptyStdinLeavesTheFileByteIdentical(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, ".env", "API_KEY=ENC[v1:existing-and-precious]\n", 0644)
	before := readFile(t, ".env")

	err, stdout, stderr := runSet(t, "", ".env", "API_KEY", "-")
	if err == nil {
		t.Fatal("empty stdin must be an error")
	}
	if after := readFile(t, ".env"); !bytes.Equal(before, after) {
		t.Errorf("the file was rewritten on empty stdin:\nbefore %q\n after %q", before, after)
	}
	if contains(stdout, "ENC[") {
		t.Errorf("unexpected stdout: %q", stdout)
	}
	_ = stderr
}

func TestSetAllowEmptyWritesAnEmptyValue(t *testing.T) {
	setupKeyedTempDir(t)

	err, _, _ := runSet(t, "", ".env", "--allow-empty", "API_KEY", "-")
	if err != nil {
		t.Fatalf("set --allow-empty: %v", err)
	}
	if got := string(readFile(t, ".env")); !contains(got, "API_KEY=ENC[v1:") {
		t.Errorf("expected a marker, got %q", got)
	}
	if got := envOf(t, ".env")["API_KEY"]; got != "" {
		t.Errorf("API_KEY = %q, want an empty value", got)
	}
}

func TestSetRefusesATerminal(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, ".env", "A=1\n", 0644)
	before := readFile(t, ".env")

	orig := isTerminal
	isTerminal = func(*os.File) bool { return true }
	t.Cleanup(func() { isTerminal = orig })

	resetSet(t, nil, "")
	// The seam is only consulted for an *os.File; a buffer never reaches it.
	rootCmd.SetIn(os.Stdin)
	t.Cleanup(func() { rootCmd.SetIn(os.Stdin) })
	rootCmd.SetArgs([]string{"set", ".env", "API_KEY", "-"})
	err := rootCmd.Execute()

	if err == nil {
		t.Fatal("set on a terminal should be refused, not hang")
	}
	if !contains(err.Error(), "refusing to read from a terminal") {
		t.Errorf("unexpected error: %v", err)
	}
	if after := readFile(t, ".env"); !bytes.Equal(before, after) {
		t.Errorf("the file changed on a refused run")
	}
}

func TestSetRejectsAnInvalidKeyNameBeforeAnyWrite(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, ".env", "A=1\n", 0644)
	before := readFile(t, ".env")

	for _, key := range []string{"9LIVES", "API-KEY", "API KEY", "api.key"} {
		err, _, _ := runSet(t, "value", ".env", key, "-")
		if err == nil {
			t.Errorf("set accepted the invalid key %q", key)
			continue
		}
		if !contains(err.Error(), "invalid key name") {
			t.Errorf("unexpected error for %q: %v", key, err)
		}
	}
	if after := readFile(t, ".env"); !bytes.Equal(before, after) {
		t.Errorf("a rejected key still rewrote the file:\nbefore %q\n after %q", before, after)
	}
}

func TestSetRejectsAJSONPayloadKeyThatIsNotAVariableName(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, ".env", "A=1\n", 0644)
	before := readFile(t, ".env")

	err, _, _ := runSet(t, `{"ok":"1","not a name":"2"}`, ".env", "--from-json", "-")
	if err == nil {
		t.Fatal("a payload with an invalid key must be rejected")
	}
	if after := readFile(t, ".env"); !bytes.Equal(before, after) {
		t.Errorf("a partially valid payload wrote anyway: %q", after)
	}
}

func TestSetRejectsAYAMLTargetAndPointsAtEdit(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, "config.yaml", "---\npassword: ENC[v1:abc]\napi_key: ENC[v1:def]\n", 0644)
	before := readFile(t, "config.yaml")

	err, _, _ := runSet(t, "value", "config.yaml", "API_KEY", "-")
	if err == nil {
		t.Fatal("a YAML target must be refused")
	}
	if !contains(err.Error(), "envisible edit") {
		t.Errorf("the error should point at `edit`; got %v", err)
	}
	if after := readFile(t, "config.yaml"); !bytes.Equal(before, after) {
		t.Errorf("the YAML file was modified: %q", after)
	}
}

// There is no --value flag, and forgetting the trailing "-" is an error rather
// than a prompt or a hang.
func TestSetRequiresTheStdinMarker(t *testing.T) {
	setupKeyedTempDir(t)

	err, _, _ := runSet(t, "value", ".env", "API_KEY")
	if err == nil {
		t.Fatal("set without the trailing '-' should fail")
	}
	if !contains(err.Error(), "stdin") {
		t.Errorf("the error should explain the stdin-only rule; got %v", err)
	}
	if _, statErr := os.Stat(".env"); !os.IsNotExist(statErr) {
		t.Errorf(".env should not have been created")
	}

	resetSet(t, nil, "")
	rootCmd.SetArgs([]string{"set", "--value", "hunter2", "API_KEY"})
	if err := rootCmd.Execute(); err == nil {
		t.Error("--value must not exist: an argument is visible in ps")
	}
}

// --- behavioral --------------------------------------------------------------

// --dry-run is a gate, shaped like `check`: the report goes to stdout where -q
// cannot silence it, and the exit code says whether anything would change.
func TestSetDryRunWritesNothingAndReportsTheActions(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, ".env", "EXISTING=ENC[v1:abc]\n", 0644)
	before := readFile(t, ".env")

	out := &bytes.Buffer{}
	resetSet(t, out, `{"EXISTING":"a","BRAND_NEW":"b"}`)
	rootCmd.SetArgs([]string{"-q", "set", ".env", "--dry-run", "--from-json", "-"})
	var err error
	_, stderr := captureStdStreams(t, func() { err = rootCmd.Execute() })

	if err == nil {
		t.Fatal("--dry-run with a change must exit non-zero, like `check`")
	}
	if !contains(err.Error(), "dry run") {
		t.Errorf("the error should say it was a dry run: %v", err)
	}
	if after := readFile(t, ".env"); !bytes.Equal(before, after) {
		t.Errorf("--dry-run wrote to the file:\nbefore %q\n after %q", before, after)
	}
	want := "added\tBRAND_NEW\t.env\nupdated\tEXISTING\t.env\n"
	if out.String() != want {
		t.Errorf("stdout report under -q:\n got %q\nwant %q", out.String(), want)
	}
	if contains(out.String(), "\"a\"") || contains(stderr, "\"a\"") {
		t.Errorf("a value reached the terminal:\nstdout %q\nstderr %q", out.String(), stderr)
	}
}

func TestSetDryRunWithNothingToChangeExitsZero(t *testing.T) {
	setupKeyedTempDir(t)
	if err, _, _ := runSet(t, "stable", ".env", "API_KEY", "-"); err != nil {
		t.Fatalf("initial set: %v", err)
	}

	out := &bytes.Buffer{}
	resetSet(t, out, "stable")
	rootCmd.SetArgs([]string{"-q", "set", ".env", "--dry-run", "--if-changed", "API_KEY", "-"})
	var err error
	captureStdStreams(t, func() { err = rootCmd.Execute() })

	if err != nil {
		t.Fatalf("--dry-run with no change must exit 0: %v", err)
	}
	if want := "unchanged\tAPI_KEY\t.env\n"; out.String() != want {
		t.Errorf("stdout = %q, want %q", out.String(), want)
	}
}

func TestSetIfChangedWithAnUnchangedValueLeavesTheFileByteIdentical(t *testing.T) {
	setupKeyedTempDir(t)

	if err, _, _ := runSet(t, "stable-value", ".env", "API_KEY", "-"); err != nil {
		t.Fatalf("initial set: %v", err)
	}
	before := readFile(t, ".env")

	err, _, stderr := runSet(t, "stable-value", ".env", "--if-changed", "API_KEY", "-")
	if err != nil {
		t.Fatalf("set --if-changed: %v", err)
	}
	if after := readFile(t, ".env"); !bytes.Equal(before, after) {
		t.Errorf("--if-changed churned an unchanged value:\nbefore %q\n after %q", before, after)
	}
	if !contains(stderr, "API_KEY (unchanged)") {
		t.Errorf("the report should say the key was unchanged: %q", stderr)
	}

	// And a genuinely different value still gets written.
	if err, _, _ := runSet(t, "rotated", ".env", "--if-changed", "API_KEY", "-"); err != nil {
		t.Fatalf("set --if-changed (rotated): %v", err)
	}
	if bytes.Equal(before, readFile(t, ".env")) {
		t.Error("--if-changed skipped a value that did change")
	}
	if got := envOf(t, ".env")["API_KEY"]; got != "rotated" {
		t.Errorf("API_KEY = %q, want %q", got, "rotated")
	}
}

// --if-changed must never silently degrade into a full rewrite when it cannot
// read the current value.
func TestSetIfChangedWithoutDecryptCapabilityFailsClearly(t *testing.T) {
	setupKeyedTempDir(t)
	if err, _, _ := runSet(t, "value", ".env", "API_KEY", "-"); err != nil {
		t.Fatalf("initial set: %v", err)
	}
	if err := os.Remove("envisible.key"); err != nil {
		t.Fatalf("remove private key: %v", err)
	}
	before := readFile(t, ".env")

	err, _, _ := runSet(t, "value", ".env", "--if-changed", "API_KEY", "-")
	if err == nil {
		t.Fatal("--if-changed without decrypt capability must fail")
	}
	if !contains(err.Error(), "--if-changed") || !contains(err.Error(), "decrypt") {
		t.Errorf("the error should name the flag and the missing capability; got %v", err)
	}
	if after := readFile(t, ".env"); !bytes.Equal(before, after) {
		t.Errorf("it degraded into a rewrite:\nbefore %q\n after %q", before, after)
	}
}

// Every path — success, refusal, dry run — is checked for the one thing that
// must never appear.
func TestSetNeverPrintsAValue(t *testing.T) {
	setupKeyedTempDir(t)
	const secret = "correct-horse-battery-staple"

	runs := []struct {
		name  string
		stdin string
		args  []string
	}{
		{"plain set", secret, []string{".env", "API_KEY", "-"}},
		{"update", secret, []string{".env", "API_KEY", "-"}},
		{"dry run", secret, []string{".env", "--dry-run", "API_KEY", "-"}},
		{"if-changed", secret, []string{".env", "--if-changed", "API_KEY", "-"}},
		{"from-json", `{"API_KEY":"` + secret + `"}`, []string{".env", "--from-json", "-"}},
		{"from-env", "API_KEY=" + secret + "\n", []string{".env", "--from-env", "-"}},
		{"bad key", secret, []string{".env", "9BAD", "-"}},
		{"bad json", secret, []string{".env", "--from-json", "-"}},
	}
	for _, r := range runs {
		t.Run(r.name, func(t *testing.T) {
			_, stdout, stderr := runSet(t, r.stdin, r.args...)
			if contains(stdout, secret) {
				t.Errorf("the value reached stdout: %q", stdout)
			}
			if contains(stderr, secret) {
				t.Errorf("the value reached stderr: %q", stderr)
			}
		})
	}
}

// --- cross-command -----------------------------------------------------------

func TestSetThenRunExportsTheExactValue(t *testing.T) {
	setupKeyedTempDir(t)
	const secret = "line one\nline two ]with a bracket"

	if err, _, _ := runSet(t, secret, ".env", "--raw", "SECRET", "-"); err != nil {
		t.Fatalf("set: %v", err)
	}

	out := bytes.NewBufferString("")
	resetRoot(out)
	rootCmd.SetArgs([]string{"run", "-f", ".env", "--", "sh", "-c", `printf '<%s>' "$SECRET"`})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("run: %v", err)
	}
	if want := "<" + secret + ">"; out.String() != want {
		t.Errorf("run exported %q, want %q", out.String(), want)
	}
}

func TestSetThenCheckPasses(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, ".env", "# header\nPLAIN=not-a-secret\n", 0644)

	if err, _, _ := runSet(t, "sk_live_x", ".env", "API_KEY", "-"); err != nil {
		t.Fatalf("set: %v", err)
	}

	resetRoot(nil)
	rootCmd.SetArgs([]string{"check", "--verify", ".env"})
	var checkErr error
	captureStdStreams(t, func() { checkErr = rootCmd.Execute() })
	if checkErr != nil {
		t.Errorf("check --verify on a set-written file: %v", checkErr)
	}
}

// Encryption is randomized, so a second set of the same value rewrites the
// marker. This is the churn the plan calls out; it is a property, not a bug.
func TestSetTwiceWithTheSameValueProducesDifferentCiphertext(t *testing.T) {
	setupKeyedTempDir(t)

	if err, _, _ := runSet(t, "same", ".env", "API_KEY", "-"); err != nil {
		t.Fatalf("first set: %v", err)
	}
	first := readFile(t, ".env")

	if err, _, _ := runSet(t, "same", ".env", "API_KEY", "-"); err != nil {
		t.Fatalf("second set: %v", err)
	}
	second := readFile(t, ".env")

	if bytes.Equal(first, second) {
		t.Error("the ciphertext did not change; encryption should be randomized")
	}
	if got := envOf(t, ".env")["API_KEY"]; got != "same" {
		t.Errorf("API_KEY = %q, want %q", got, "same")
	}
}

// `set` with no file argument writes the global -f / .env target, like every
// other command.
func TestSetUsesTheGlobalFileTarget(t *testing.T) {
	setupKeyedTempDir(t)

	if err, _, _ := runSet(t, "value", "API_KEY", "-"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := envOf(t, ".env")["API_KEY"]; got != "value" {
		t.Errorf("API_KEY = %q, want %q", got, "value")
	}

	if err, _, _ := runSet(t, "other", "-f", "other.env", "API_KEY", "-"); err != nil {
		t.Fatalf("set -f: %v", err)
	}
	if got := envOf(t, "other.env")["API_KEY"]; got != "other" {
		t.Errorf("API_KEY in other.env = %q, want %q", got, "other")
	}
}

// --- plan 06: bring `set` in line with the rest of the CLI --------------------

// `set` is a write path, and the one a pub-key-only developer uses: the bytes
// of the target are the assertion, because they cannot check their own work.
func TestSetRefusesADefectiveTargetAndWritesNothing(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, "d.env", "A=ENC[oops\nB=1\n", 0644)
	before := readFile(t, "d.env")

	err, _, _ := runSet(t, "v", "d.env", "B", "-")
	if err == nil {
		t.Fatal("set into a file with an unterminated marker must fail, like encrypt and check do")
	}
	if !contains(err.Error(), "d.env:1:3") {
		t.Errorf("the error should carry file:line:col; got %v", err)
	}
	if after := readFile(t, "d.env"); !bytes.Equal(before, after) {
		t.Errorf("the defective target was rewritten:\nbefore %q\n after %q", before, after)
	}
}

func TestSetFromEnvPayloadErrorNamesStdinAndNotRun(t *testing.T) {
	setupKeyedTempDir(t)

	err, _, _ := runSet(t, "A=1\nnot an assignment\n", "x.env", "--from-env", "-")
	if err == nil {
		t.Fatal("a malformed payload line must be rejected")
	}
	if !contains(err.Error(), stdinDisplayName+":2:1") {
		t.Errorf("the error should locate the line in <stdin>; got %v", err)
	}
	if contains(err.Error(), "`run`") || contains(err.Error(), "skipped") {
		t.Errorf("the error describes `run`, a command the user did not invoke: %v", err)
	}
	if _, statErr := os.Stat("x.env"); !os.IsNotExist(statErr) {
		t.Error("x.env should not have been created")
	}
}

func TestSetWarnsOnAnUnmatchedTrailingBracketButStillWrites(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, ".env", "A=ENC[ab]cd]\n", 0644)

	err, _, stderr := runSet(t, "v", ".env", "B", "-")
	if err != nil {
		t.Fatalf("an ambiguous-but-legal marker must not block the write: %v", err)
	}
	if !contains(stderr, "unmatched ']'") {
		t.Errorf("expected the ambiguity warning encrypt would give; stderr %q", stderr)
	}
	if got := string(readFile(t, ".env")); !contains(got, "B=ENC[v1:") {
		t.Errorf("the write did not happen: %q", got)
	}
}

func TestSetFollowsASymlinkedTarget(t *testing.T) {
	setupKeyedTempDir(t)
	writeFile(t, "real.env", "A=1\n", 0600)
	if err := os.Symlink("real.env", "link.env"); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err, _, _ := runSet(t, "x", "link.env", "A", "-"); err != nil {
		t.Fatalf("set: %v", err)
	}

	if info, err := os.Lstat("link.env"); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link.env is no longer a symlink: the link was replaced instead of followed")
	}
	if got := string(readFile(t, "real.env")); !contains(got, "A=ENC[v1:") {
		t.Errorf("the symlink's target was not updated: %q", got)
	}
	info, err := os.Stat("real.env")
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("target mode = %#o, want 0600 preserved", mode)
	}
	if got := envOf(t, "link.env")["A"]; got != "x" {
		t.Errorf("A via the link = %q, want %q", got, "x")
	}
}

func TestSetRefusesADanglingSymlink(t *testing.T) {
	setupKeyedTempDir(t)
	if err := os.Symlink("nowhere.env", "dangling.env"); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err, _, _ := runSet(t, "x", "dangling.env", "A", "-")
	if err == nil {
		t.Fatal("a dangling symlink must be an explicit error, not a new regular file")
	}
	if !contains(err.Error(), "symlink") {
		t.Errorf("the error should say why; got %v", err)
	}
	if _, statErr := os.Stat("nowhere.env"); !os.IsNotExist(statErr) {
		t.Error("the dangling target was created")
	}
	if info, err := os.Lstat("dangling.env"); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Error("the dangling link itself was replaced")
	}
}

// In payload mode the lone positional is a file. One that looks like a KEY is a
// typo, and the wrong outcome is a file named MYKEY full of secrets.
func TestSetPayloadModeRejectsAPositionalThatLooksLikeAKey(t *testing.T) {
	setupKeyedTempDir(t)

	err, _, _ := runSet(t, `{"A":"1"}`, "--from-json", "MYKEY", "-")
	if err == nil {
		t.Fatal("`set --from-json MYKEY -` must not succeed")
	}
	if !contains(err.Error(), "--from-json takes a file, not a key") {
		t.Errorf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat("MYKEY"); !os.IsNotExist(statErr) {
		t.Error("a file named MYKEY was created")
	}

	// The documented route around a false rejection.
	if err, _, _ := runSet(t, `{"A":"1"}`, "--from-json", "./MYKEY", "-"); err != nil {
		t.Fatalf("./MYKEY should be accepted as a path: %v", err)
	}
	if got := envOf(t, "MYKEY")["A"]; got != "1" {
		t.Errorf("A = %q, want %q", got, "1")
	}
}

func TestSetEmptyPayloadValueErrorNamesTheKeyNotStdin(t *testing.T) {
	setupKeyedTempDir(t)

	err, _, _ := runSet(t, `{"A":""}`, "y.env", "--from-json", "-")
	if err == nil {
		t.Fatal("an empty payload value must be refused without --allow-empty")
	}
	if !contains(err.Error(), "for A") || !contains(err.Error(), "--from-json payload") {
		t.Errorf("the error should name the key and the payload; got %v", err)
	}
	if contains(err.Error(), "stdin carried no bytes") {
		t.Errorf("stdin carried a perfectly good payload; the error claims otherwise: %v", err)
	}
	if _, statErr := os.Stat("y.env"); !os.IsNotExist(statErr) {
		t.Error("y.env should not have been created")
	}
}

func TestSetTerminalRefusalDoesNotSuggestAFilePath(t *testing.T) {
	setupKeyedTempDir(t)

	orig := isTerminal
	isTerminal = func(*os.File) bool { return true }
	t.Cleanup(func() { isTerminal = orig })

	resetSet(t, nil, "")
	rootCmd.SetIn(os.Stdin)
	t.Cleanup(func() { rootCmd.SetIn(os.Stdin) })
	rootCmd.SetArgs([]string{"set", ".env", "API_KEY", "-"})
	err := rootCmd.Execute()

	if err == nil {
		t.Fatal("expected the terminal refusal")
	}
	if contains(err.Error(), "pass a file path") {
		t.Errorf("set cannot take the value from a file; the remedy is wrong: %v", err)
	}
	if !contains(err.Error(), "pipe") {
		t.Errorf("the remedy should tell the user to pipe the value: %v", err)
	}
}
