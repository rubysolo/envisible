package processor

import (
	"context"
	"strings"
	"testing"

	"github.com/rubysolo/envisible/pkg/crypto"
)

// envFixture is a keypair plus the helpers to build a .env file whose values
// are real ciphertext, which is the only way to test the parser honestly: the
// structure is resolved against the encrypted bytes, so the tests have to hand
// it encrypted bytes.
type envFixture struct {
	pub  [32]byte
	priv [32]byte
}

func newEnvFixture(t *testing.T) envFixture {
	t.Helper()
	pub, priv, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return envFixture{pub: pub, priv: priv}
}

// marker returns the on-disk ENC[v1:...] form of plaintext.
func (f envFixture) marker(t *testing.T, plaintext string) string {
	t.Helper()
	inner, err := NaclEncryptor{PublicKey: f.pub}.EncryptValue([]byte(plaintext))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	return "ENC[" + inner + "]"
}

func (f envFixture) extract(t *testing.T, content string) map[string]string {
	t.Helper()
	env, err := ExtractEnv(context.Background(), []byte(content), NaclDecryptor{PrivateKey: f.priv})
	if err != nil {
		t.Fatalf("ExtractEnv(%q): %v", content, err)
	}
	return env
}

// TestExtractEnvValueFidelity is the headline guarantee: the bytes that were
// encrypted are the bytes the child process gets. No trimming, no unquoting, no
// reinterpretation of any kind.
func TestExtractEnvValueFidelity(t *testing.T) {
	f := newEnvFixture(t)

	cases := map[string]string{
		"trailing space":      "sk_live_abc ",
		"leading space":       " sk_live_abc",
		"space on both ends":  "  sk_live_abc\t",
		"double quoted":       `"quoted"`,
		"single quoted":       `'quoted'`,
		"nested quotes":       `"'quoted'"`,
		"contains equals":     "a=b=c",
		"contains hash":       "pa#ss # not-a-comment",
		"contains apostrophe": "pa'ss",
		"contains quote":      `pa"ss`,
		"contains backslash":  `C:\Users\pa\\ss`,
		"contains brackets":   `{"scopes":["a","b"]}`,
		"empty":               "",
		"only whitespace":     "   ",
		"trailing newline":    "sk_live_abc\n",
		"not valid utf-8":     string([]byte{0xff, 0xfe, 0x00, 'a', 0x80}),
		"pem":                 "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\nBgkqhkiG9w0B\n-----END PRIVATE KEY-----\n",
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			env := f.extract(t, "SECRET="+f.marker(t, want)+"\n")
			if got := env["SECRET"]; got != want {
				t.Errorf("value was mangled:\n got %q\nwant %q", got, want)
			}
			if len(env) != 1 {
				t.Errorf("secret content added or removed keys: %v", env)
			}
		})
	}
}

// TestExtractEnvMultiLineValueAddsNoKeys pins the shape of the fidelity
// guarantee that matters most: a multi-line plaintext is one value, not a
// fragment of .env syntax.
func TestExtractEnvMultiLineValueAddsNoKeys(t *testing.T) {
	f := newEnvFixture(t)
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----"

	env := f.extract(t, "OTHER=plain\nKEY="+f.marker(t, pem)+"\nAFTER=tail\n")

	if env["KEY"] != pem {
		t.Errorf("multi-line value mangled:\n got %q\nwant %q", env["KEY"], pem)
	}
	if len(env) != 3 {
		t.Errorf("expected exactly OTHER, KEY and AFTER; got %v", env)
	}
	if env["OTHER"] != "plain" || env["AFTER"] != "tail" {
		t.Errorf("neighbouring lines were disturbed: %v", env)
	}
	for _, k := range []string{"MIIEvQIBADAN", "-----BEGIN PRIVATE KEY-----"} {
		if _, ok := env[k]; ok {
			t.Errorf("a line of the secret became a variable: %v", env)
		}
	}
}

// TestExtractEnvSecretCannotInjectAVariable is the injection regression. A
// secret whose plaintext contains a newline followed by KEY=value used to hand
// that variable to the child process; secret content must never control the
// environment of the process it is handed to.
func TestExtractEnvSecretCannotInjectAVariable(t *testing.T) {
	f := newEnvFixture(t)
	const plaintext = "hunter2\nPATH=/tmp/evil"

	env := f.extract(t, "PASSWORD="+f.marker(t, plaintext)+"\n")

	if env["PASSWORD"] != plaintext {
		t.Errorf("PASSWORD should be the whole two-line secret:\n got %q\nwant %q", env["PASSWORD"], plaintext)
	}
	if v, ok := env["PATH"]; ok {
		t.Errorf("secret content injected PATH=%q into the environment", v)
	}
	if len(env) != 1 {
		t.Errorf("expected exactly one variable, got %v", env)
	}
}

// TestExtractEnvQuotingAppliesToFileTextOnly: quoting is a property of how a
// value is written in the file, so it is applied to literal text and never to
// decrypted bytes — and exactly one pair comes off, never two.
func TestExtractEnvQuotingAppliesToFileTextOnly(t *testing.T) {
	f := newEnvFixture(t)

	cases := []struct {
		name, line, key, want string
	}{
		{"bare literal", "FOO=bar", "FOO", "bar"},
		{"double quoted literal", `FOO="bar"`, "FOO", "bar"},
		{"single quoted literal", `FOO='bar'`, "FOO", "bar"},
		{"only one pair comes off", `FOO="'bar'"`, "FOO", "'bar'"},
		{"unbalanced quote is content", `FOO="bar`, "FOO", `"bar`},
		{"surrounding whitespace is layout", "FOO=   bar   ", "FOO", "bar"},
		{"empty value", "FOO=", "FOO", ""},
		{"empty quoted value", `FOO=""`, "FOO", ""},
		{"literal keeps inner spaces", "FOO=a b c", "FOO", "a b c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := f.extract(t, tc.line+"\n")
			if got := env[tc.key]; got != tc.want {
				t.Errorf("%s: got %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

// TestExtractEnvQuotedMarkerIsNotUnquotedTwice: the quotes around the marker in
// the file come off, the quotes inside the secret stay on.
func TestExtractEnvQuotedMarkerIsNotUnquotedTwice(t *testing.T) {
	f := newEnvFixture(t)
	const secret = `"still quoted"`

	env := f.extract(t, `TOKEN="`+f.marker(t, secret)+`"`+"\n")

	if env["TOKEN"] != secret {
		t.Errorf("got %q, want %q", env["TOKEN"], secret)
	}
}

func TestExtractEnvStructure(t *testing.T) {
	f := newEnvFixture(t)
	m := f.marker(t, "s3cret")

	t.Run("export prefix", func(t *testing.T) {
		env := f.extract(t, "export FOO="+m+"\n")
		if env["FOO"] != "s3cret" {
			t.Errorf("`export FOO=` should define FOO; got %v", env)
		}
		if _, ok := env["export FOO"]; ok {
			t.Errorf("the shell keyword leaked into the key name: %v", env)
		}
		if len(env) != 1 {
			t.Errorf("expected exactly one variable, got %v", env)
		}
	})

	t.Run("export with extra whitespace", func(t *testing.T) {
		env := f.extract(t, "export\tFOO="+m+"\n")
		if env["FOO"] != "s3cret" {
			t.Errorf("got %v", env)
		}
	})

	t.Run("inline comment is stripped", func(t *testing.T) {
		env := f.extract(t, "FOO="+m+" # note\n")
		if env["FOO"] != "s3cret" {
			t.Errorf("comment text bled into the value: %q", env["FOO"])
		}
	})

	t.Run("inline comment after a literal", func(t *testing.T) {
		env := f.extract(t, "FOO=bar # note\n")
		if env["FOO"] != "bar" {
			t.Errorf("comment text bled into the value: %q", env["FOO"])
		}
	})

	t.Run("hash without leading space is content", func(t *testing.T) {
		env := f.extract(t, "FOO=bar#note\n")
		if env["FOO"] != "bar#note" {
			t.Errorf("got %q, want %q", env["FOO"], "bar#note")
		}
	})

	t.Run("commented-out assignment", func(t *testing.T) {
		env := f.extract(t, "# FOO="+m+"\nBAR=ok\n")
		if _, ok := env["FOO"]; ok {
			t.Errorf("a commented-out line defined a variable: %v", env)
		}
		if env["BAR"] != "ok" {
			t.Errorf("got %v", env)
		}
	})

	t.Run("marker embedded in a literal", func(t *testing.T) {
		env := f.extract(t, "DATABASE_URL=postgres://u:"+f.marker(t, "p@ss")+"@h/db\n")
		if want := "postgres://u:p@ss@h/db"; env["DATABASE_URL"] != want {
			t.Errorf("got %q, want %q", env["DATABASE_URL"], want)
		}
	})

	t.Run("two markers in one value", func(t *testing.T) {
		env := f.extract(t, "PAIR="+f.marker(t, "left")+"-"+f.marker(t, "right")+"\n")
		if want := "left-right"; env["PAIR"] != want {
			t.Errorf("got %q, want %q", env["PAIR"], want)
		}
	})

	t.Run("blank and whitespace-only lines", func(t *testing.T) {
		content := "\n   \n\t\nFOO=" + m + "\n\n  \n"
		env, defects, err := ExtractEnvWithDefects(context.Background(), []byte(content), NaclDecryptor{PrivateKey: f.priv})
		if err != nil {
			t.Fatalf("ExtractEnvWithDefects: %v", err)
		}
		if len(defects) != 0 {
			t.Errorf("blank lines are not defects: %+v", defects)
		}
		if len(env) != 1 || env["FOO"] != "s3cret" {
			t.Errorf("got %v", env)
		}
	})

	t.Run("no trailing newline", func(t *testing.T) {
		env := f.extract(t, "FOO="+m)
		if env["FOO"] != "s3cret" {
			t.Errorf("got %v", env)
		}
	})

	t.Run("key with surrounding whitespace", func(t *testing.T) {
		env := f.extract(t, "  FOO = "+m+"\n")
		if env["FOO"] != "s3cret" {
			t.Errorf("got %v", env)
		}
	})
}

// TestExtractEnvCRLF: a file with Windows line endings must not leave a '\r' on
// the end of every value. The old parser hid it behind TrimSpace; nothing hides
// it now, so it has to be handled as the line structure it is.
func TestExtractEnvCRLF(t *testing.T) {
	f := newEnvFixture(t)
	content := "FOO=" + f.marker(t, "secret") + "\r\nBAR=literal\r\n# comment\r\nBAZ=quoted \r\n"

	env := f.extract(t, content)

	for k, v := range env {
		if strings.ContainsRune(v, '\r') {
			t.Errorf("%s = %q still carries a carriage return", k, v)
		}
	}
	if env["FOO"] != "secret" || env["BAR"] != "literal" || env["BAZ"] != "quoted" {
		t.Errorf("CRLF file parsed wrong: %v", env)
	}
	if len(env) != 3 {
		t.Errorf("expected three variables, got %v", env)
	}
}

// TestExtractEnvReportsUnparsableLines: a line that is not an assignment is
// skipped out loud. It used to be dropped in silence, which is how a typo'd
// variable name becomes a missing credential at runtime.
func TestExtractEnvReportsUnparsableLines(t *testing.T) {
	f := newEnvFixture(t)

	cases := map[string]string{
		"invalid name":  "not-a-valid-name=x",
		"leading digit": "9LIVES=x",
		"no equals":     "JUST_A_WORD",
		"yaml-ish":      "password: hunter2",
		"empty name":    "=orphan",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			content := "GOOD=" + f.marker(t, "ok") + "\n" + line + "\n"
			env, defects, err := ExtractEnvWithDefects(context.Background(), []byte(content), NaclDecryptor{PrivateKey: f.priv})
			if err != nil {
				t.Fatalf("an unparsable line must not fail the read: %v", err)
			}
			if len(defects) != 1 || defects[0].Kind != MalformedEnvLine {
				t.Fatalf("defects = %+v, want one MalformedEnvLine", defects)
			}
			if line, col := LineCol([]byte(content), defects[0].Offset); line != 2 || col != 1 {
				t.Errorf("defect points at %d:%d, want 2:1", line, col)
			}
			if len(env) != 1 || env["GOOD"] != "ok" {
				t.Errorf("the healthy line must still load; got %v", env)
			}
		})
	}
}

// TestExtractEnvKeepsReportingMarkerDefects: the line-level defects are added
// to the scanner's, not swapped for them.
func TestExtractEnvKeepsReportingMarkerDefects(t *testing.T) {
	f := newEnvFixture(t)
	content := "GOOD=" + f.marker(t, "ok") + "\nBROKEN=ENC[oops\nnot a name\n"

	env, defects, err := ExtractEnvWithDefects(context.Background(), []byte(content), NaclDecryptor{PrivateKey: f.priv})
	if err != nil {
		t.Fatalf("ExtractEnvWithDefects: %v", err)
	}
	if len(defects) != 2 {
		t.Fatalf("defects = %+v, want two (the unterminated marker and the bare word)", defects)
	}
	if defects[0].Kind != Unterminated || defects[1].Kind != MalformedEnvLine {
		t.Errorf("defects should be ordered by offset with both kinds present, got %+v", defects)
	}
	if env["GOOD"] != "ok" {
		t.Errorf("a defect elsewhere must not stop the good values loading; got %v", env)
	}
}

// TestExtractEnvUnknownVersionIsLeftAsWritten: a marker this decryptor does not
// handle is text, exactly as it is on every other read path.
func TestExtractEnvUnknownVersionIsLeftAsWritten(t *testing.T) {
	f := newEnvFixture(t)
	content := "FUTURE=ENC[v9:c29tZXRoaW5n]\n"

	env := f.extract(t, content)

	if want := "ENC[v9:c29tZXRoaW5n]"; env["FUTURE"] != want {
		t.Errorf("got %q, want %q", env["FUTURE"], want)
	}
}

// TestExtractEnvPlaintextMarkerIsNotAValue: an un-encrypted marker is a file
// that has not been encrypted yet, not a secret. It reads as the literal text
// it is rather than silently becoming the value.
func TestExtractEnvPlaintextMarkerIsNotAValue(t *testing.T) {
	f := newEnvFixture(t)

	env := f.extract(t, "FOO=ENC[not-encrypted-yet]\n")

	if want := "ENC[not-encrypted-yet]"; env["FOO"] != want {
		t.Errorf("got %q, want %q", env["FOO"], want)
	}
}

// TestExtractEnvFailsOnUndecryptableMarker: a value that cannot be decrypted is
// an error, not an empty string quietly handed to the child.
func TestExtractEnvFailsOnUndecryptableMarker(t *testing.T) {
	f := newEnvFixture(t)

	env, err := ExtractEnv(context.Background(), []byte("FOO=ENC[v1:not-base64-at-all]\n"), NaclDecryptor{PrivateKey: f.priv})
	if err == nil {
		t.Fatalf("expected a decryption error, got env %v", env)
	}
	if env != nil {
		t.Errorf("no environment should be returned on failure; got %v", env)
	}
}
