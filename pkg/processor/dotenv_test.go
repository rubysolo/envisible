package processor

import (
	"context"
	"strings"
	"testing"
)

// upsertMarker encrypts plaintext and splices it into content under key, which
// is exactly what `envisible set` does. Tests that assert on the *result* of a
// set go through here so they exercise the real path rather than a hand-written
// marker.
func (f envFixture) upsert(t *testing.T, content, key, plaintext string) (string, Action) {
	t.Helper()
	inner, err := NaclEncryptor{PublicKey: f.pub}.EncryptValue([]byte(plaintext))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	out, action := Upsert([]byte(content), key, WrapMarker(inner))
	return string(out), action
}

func TestUpsertAppendsAnUnknownKey(t *testing.T) {
	content := "# a leading comment\nFIRST=one\n\n# another\nSECOND=two\n"
	raw, action := Upsert([]byte(content), "THIRD", "ENC[v1:abc]")
	out := string(raw)

	if action != Added {
		t.Errorf("action = %v, want Added", action)
	}
	if !strings.HasPrefix(out, content) {
		t.Errorf("the original bytes were not preserved verbatim:\n got %q\nwant prefix %q", out, content)
	}
	if out != content+"THIRD=ENC[v1:abc]\n" {
		t.Errorf("append mismatch:\n got %q\nwant %q", out, content+"THIRD=ENC[v1:abc]\n")
	}
}

func TestUpsertPreservesExportIndentationAndInlineComment(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"plain":            {"FOO=old\n", "FOO=ENC[v1:new]\n"},
		"export prefix":    {"export FOO=old\n", "export FOO=ENC[v1:new]\n"},
		"indented":         {"    FOO=old\n", "    FOO=ENC[v1:new]\n"},
		"inline comment":   {"FOO=old # keep me\n", "FOO=ENC[v1:new] # keep me\n"},
		"spacing around =": {"FOO =  old\n", "FOO =  ENC[v1:new]\n"},
		"double quoted":    {"FOO=\"old\"\n", "FOO=ENC[v1:new]\n"},
		"single quoted":    {"FOO='old'\n", "FOO=ENC[v1:new]\n"},
		"empty value":      {"FOO=\n", "FOO=ENC[v1:new]\n"},
		"no trailing nl":   {"FOO=old", "FOO=ENC[v1:new]"},
		"crlf":             {"FOO=old\r\n", "FOO=ENC[v1:new]\r\n"},
		"export + comment": {"  export FOO=old\t# note\n", "  export FOO=ENC[v1:new]\t# note\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out, action := Upsert([]byte(tc.in), "FOO", "ENC[v1:new]")
			if action != Updated {
				t.Errorf("action = %v, want Updated", action)
			}
			if out := string(out); out != tc.want {
				t.Errorf("layout not preserved:\n got %q\nwant %q", out, tc.want)
			}
		})
	}
}

func TestUpsertLeavesEverySurroundingLineAlone(t *testing.T) {
	content := "# top\nA=1\nexport B=2 # b's note\n\nC=3\n"
	out, _ := Upsert([]byte(content), "B", "ENC[v1:xyz]")

	want := "# top\nA=1\nexport B=ENC[v1:xyz] # b's note\n\nC=3\n"
	if string(out) != want {
		t.Errorf("neighbouring lines changed:\n got %q\nwant %q", string(out), want)
	}
}

func TestUpsertOnEmptyContentProducesOneAssignment(t *testing.T) {
	out, action := Upsert(nil, "FOO", "ENC[v1:abc]")
	if action != Added {
		t.Errorf("action = %v, want Added", action)
	}
	if string(out) != "FOO=ENC[v1:abc]\n" {
		t.Errorf("got %q, want %q", string(out), "FOO=ENC[v1:abc]\n")
	}
}

func TestUpsertAddsTheMissingTrailingNewlineBeforeAppending(t *testing.T) {
	out, _ := Upsert([]byte("A=1"), "B", "ENC[v1:abc]")
	want := "A=1\nB=ENC[v1:abc]\n"
	if string(out) != want {
		t.Errorf("got %q, want %q", string(out), want)
	}
	if strings.HasSuffix(string(out), "\n\n") {
		t.Errorf("a second trailing newline was added: %q", string(out))
	}
}

// A duplicated key is resolved last-wins by ExtractEnv, so that is the
// occurrence Upsert has to rewrite. Rewriting any other one would leave the
// file looking updated while `run` kept handing out the stale value.
func TestUpsertRewritesTheOccurrenceExtractEnvResolves(t *testing.T) {
	f := newEnvFixture(t)
	firstMarker := f.marker(t, "first")
	content := "FOO=" + firstMarker + "\nFOO=" + f.marker(t, "second") + "\n"

	out, action := f.upsert(t, content, "FOO", "third")
	if action != Updated {
		t.Fatalf("action = %v, want Updated", action)
	}
	env := f.extract(t, out)
	if env["FOO"] != "third" {
		t.Errorf("FOO = %q, want %q — the effective occurrence was not the one rewritten", env["FOO"], "third")
	}
	if !strings.Contains(out, "FOO="+firstMarker) {
		t.Errorf("the shadowed first occurrence should be untouched: %q", out)
	}
}

func TestUpsertIgnoresACommentedOutKey(t *testing.T) {
	content := "# FOO=old-and-commented\nBAR=1\n"
	out, action := Upsert([]byte(content), "FOO", "ENC[v1:abc]")

	if action != Added {
		t.Errorf("action = %v, want Added — a commented line is not an assignment", action)
	}
	want := content + "FOO=ENC[v1:abc]\n"
	if string(out) != want {
		t.Errorf("got %q, want %q", string(out), want)
	}
}

// The whole reason `set` exists: the plaintext never enters the marker grammar,
// so no value can need escaping and none is ever applied.
func TestUpsertRoundTripsAnyValueWithoutEscaping(t *testing.T) {
	f := newEnvFixture(t)
	cases := map[string]string{
		"closing bracket":  "secret]value",
		"open bracket":     "secret[value",
		"both brackets":    `{"scopes":["a","b"]}`,
		"backslashes":      `C:\Users\me\key`,
		"escape lookalike": `already\]escaped`,
		"equals sign":      "a=b=c",
		"hash":             "value # not a comment",
		"quotes":           `"quoted" and 'quoted'`,
		"looks versioned":  "v1:not-really-ciphertext",
		"multi line PEM":   "-----BEGIN KEY-----\nMIIEvQIBADAN\n-----END KEY-----",
		"trailing newline": "value\n",
		"trailing space":   "value ",
		"non utf8":         "\xff\xfe\x00binary",
		"empty":            "",
	}

	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			out, action := f.upsert(t, "PRE=1\n", "SECRET", plaintext)
			if action != Added {
				t.Fatalf("action = %v, want Added", action)
			}
			if strings.Contains(out, plaintext) && plaintext != "" {
				t.Errorf("plaintext leaked into the file: %q", out)
			}
			if strings.Contains(out, `\]`) || strings.Contains(out, `\[`) || strings.Contains(out, `\\`) {
				t.Errorf("the file contains escape sequences; the plaintext should never have entered the marker grammar: %q", out)
			}
			env := f.extract(t, out)
			if env["SECRET"] != plaintext {
				t.Errorf("round trip mismatch:\n got %q\nwant %q", env["SECRET"], plaintext)
			}
			if env["PRE"] != "1" {
				t.Errorf("the unrelated key was disturbed: %q", env["PRE"])
			}
		})
	}
}

// Two writes of the same value produce different ciphertext — encryption is
// randomized. Documented here so the churn is a known property rather than a
// surprise in a diff.
func TestUpsertTwiceWithTheSameValueChurnsTheCiphertext(t *testing.T) {
	f := newEnvFixture(t)
	first, _ := f.upsert(t, "", "FOO", "same")
	second, _ := f.upsert(t, first, "FOO", "same")

	if first == second {
		t.Errorf("identical ciphertext across two writes; encryption should be randomized")
	}
	if got := f.extract(t, second)["FOO"]; got != "same" {
		t.Errorf("FOO = %q, want %q", got, "same")
	}
}

func TestLookupValueAgreesWithExtractEnv(t *testing.T) {
	f := newEnvFixture(t)
	content := "# note\nexport FOO=" + f.marker(t, "foo]value") + " # inline\nBAR=plain\n"

	dec := NaclDecryptor{PrivateKey: f.priv}
	for _, key := range []string{"FOO", "BAR"} {
		got, found, err := LookupValue(context.Background(), []byte(content), key, dec)
		if err != nil {
			t.Fatalf("LookupValue(%s): %v", key, err)
		}
		if !found {
			t.Fatalf("LookupValue(%s): not found", key)
		}
		if want := f.extract(t, content)[key]; got != want {
			t.Errorf("LookupValue(%s) = %q, ExtractEnv says %q", key, got, want)
		}
	}
}

func TestLookupValueReportsAMissingKey(t *testing.T) {
	f := newEnvFixture(t)
	_, found, err := LookupValue(context.Background(), []byte("FOO=1\n"), "NOPE", NaclDecryptor{PrivateKey: f.priv})
	if err != nil {
		t.Fatalf("LookupValue: %v", err)
	}
	if found {
		t.Error("found a key that is not in the file")
	}
}

// A key that is only present in a comment is not present.
func TestLookupValueIgnoresCommentedAssignments(t *testing.T) {
	f := newEnvFixture(t)
	content := "# FOO=" + f.marker(t, "shhh") + "\n"
	_, found, err := LookupValue(context.Background(), []byte(content), "FOO", NaclDecryptor{PrivateKey: f.priv})
	if err != nil {
		t.Fatalf("LookupValue: %v", err)
	}
	if found {
		t.Error("a commented-out assignment was treated as live")
	}
}

func TestLooksLikeDotenv(t *testing.T) {
	cases := map[string]struct {
		content string
		want    bool
	}{
		"empty":               {"", true},
		"whitespace only":     {"\n \t\n", true},
		"comments only":       {"# just a note\n", true},
		"plain assignments":   {"A=1\nB=2\n", true},
		"export assignments":  {"export A=1\n", true},
		"toml-ish":            {"key = \"value\"\n", true},
		"one bad line is ok":  {"A=1\nnot an assignment\n", true},
		"yaml document start": {"---\nfoo: bar\n", false},
		"yaml mapping":        {"password: ENC[v1:abc]\napi_key: ENC[v1:def]\n", false},
		"json object":         {"{\n  \"a\": 1\n}\n", false},
		"json array":          {"[1, 2, 3]\n", false},
		"prose":               {"this file is not a dotenv file at all\n", false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := LooksLikeDotenv([]byte(tc.content)); got != tc.want {
				t.Errorf("LooksLikeDotenv(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

func TestValidEnvName(t *testing.T) {
	valid := []string{"FOO", "_foo", "a1", "A_B_2", "_"}
	invalid := []string{"", "1FOO", "FOO-BAR", "FOO BAR", "FOO=BAR", "export FOO", "FOO.BAR", "FÖÖ"}

	for _, s := range valid {
		if !ValidEnvName(s) {
			t.Errorf("ValidEnvName(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if ValidEnvName(s) {
			t.Errorf("ValidEnvName(%q) = true, want false", s)
		}
	}
}

func TestActionString(t *testing.T) {
	for action, want := range map[Action]string{Added: "added", Updated: "updated", Unchanged: "unchanged"} {
		if got := action.String(); got != want {
			t.Errorf("Action(%d).String() = %q, want %q", action, got, want)
		}
	}
}

// The write paths must learn about a damaged file from the same call that
// locates their line, so the defects are returned rather than dropped.
func TestDotenvEntryPointsReturnScannerDefects(t *testing.T) {
	damaged := []byte("A=ENC[oops\nB=1\n")

	if _, defects := LooksLikeDotenvWithDefects(damaged); len(defects) != 1 || defects[0].Kind != Unterminated {
		t.Errorf("LooksLikeDotenvWithDefects: defects = %+v, want one Unterminated", defects)
	}
	if _, _, defects := UpsertWithDefects(damaged, "B", "ENC[v1:x]"); len(defects) != 1 || defects[0].Kind != Unterminated {
		t.Errorf("UpsertWithDefects: defects = %+v, want one Unterminated", defects)
	}
	// Reported even when the key is absent: the caller is deciding what to do
	// with the file, not just the key.
	_, found, defects, err := LookupValueWithDefects(context.Background(), damaged, "NOPE", nil)
	if err != nil || found {
		t.Fatalf("LookupValueWithDefects: found=%v err=%v", found, err)
	}
	if len(defects) != 1 || defects[0].Kind != Unterminated {
		t.Errorf("LookupValueWithDefects: defects = %+v, want one Unterminated", defects)
	}

	clean := []byte("A=1\n")
	if _, defects := LooksLikeDotenvWithDefects(clean); len(defects) != 0 {
		t.Errorf("clean content reported defects: %+v", defects)
	}
}
