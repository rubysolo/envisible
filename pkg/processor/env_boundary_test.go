package processor

import (
	"context"
	"testing"
)

// These tests pin the boundaries of the .env parser that the rest of the suite
// walks past: the first and last byte of a file, a line that is exactly as long
// as a keyword, a value that is one byte long. Each one names the comparison it
// holds in place.

// extractWithDefects is envFixture.extract for the tests that also care about
// what was reported.
func (f envFixture) extractWithDefects(t *testing.T, content string) (map[string]string, []Defect) {
	t.Helper()
	env, defects, err := ExtractEnvWithDefects(context.Background(), []byte(content), NaclDecryptor{PrivateKey: f.priv})
	if err != nil {
		t.Fatalf("ExtractEnvWithDefects(%q): %v", content, err)
	}
	return env, defects
}

// wantEnv asserts the whole map, so a test fails on an extra key as loudly as
// on a wrong value.
func wantEnv(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("got %d variables %q, want %d %q", len(got), got, len(want), want)
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("%s is missing; got %q", k, got)
			continue
		}
		if g != w {
			t.Errorf("%s = %q, want %q", k, g, w)
		}
	}
}

func wantDefects(t *testing.T, got []Defect, want ...Defect) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("defects = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("defects[%d] = %+v, want %+v (all: %+v)", i, got[i], want[i], got)
		}
	}
}

// TestExtractEnvLeadingBlankLineDoesNotSwallowTheFile: a newline at the very
// start of a line is an empty line, not "no newline found". Reading it as the
// latter turns the rest of the file into one logical line, so the first
// assignment's value absorbs every assignment after it.
func TestExtractEnvLeadingBlankLineDoesNotSwallowTheFile(t *testing.T) {
	f := newEnvFixture(t)

	t.Run("literals", func(t *testing.T) {
		env, defects := f.extractWithDefects(t, "\nA=1\nB=2\n")
		wantEnv(t, env, map[string]string{"A": "1", "B": "2"})
		wantDefects(t, defects)
	})

	t.Run("blank line between two secrets", func(t *testing.T) {
		env, defects := f.extractWithDefects(t, "A="+f.marker(t, "first")+"\n\nB="+f.marker(t, "second")+"\n")
		wantEnv(t, env, map[string]string{"A": "first", "B": "second"})
		wantDefects(t, defects)
	})
}

// TestExtractEnvMultiLineMarkerIsOneLogicalLine: a plaintext marker carrying a
// backslash-newline continuation spans two physical lines and is still one
// value. Splitting it would read its second half as an assignment of its own.
func TestExtractEnvMultiLineMarkerIsOneLogicalLine(t *testing.T) {
	f := newEnvFixture(t)

	t.Run("in a value", func(t *testing.T) {
		const marker = "ENC[line1\\\nINJECTED=line2]"
		env, defects := f.extractWithDefects(t, "KEY="+marker+"\nAFTER=tail\n")

		// Not encrypted yet, so it reads as the literal text it is.
		wantEnv(t, env, map[string]string{"KEY": marker, "AFTER": "tail"})
		wantDefects(t, defects)
	})

	t.Run("at the very start of a line", func(t *testing.T) {
		// The marker begins exactly where the line does. The line is not an
		// assignment, and it is one defect — not a defect plus a variable
		// made out of the marker's second half.
		env, defects := f.extractWithDefects(t, "ENC[line1\\\nINJECTED=line2]\nAFTER=tail\n")

		wantEnv(t, env, map[string]string{"AFTER": "tail"})
		wantDefects(t, defects, Defect{Offset: 0, Kind: MalformedEnvLine})
	})
}

// TestExtractEnvNoTrailingNewlineBoundaries: the last line of a file with no
// final newline ends at len(content), so every "one past the end" slip in the
// line scanners lands outside the buffer.
func TestExtractEnvNoTrailingNewlineBoundaries(t *testing.T) {
	f := newEnvFixture(t)

	t.Run("bare word with no equals", func(t *testing.T) {
		env, defects := f.extractWithDefects(t, "JUST_A_WORD")
		wantEnv(t, env, map[string]string{})
		wantDefects(t, defects, Defect{Offset: 0, Kind: MalformedEnvLine})
	})

	t.Run("empty value", func(t *testing.T) {
		env, defects := f.extractWithDefects(t, "FOO=")
		wantEnv(t, env, map[string]string{"FOO": ""})
		wantDefects(t, defects)
	})

	t.Run("literal ending in a lone carriage return", func(t *testing.T) {
		env, defects := f.extractWithDefects(t, "FOO=bar\r")
		wantEnv(t, env, map[string]string{"FOO": "bar"})
		wantDefects(t, defects)
	})

	t.Run("secret ending in a lone carriage return", func(t *testing.T) {
		env, defects := f.extractWithDefects(t, "FOO="+f.marker(t, " padded ")+"\r")
		wantEnv(t, env, map[string]string{"FOO": " padded "})
		wantDefects(t, defects)
	})

	t.Run("the word export and nothing else", func(t *testing.T) {
		env, defects := f.extractWithDefects(t, "export")
		wantEnv(t, env, map[string]string{})
		wantDefects(t, defects, Defect{Offset: 0, Kind: MalformedEnvLine})
	})
}

// TestExtractEnvBareExportIsReportedWhereItStarts: a line that is exactly the
// keyword has no assignment after it. It is a malformed line, reported at its
// own first byte, and it does not disturb the line below.
func TestExtractEnvBareExportIsReportedWhereItStarts(t *testing.T) {
	f := newEnvFixture(t)

	t.Run("followed by a newline", func(t *testing.T) {
		env, defects := f.extractWithDefects(t, "export\nFOO="+f.marker(t, "s3cret")+"\n")
		wantEnv(t, env, map[string]string{"FOO": "s3cret"})
		wantDefects(t, defects, Defect{Offset: 0, Kind: MalformedEnvLine})
	})

	t.Run("followed by trailing whitespace", func(t *testing.T) {
		env, defects := f.extractWithDefects(t, "OK=1\n  export  \nFOO=bar\n")
		wantEnv(t, env, map[string]string{"OK": "1", "FOO": "bar"})
		wantDefects(t, defects, Defect{Offset: 7, Kind: MalformedEnvLine})
	})

	t.Run("a six-byte assignment is not mistaken for the keyword", func(t *testing.T) {
		env, defects := f.extractWithDefects(t, "ABCD=x\n")
		wantEnv(t, env, map[string]string{"ABCD": "x"})
		wantDefects(t, defects)
	})
}

// TestExtractEnvShortValuesAreNotUnquoted: a pair of quotes needs two bytes. A
// value shorter than that is content, whatever the byte is.
func TestExtractEnvShortValuesAreNotUnquoted(t *testing.T) {
	f := newEnvFixture(t)

	cases := []struct {
		name, content, want string
	}{
		{"lone double quote", "FOO=\"\n", `"`},
		{"lone single quote", "FOO='\n", `'`},
		{"lone double quote at end of file", `FOO="`, `"`},
		{"one character", "FOO=a\n", "a"},
		{"empty pair", "FOO=\"\"\n", ""},
		{"one quoted character", "FOO=\"a\"\n", "a"},
		{"empty before a comment", "FOO= # note\n", ""},
		{"lone quote before a comment", "FOO=\" # note\n", `"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, defects := f.extractWithDefects(t, tc.content)
			wantEnv(t, env, map[string]string{"FOO": tc.want})
			wantDefects(t, defects)
		})
	}
}

// TestExtractEnvDefectsAtTheSameOffsetKeepScannerOrder: `ENC[oops` alone on a
// line is two defects at one offset — the marker never closes, and the line is
// not an assignment. The sort is stable, so the scanner's defect stays ahead of
// the line's.
func TestExtractEnvDefectsAtTheSameOffsetKeepScannerOrder(t *testing.T) {
	f := newEnvFixture(t)

	env, defects := f.extractWithDefects(t, "ENC[oops\nGOOD="+f.marker(t, "ok")+"\n")

	wantEnv(t, env, map[string]string{"GOOD": "ok"})
	wantDefects(t, defects,
		Defect{Offset: 0, Kind: Unterminated},
		Defect{Offset: 0, Kind: MalformedEnvLine},
	)
}

// TestExtractEnvEqualsInsideAMarkerOnTheNameSide: an '=' inside a marker is not
// the separator. With a marker on the name side there is no valid name either
// way, so the line is one defect at its first byte and defines nothing.
func TestExtractEnvEqualsInsideAMarkerOnTheNameSide(t *testing.T) {
	f := newEnvFixture(t)

	cases := []struct {
		name, line string
		offset     int
	}{
		{"marker is the whole line", "ENC[a=b]", 0},
		{"marker then a separator", "ENC[a=b]=c", 0},
		{"marker after a word", "FOO ENC[a=b]=c", 0},
		{"indented", "  ENC[a=b]=c", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, defects := f.extractWithDefects(t, tc.line+"\nGOOD=ok\n")
			wantEnv(t, env, map[string]string{"GOOD": "ok"})
			wantDefects(t, defects, Defect{Offset: tc.offset, Kind: MalformedEnvLine})
		})
	}
}

// TestExtractEnvEqualsInsideAValueMarker: the separator is the first '=' on the
// line, and one inside a marker on the value side stays part of the value.
func TestExtractEnvEqualsInsideAValueMarker(t *testing.T) {
	f := newEnvFixture(t)

	env, defects := f.extractWithDefects(t, "FOO=ENC[a=b]\nBAR=x="+f.marker(t, "y=z")+"\n")

	wantEnv(t, env, map[string]string{"FOO": "ENC[a=b]", "BAR": "x=y=z"})
	wantDefects(t, defects)
}
