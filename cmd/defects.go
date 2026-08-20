package cmd

import (
	"fmt"
	"strings"

	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/rubysolo/envisible/pkg/ui"
)

// defectContext is the per-command phrasing for defects whose meaning depends
// on what the user was doing. Marker defects read the same everywhere; a line
// that is not NAME=value does not — under `run` it was skipped, under
// `set --from-env` it is the caller's own payload and nothing is skipped. A
// message must never describe a command the user did not run.
type defectContext struct {
	// malformedEnvLine is the text after "file:line:col: " for a
	// MalformedEnvLine defect.
	malformedEnvLine string
}

var (
	// runContext is the default: the file was being read to populate an
	// environment, and the bad line was left out of it.
	runContext = defectContext{
		malformedEnvLine: "skipped: not a NAME=value assignment, so `run` cannot turn it into an environment variable",
	}
	// payloadContext is for `set --from-env`, where the input is the caller's
	// stdin and a bad line means the payload is wrong, not the file.
	payloadContext = defectContext{
		malformedEnvLine: "not a NAME=value assignment; every non-blank, non-comment line of a --from-env payload must be one",
	}
)

// describe renders one scanner defect as "file:line:col: message".
func (c defectContext) describe(file string, content []byte, d processor.Defect) string {
	line, col := processor.LineCol(content, d.Offset)
	switch d.Kind {
	case processor.Unterminated:
		return fmt.Sprintf("%s:%d:%d: unterminated ENC[ marker (add the closing ']', or escape a literal bracket as '\\[')", file, line, col)
	case processor.MalformedCiphertext:
		return fmt.Sprintf("%s:%d:%d: malformed ENC[vN:...] marker — no closing ']' before end of line (ciphertext is base64 and never spans lines)", file, line, col)
	case processor.MalformedEnvLine:
		return fmt.Sprintf("%s:%d:%d: %s", file, line, col, c.malformedEnvLine)
	default:
		return fmt.Sprintf("%s:%d:%d: %s", file, line, col, d.Kind)
	}
}

// describeDefect renders one scanner defect with the default (`run`) phrasing.
func describeDefect(file string, content []byte, d processor.Defect) string {
	return runContext.describe(file, content, d)
}

// defectError turns scanner defects into a hard failure. Used by the write and
// validate paths (encrypt, edit, check): a marker that does not mean what it
// looks like must be caught before it reaches a commit.
func defectError(file string, content []byte, defects []processor.Defect) error {
	if len(defects) == 0 {
		return nil
	}
	lines := make([]string, 0, len(defects))
	for _, d := range defects {
		lines = append(lines, describeDefect(file, content, d))
	}
	return fmt.Errorf("found %d malformed ENC[ marker(s):\n  %s", len(defects), strings.Join(lines, "\n  "))
}

// warnDefects reports scanner defects without failing. Used by the read paths
// (decrypt, run, kms rotate): a stray ENC[ in a config file must not take down
// a deploy.
func warnDefects(file string, content []byte, defects []processor.Defect) {
	for _, d := range defects {
		ui.Warn("%s", describeDefect(file, content, d))
	}
}

// warnAmbiguousMarker reports the shapes the scanner can parse but that a human
// may not have meant. Neither is a defect — the file parses, and both readings
// are legal grammar — so these warn and never fail a command.
func warnAmbiguousMarker(file string, content []byte, m processor.Marker) {
	if m.Encrypted {
		return
	}
	line, col := processor.LineCol(content, m.Start)
	if processor.UnmatchedTrailingBracket(content, m) {
		ui.Warn("%s:%d:%d: plaintext marker is followed by an unmatched ']' — if it is part of the secret, escape it as '\\]'", file, line, col)
	}
}

// warnAmbiguousMarkers runs warnAmbiguousMarker over every effective marker in
// content. The write paths use it just before producing an artifact.
func warnAmbiguousMarkers(file string, content []byte) {
	markers, _ := processor.Scan(content)
	for _, m := range markers {
		warnAmbiguousMarker(file, content, m)
	}
}
