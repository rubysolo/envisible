package cmd

import (
	"fmt"
	"strings"

	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/rubysolo/envisible/pkg/ui"
)

// describeDefect renders one scanner defect as "file:line:col: message".
func describeDefect(file string, content []byte, d processor.Defect) string {
	line, col := processor.LineCol(content, d.Offset)
	switch d.Kind {
	case processor.Unterminated:
		return fmt.Sprintf("%s:%d:%d: unterminated ENC[ marker (add the closing ']', or escape a literal bracket as '\\[')", file, line, col)
	case processor.MalformedCiphertext:
		return fmt.Sprintf("%s:%d:%d: malformed ENC[vN:...] marker — no closing ']' before end of line (ciphertext is base64 and never spans lines)", file, line, col)
	default:
		return fmt.Sprintf("%s:%d:%d: %s", file, line, col, d.Kind)
	}
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
	if processor.MultiLinePlaintext(m) {
		endLine, _ := processor.LineCol(content, m.End-1)
		ui.Warn("%s:%d:%d: plaintext marker spans lines %d-%d and will be encrypted as one multi-line value — if the closing ']' is missing, those lines are about to be absorbed into the secret", file, line, col, line, endLine)
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
