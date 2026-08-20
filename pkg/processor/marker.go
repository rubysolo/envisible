package processor

import (
	"bytes"
	"strings"
)

// markerPrefix opens every marker. It is deliberately the only place in the
// repo that knows the literal — ScanMarkers is the single marker parser, and
// wrapMarker is the single marker writer.
const markerPrefix = "ENC["

// markerSuffix closes every marker.
const markerSuffix = "]"

// wrapMarker builds the on-disk form of a marker from an already-prepared
// inner string (ciphertext, or an escaped plaintext).
func wrapMarker(inner string) string {
	return markerPrefix + inner + markerSuffix
}

// Marker is one ENC[...] occurrence located in a byte slice.
type Marker struct {
	Start, End int    // content[Start:End] is the whole marker, brackets included
	Raw        string // bytes between the brackets, exactly as they appear on disk
	Value      string // Raw with escapes resolved; meaningless when Encrypted
	Encrypted  bool   // Raw carries a vN: prefix
}

// DefectKind classifies a marker token that could not be parsed.
type DefectKind int

const (
	// Unterminated is an ENC[ whose plaintext body never closes: bracket depth
	// is still positive at end of input.
	Unterminated DefectKind = iota
	// MalformedCiphertext is an ENC[vN: whose body has no closing ']' before
	// the end of the line. Ciphertext is base64 and can never span lines, so a
	// newline (or EOF) first means the marker is truncated.
	MalformedCiphertext
)

func (k DefectKind) String() string {
	switch k {
	case Unterminated:
		return "unterminated marker"
	case MalformedCiphertext:
		return "malformed ciphertext marker"
	default:
		return "unknown defect"
	}
}

// Defect is a malformed marker token that ScanMarkers could not turn into a
// Marker. Offset points at the 'E' of the opening ENC[.
type Defect struct {
	Offset int
	Kind   DefectKind
}

// span is a half-open byte range [start, end) of content.
type span struct{ start, end int }

// ScanMarkers finds every ENC[...] marker in content, ignoring comments
// entirely (see Scan for the comment-aware entry point).
//
// It never returns an error: malformed tokens come back as defects so the
// caller can pick a severity. That also breaks the ordering cycle between
// marker detection and comment detection — markers are located first, over the
// raw bytes, and comments are resolved against the marker spans afterwards.
//
// Two scanning modes:
//
// Ciphertext mode is entered when the bytes after ENC[ match ^v\d+:. Both v1
// and v2 inners are a version prefix plus standard base64, an alphabet with no
// '[', ']', '\' or newline, so scanning to the first ']' without crossing a
// newline is exactly correct — and byte-for-byte identical to what the old
// `ENC\[(.*?)\]` regex produced for every marker envisible has ever written.
//
// Plaintext mode tracks bracket depth so a pasted JSON blob needs no escaping,
// honors '\[', '\]' and '\\' escapes, and allows newlines so multi-line values
// (PEM keys, service-account JSON) are expressible at all.
func ScanMarkers(content []byte) ([]Marker, []Defect) {
	var (
		markers []Marker
		defects []Defect
	)
	for i := 0; i+len(markerPrefix) <= len(content); {
		rel := bytes.Index(content[i:], []byte(markerPrefix))
		if rel < 0 {
			break
		}
		start := i + rel
		inner := start + len(markerPrefix)

		if isCiphertextStart(content[inner:]) {
			closeIdx, ok := scanCiphertextBody(content, inner)
			if !ok {
				defects = append(defects, Defect{Offset: start, Kind: MalformedCiphertext})
				i = inner
				continue
			}
			raw := string(content[inner:closeIdx])
			markers = append(markers, Marker{
				Start:     start,
				End:       closeIdx + 1,
				Raw:       raw,
				Value:     raw,
				Encrypted: true,
			})
			i = closeIdx + 1
			continue
		}

		closeIdx, ok := scanPlaintextBody(content, inner)
		if !ok {
			defects = append(defects, Defect{Offset: start, Kind: Unterminated})
			i = inner
			continue
		}
		raw := string(content[inner:closeIdx])
		markers = append(markers, Marker{
			Start: start,
			End:   closeIdx + 1,
			Raw:   raw,
			Value: unescapeMarkerValue(raw),
		})
		i = closeIdx + 1
	}
	return markers, defects
}

// isCiphertextStart reports whether b begins with a version prefix (v1:, v2:,
// v37:, ...). It is the byte-slice twin of IsEncryptedInner and must agree with
// it, since Marker.Encrypted is what the rewriters branch on.
func isCiphertextStart(b []byte) bool {
	if len(b) < 3 || b[0] != 'v' {
		return false
	}
	i := 1
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	return i > 1 && i < len(b) && b[i] == ':'
}

// scanCiphertextBody returns the index of the closing ']' for a ciphertext
// marker whose body starts at inner. A newline or EOF first means truncation.
func scanCiphertextBody(content []byte, inner int) (int, bool) {
	for j := inner; j < len(content); j++ {
		switch content[j] {
		case ']':
			return j, true
		case '\n':
			return 0, false
		}
	}
	return 0, false
}

// scanPlaintextBody returns the index of the closing ']' for a plaintext marker
// whose body starts at inner, tracking bracket depth and honoring escapes.
// Newlines are ordinary content.
func scanPlaintextBody(content []byte, inner int) (int, bool) {
	depth := 1
	for j := inner; j < len(content); j++ {
		switch content[j] {
		case '\\':
			if j+1 < len(content) {
				switch content[j+1] {
				case '[', ']', '\\':
					j++
				}
			}
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return j, true
			}
		}
	}
	return 0, false
}

// escapeMarkerValue renders a plaintext value so it can be written inside a
// marker unambiguously: '\' -> '\\', '[' -> '\[', ']' -> '\]'.
//
// Escaping '[' as well as ']' is what makes machine-written markers safe. An
// unescaped '[' would push bracket depth to 2 and swallow the rest of the file;
// with both escaped, anything envisible emits has depth that never exceeds 1.
// Bracket balancing in the scanner exists purely so a human pasting a JSON blob
// does not have to escape anything.
func escapeMarkerValue(s string) string {
	if !strings.ContainsAny(s, `\[]`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '[', ']':
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unescapeMarkerValue is the exact inverse of escapeMarkerValue. A backslash
// followed by anything other than '\', '[' or ']' is a literal backslash.
func unescapeMarkerValue(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\', '[', ']':
				b.WriteByte(s[i+1])
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// CommentRegions computes the comment spans of content, given the complete,
// unfiltered marker list from ScanMarkers.
//
// A '#' opens a comment when it sits at the start of a line or after a space or
// tab (the YAML/TOML/.env convention) AND is not inside a marker span — so a
// value that legitimately contains '#' round-trips unmodified. The comment runs
// to the end of that line.
func CommentRegions(content []byte, markers []Marker) []span {
	var regions []span
	inMarker := func(pos int) bool {
		for _, m := range markers {
			if pos < m.Start {
				return false
			}
			if pos < m.End {
				return true
			}
		}
		return false
	}
	lineStart := 0
	for i := 0; i <= len(content); i++ {
		if i < len(content) && content[i] != '\n' {
			continue
		}
		line := content[lineStart:i]
		for j := 0; j < len(line); j++ {
			if line[j] != '#' {
				continue
			}
			if j != 0 && line[j-1] != ' ' && line[j-1] != '\t' {
				continue
			}
			if inMarker(lineStart + j) {
				continue
			}
			regions = append(regions, span{start: lineStart + j, end: i})
			break
		}
		lineStart = i + 1
	}
	return regions
}

// Scan returns the effective markers (comments excluded) and the defects that
// matter (comments excluded). This is the entry point every command uses.
//
// The fixed ordering — markers first over the whole content, then comments
// against those spans, then filter — is what makes multi-line markers and
// comment skipping coexist. Dropping defects inside comments matters too: a
// "# TODO: wrap this in ENC[" is prose, not a broken marker.
func Scan(content []byte) ([]Marker, []Defect) {
	all, defects := ScanMarkers(content)
	regions := CommentRegions(content, all)
	if len(regions) == 0 {
		return all, defects
	}

	inComment := func(pos int) bool {
		for _, r := range regions {
			if pos < r.start {
				return false
			}
			if pos < r.end {
				return true
			}
		}
		return false
	}

	markers := make([]Marker, 0, len(all))
	for _, m := range all {
		if !inComment(m.Start) {
			markers = append(markers, m)
		}
	}
	kept := make([]Defect, 0, len(defects))
	for _, d := range defects {
		if !inComment(d.Offset) {
			kept = append(kept, d)
		}
	}
	return markers, kept
}

// LineCol converts a byte offset into 1-based line and column numbers, for
// error messages that a human (or an editor) can jump to.
func LineCol(content []byte, offset int) (line, col int) {
	if offset > len(content) {
		offset = len(content)
	}
	if offset < 0 {
		offset = 0
	}
	line = 1 + bytes.Count(content[:offset], []byte("\n"))
	lineStart := bytes.LastIndexByte(content[:offset], '\n') + 1
	return line, offset - lineStart + 1
}

// UnmatchedTrailingBracket reports whether a plaintext marker is followed, on
// the same line, by a ']' that nothing opened.
//
// This is the heuristic for the one irreducibly ambiguous case in the grammar:
//
//	password: ENC[ab]cd]
//
// Bracket balancing cannot help — depth legitimately reaches zero at the first
// ']' — so the scanner reads "ab", and the user may have meant "ab]cd". The
// trigger requires a plaintext marker (a transient authoring state) and a
// trailing unmatched bracket on the same line, so false positives are rare.
func UnmatchedTrailingBracket(content []byte, m Marker) bool {
	if m.Encrypted {
		return false
	}
	depth := 0
	for j := m.End; j < len(content); j++ {
		switch content[j] {
		case '\n':
			return false
		case '[':
			depth++
		case ']':
			if depth == 0 {
				return true
			}
			depth--
		}
	}
	return false
}
