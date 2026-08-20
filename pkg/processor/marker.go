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

// markerPrefixBytes is markerPrefix as a slice, for scanning.
var markerPrefixBytes = []byte(markerPrefix)

// opensMarkerAt reports whether the literal "ENC[" begins at content[j].
func opensMarkerAt(content []byte, j int) bool {
	return bytes.HasPrefix(content[j:], markerPrefixBytes)
}

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
	// MalformedEnvLine is not a marker problem at all: it is a non-blank,
	// non-comment line that ExtractEnv could not read as a NAME=value
	// assignment — no '=', or a left-hand side that is not a valid environment
	// variable name. Only `run` produces it, and only so the line is skipped
	// out loud instead of silently.
	MalformedEnvLine
)

func (k DefectKind) String() string {
	switch k {
	case Unterminated:
		return "unterminated marker"
	case MalformedCiphertext:
		return "malformed ciphertext marker"
	case MalformedEnvLine:
		return "malformed .env line"
	default:
		return "unknown defect"
	}
}

// Defect is something the caller should be told about but that is not worth
// failing a read path over: a malformed marker token ScanMarkers could not turn
// into a Marker (Offset points at the 'E' of the opening ENC[), or a .env line
// ExtractEnv had to skip (Offset points at the first non-blank byte of the
// line).
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
//
// Both modes stop at an unescaped, nested "ENC[": no marker span ever contains
// another marker's opener. That invariant is what makes the comment filtering
// in Scan safe — a span that gets discarded can never have been hiding a real
// marker — and it bounds the damage of a forgotten ']'.
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
			closeIdx, status := scanCiphertextBody(content, inner)
			switch status {
			case bodyClosed:
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
			case bodyTruncated:
				defects = append(defects, Defect{Offset: start, Kind: MalformedCiphertext})
				i = inner
				continue
			}
			// bodyNotCiphertext: the body holds a byte no base64 payload can
			// contain, so this is not a ciphertext marker after all. Fall
			// through and read it as plaintext, where escapes are honored.
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

// bodyStatus is the outcome of scanning a ciphertext marker body.
type bodyStatus int

const (
	// bodyClosed: a ']' terminated the body on the same line.
	bodyClosed bodyStatus = iota
	// bodyTruncated: the line (or the input) ended, or another marker opened,
	// before the ']' arrived. The marker is malformed.
	bodyTruncated
	// bodyNotCiphertext: the body contains a byte that standard base64 cannot
	// produce, so despite the vN: prefix this is not ciphertext. The caller
	// re-reads it in plaintext mode.
	bodyNotCiphertext
)

// scanCiphertextBody returns the index of the closing ']' for a ciphertext
// marker whose body starts at inner. A newline or EOF first means truncation.
//
// A backslash means it is not ciphertext at all: v1 and v2 inners are a version
// prefix plus standard base64, an alphabet with no '\'. The only way one gets
// there is a plaintext value that happens to start "vN:" — which escapeMarkerValue
// now neutralizes on the way out, but a hand-written file can still contain.
// Reading it as plaintext honors '\]' instead of stopping mid-value.
func scanCiphertextBody(content []byte, inner int) (int, bodyStatus) {
	for j := inner; j < len(content); j++ {
		if opensMarkerAt(content, j) {
			// No marker may span another marker's opener. See scanPlaintextBody.
			return 0, bodyTruncated
		}
		switch content[j] {
		case ']':
			return j, bodyClosed
		case '\n':
			return 0, bodyTruncated
		case '\\':
			return 0, bodyNotCiphertext
		}
	}
	return 0, bodyTruncated
}

// scanPlaintextBody returns the index of the closing ']' for a plaintext marker
// whose body starts at inner, tracking bracket depth and honoring escapes.
// Newlines are ordinary content.
func scanPlaintextBody(content []byte, inner int) (int, bool) {
	depth := 1
	for j := inner; j < len(content); j++ {
		if opensMarkerAt(content, j) {
			// An unescaped ENC[ inside a body means this body never closed:
			// the author forgot a ']', or left a stray bracket in prose. Bail
			// out rather than absorb the next marker.
			//
			// This is the invariant that keeps the grammar safe across lines:
			// no marker span ever contains another marker's opener. Without it
			// a lone 'ENC[' in a comment can swallow the real ENC[v1:...] that
			// follows, and because the swallowing marker is itself discarded as
			// commented-out, the ciphertext becomes invisible to every command
			// with no defect reported. Anything envisible writes escapes '[' as
			// '\[', so a machine-written value never trips this.
			return 0, false
		}
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
// marker unambiguously: '\' -> '\\', '[' -> '\[', ']' -> '\]', plus a leading
// '\' in front of a value that itself begins with a version prefix.
//
// Escaping '[' as well as ']' is what makes machine-written markers safe. An
// unescaped '[' would push bracket depth to 2 and swallow the rest of the file;
// with both escaped, anything envisible emits has depth that never exceeds 1.
// Bracket balancing in the scanner exists purely so a human pasting a JSON blob
// does not have to escape anything.
//
// The leading-'v' case is the same class of bug one level up: a secret whose
// plaintext looks like "v1:..." would be re-read in ciphertext mode, so the
// `edit` round trip would write it back to disk in the clear (and report
// success). Prefixing the escape moves it out of ciphertext mode; the scanner
// puts the 'v' back.
func escapeMarkerValue(s string) string {
	looksVersioned := IsEncryptedInner(s)
	if !looksVersioned && !strings.ContainsAny(s, `\[]`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	if looksVersioned {
		b.WriteByte('\\')
	}
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
// followed by anything other than '\', '[' or ']' is a literal backslash — with
// one position-scoped exception: a leading "\v" in front of a version prefix,
// which is how escapeMarkerValue keeps a plaintext "v1:..." out of ciphertext
// mode. Restricting that escape to offset 0 keeps every other "\v" in the value
// (a Windows path, a JSON blob) byte-for-byte intact.
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
			case 'v':
				if i == 0 && IsEncryptedInner(s[1:]) {
					b.WriteByte('v')
					i++
					continue
				}
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
//
// Dropping a marker here is only safe because of ScanMarkers' no-nested-opener
// invariant. Without it, that same "# TODO: wrap this in ENC[" opens a body
// that runs across the newline, absorbs the real marker below it, and is then
// discarded whole — leaving a file with zero markers, zero defects, and a
// secret nobody is going to encrypt.
func Scan(content []byte) ([]Marker, []Defect) {
	markers, defects, _ := scanWithRegions(content)
	return markers, defects
}

// scanWithRegions is Scan plus the comment spans it computed on the way. The
// .env parser in env.go needs them to find where a comment starts on a line,
// and there is exactly one implementation of that question in the repo
// (CommentRegions) — this is how a second caller gets at it without asking it
// again with a different answer.
func scanWithRegions(content []byte) ([]Marker, []Defect, []span) {
	all, defects := ScanMarkers(content)
	regions := CommentRegions(content, all)
	if len(regions) == 0 {
		return all, defects, regions
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
	return markers, kept, regions
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

// MultiLinePlaintext reports whether a plaintext marker's body crosses a
// newline.
//
// Multi-line plaintext is a supported value shape — a PEM key or a pasted
// service-account JSON has to be expressible — so this is not a defect. It is
// the second heuristic in the grammar, and it covers the shape the trailing-']'
// heuristic cannot see:
//
//	DB_PASSWORD=ENC[hunter2
//	ALLOWED_HOST=example.com]
//
// A single forgotten ']' turns the next config line into part of the secret,
// and bracket balancing has no way to tell that from a deliberate two-line
// value. Encrypting it deletes the absorbed line from the file, so the write
// paths warn with the line range before doing it.
func MultiLinePlaintext(m Marker) bool {
	return !m.Encrypted && strings.Contains(m.Raw, "\n")
}
