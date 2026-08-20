package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
)

// Action is what an Upsert did to a file.
type Action int

const (
	// Added: the key was not present, so the assignment was appended.
	Added Action = iota
	// Updated: the key was present and only its value span was rewritten.
	Updated
	// Unchanged: nothing was written. Upsert never returns this — it belongs to
	// callers that decided, before calling, that the value already matches
	// (`set --if-changed`). It lives here so every caller spells the three
	// outcomes the same way.
	Unchanged
)

func (a Action) String() string {
	switch a {
	case Added:
		return "added"
	case Updated:
		return "updated"
	case Unchanged:
		return "unchanged"
	default:
		return "unknown action"
	}
}

// ValidEnvName reports whether s is a usable environment variable name. It is
// the same test ExtractEnv applies when deciding whether a line is an
// assignment, exported so write paths can reject a bad key *before* touching a
// file rather than writing a line no consumer can read back.
func ValidEnvName(s string) bool {
	return envNamePattern.MatchString(s)
}

// WrapMarker renders an already-prepared inner string (ciphertext, or an
// escaped plaintext) as the on-disk ENC[...] form. It is the exported face of
// the single marker writer in marker.go: `set` builds a marker without knowing
// the literal, and there is still exactly one place that does.
func WrapMarker(inner string) string {
	return wrapMarker(inner)
}

// dotenvLine is one logical line of a .env file, located but not interpreted.
// The offsets index the original content, so a caller can rewrite a span
// without reflowing anything around it.
type dotenvLine struct {
	// start, end bound the line's significant bytes: leading and trailing
	// whitespace, any trailing comment, and a CRLF '\r' are already excluded.
	start, end int
	// key is the assignment's name, with any `export ` prefix stripped. Empty
	// when ok is false.
	key string
	// valueStart, valueEnd bound the right-hand side exactly as written,
	// including any quotes and any whitespace directly after the '='.
	valueStart, valueEnd int
	// ok reports whether this line is a NAME=value assignment. When false the
	// line is a defect: something non-blank that is not an assignment.
	ok bool
}

// text returns the line's significant bytes.
func (l dotenvLine) text(content []byte) string {
	return string(content[l.start:l.end])
}

// newEnvParser builds a parser over content, returning the scanner defects
// found on the way (malformed marker tokens). dec may be nil for callers that
// only locate lines and never resolve a value.
func newEnvParser(content []byte, dec Decryptor) (*envParser, []Defect) {
	markers, defects, regions := scanWithRegions(content)
	return &envParser{content: content, markers: markers, regions: regions, dec: dec}, defects
}

// walk visits every non-blank logical line of the file in offset order,
// stopping early if visit returns false.
//
// This is the one place in the repo that answers "where does an assignment
// begin and end" — ExtractEnv reads through it and Upsert writes through it, so
// what `set` writes is by construction what `run` reads. Comment handling,
// multi-line marker spans, `export ` prefixes and CRLF all resolve here, once.
func (p *envParser) walk(visit func(dotenvLine) bool) {
	for pos := 0; pos <= len(p.content); {
		lineStart := pos
		lineEnd, next := p.logicalLine(lineStart)
		pos = next

		end := p.commentStart(lineStart, lineEnd)
		if end == lineEnd {
			// A CRLF file leaves '\r' as the last byte of every line. It is
			// line structure, not value: strip it here, once, rather than
			// letting it ride along on a value that is otherwise untrimmed.
			end = trimTrailingCR(p.content, lineStart, end)
		}

		s, e := trimSpaceRange(p.content, lineStart, end)
		if s == e {
			continue
		}
		s, e = stripExport(p.content, s, e)

		eq := p.indexAssign(s, e)
		if eq < 0 {
			if !visit(dotenvLine{start: s, end: e}) {
				return
			}
			continue
		}
		ks, ke := trimSpaceRange(p.content, s, eq)
		key := string(p.content[ks:ke])
		if !ValidEnvName(key) {
			if !visit(dotenvLine{start: s, end: e}) {
				return
			}
			continue
		}
		if !visit(dotenvLine{start: s, end: e, key: key, valueStart: eq + 1, valueEnd: e, ok: true}) {
			return
		}
	}
}

// Upsert splices `key=rawValue` into content and reports what it did.
//
// rawValue is written verbatim on the value side — for `set` that is an
// ENC[...] marker holding ciphertext, which is why no escaping is involved
// anywhere in this path: the plaintext never enters the marker grammar.
//
// Layout is preserved to the byte. On an existing key only the value span is
// rewritten, so the key, an `export ` prefix, indentation, the spacing around
// the '=' and any trailing `# comment` all survive untouched. Everything else
// in the file — comments, ordering, unrelated lines — is copied through.
//
// When the key appears more than once, the *last* assignment wins, because that
// is the one ExtractEnv resolves to and therefore the one `run` would hand to a
// child process. Rewriting any other occurrence would leave the file looking
// updated while the effective value stayed stale.
func Upsert(content []byte, key, rawValue string) ([]byte, Action) {
	p, _ := newEnvParser(content, nil)

	found := false
	var vs, ve int
	p.walk(func(l dotenvLine) bool {
		if l.ok && l.key == key {
			found = true
			// Narrow to the value's own bytes so the whitespace a human put
			// after the '=' is not swallowed by the rewrite.
			vs, ve = trimSpaceRange(content, l.valueStart, l.valueEnd)
		}
		return true
	})

	if !found {
		return appendAssignment(content, key, rawValue), Added
	}

	var out bytes.Buffer
	out.Grow(len(content) + len(rawValue))
	out.Write(content[:vs])
	out.WriteString(rawValue)
	out.Write(content[ve:])
	return out.Bytes(), Updated
}

// appendAssignment adds `key=rawValue` at the end of content, leaving it with
// exactly one trailing newline. A file that was missing its final newline gets
// one rather than having the new assignment glued onto the last line.
func appendAssignment(content []byte, key, rawValue string) []byte {
	var out bytes.Buffer
	out.Grow(len(content) + len(key) + len(rawValue) + 2)
	out.Write(content)
	if len(content) > 0 && content[len(content)-1] != '\n' {
		out.WriteByte('\n')
	}
	out.WriteString(key)
	out.WriteByte('=')
	out.WriteString(rawValue)
	out.WriteByte('\n')
	return out.Bytes()
}

// LookupValue resolves a single key out of content, decrypting its value
// exactly as ExtractEnv would — same grammar, same quoting rules, same
// no-interpretation-of-a-secret guarantee — but touching only the one
// assignment asked for.
//
// That narrowness is the point for `set --if-changed`: comparing one key must
// not require decrypt permission for, or even the ability to parse, every other
// marker in the file.
func LookupValue(ctx context.Context, content []byte, key string, dec Decryptor) (string, bool, error) {
	p, _ := newEnvParser(content, dec)

	var (
		line  dotenvLine
		found bool
	)
	p.walk(func(l dotenvLine) bool {
		if l.ok && l.key == key {
			line, found = l, true
		}
		return true
	})
	if !found {
		return "", false, nil
	}

	value, err := p.value(ctx, line.valueStart, line.valueEnd)
	if err != nil {
		return "", true, err
	}
	return value, true, nil
}

// yamlDocumentStart is the one non-dotenv shape common enough, and destructive
// enough to append to, that it gets named explicitly.
const yamlDocumentStart = "---"

// LooksLikeDotenv reports whether content is shaped like a .env file, i.e.
// whether appending `KEY=value` to it would produce something a .env reader can
// still read.
//
// A write path that guesses wrong here silently appends a dotenv line to the
// bottom of a YAML document, which no reader of either format will ever
// complain about and no human will notice. Empty content passes: a file that
// does not exist yet is about to be a .env file.
func LooksLikeDotenv(content []byte) bool {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return true
	}
	if (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(trimmed) {
		return false
	}

	p, _ := newEnvParser(content, nil)
	lines, assignments, first := 0, 0, ""
	p.walk(func(l dotenvLine) bool {
		if lines == 0 {
			first = l.text(content)
		}
		lines++
		if l.ok {
			assignments++
		}
		return true
	})

	if strings.TrimSpace(first) == yamlDocumentStart {
		return false
	}
	// Nothing but blank lines and comments is still a .env file. Otherwise at
	// least one line has to actually be an assignment; a file of `key: value`
	// pairs produces none.
	return lines == 0 || assignments > 0
}
