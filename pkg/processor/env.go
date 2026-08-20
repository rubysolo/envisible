package processor

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"sort"
)

// envNamePattern is the shape of an environment variable name: the POSIX
// portable set, which is also what every .env loader in the wild accepts.
var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// exportPrefix is the shell-ism a .env file is allowed to carry so the same
// file can be `source`d. It is structure, not part of the name.
const exportPrefix = "export"

// ExtractEnv parses content as a .env-style key=value mapping, decrypting the
// markers it finds on the value side.
//
// Structure is resolved against the *encrypted* file and values are decrypted
// afterwards, never the other way round. That ordering is the whole point: a
// decrypted secret is opaque bytes that are handed to exactly one variable, so
// no plaintext — however many newlines or '=' signs it contains — can add,
// remove, or alter another entry in the returned map.
func ExtractEnv(ctx context.Context, content []byte, dec Decryptor) (map[string]string, error) {
	env, _, err := ExtractEnvWithDefects(ctx, content, dec)
	return env, err
}

// ExtractEnvWithDefects is ExtractEnv plus the defects worth reporting, so
// `run` can warn about them: the scanner's malformed markers, and every
// non-blank line that is not a NAME=value assignment. The latter used to be
// dropped in silence.
func ExtractEnvWithDefects(ctx context.Context, content []byte, dec Decryptor) (map[string]string, []Defect, error) {
	p, defects := newEnvParser(content, dec)

	env, lineDefects, err := p.parse(ctx)
	defects = append(defects, lineDefects...)
	sort.SliceStable(defects, func(i, j int) bool { return defects[i].Offset < defects[j].Offset })
	if err != nil {
		return nil, defects, err
	}
	return env, defects, nil
}

// envParser walks the original bytes of a .env file. It holds the scanner's
// output — the effective markers and the comment regions — so that "where does
// a comment start on this line" is answered by CommentRegions and nothing else.
type envParser struct {
	content []byte
	markers []Marker
	regions []span
	dec     Decryptor

	// regionIdx is a cursor into regions. Lines are visited in increasing
	// offset order, so the comment lookup never has to rescan from the top.
	regionIdx int
}

// parse walks the file's assignments and resolves each one's value. The walk
// itself lives in dotenv.go, so `run` and `set` agree byte-for-byte on where an
// assignment starts and ends.
func (p *envParser) parse(ctx context.Context) (map[string]string, []Defect, error) {
	env := make(map[string]string)
	var (
		defects []Defect
		lastErr error
	)

	p.walk(func(l dotenvLine) bool {
		if !l.ok {
			defects = append(defects, Defect{Offset: l.start, Kind: MalformedEnvLine})
			return true
		}
		value, err := p.value(ctx, l.valueStart, l.valueEnd)
		if err != nil {
			lastErr = err
			return true
		}
		env[l.key] = value
		return true
	})

	if lastErr != nil {
		return nil, defects, lastErr
	}
	return env, defects, nil
}

// value resolves content[start:end) — the right-hand side of one assignment,
// as written in the file — into the bytes the child process receives.
//
// Two paths, and the difference between them is the fix:
//
//   - Exactly one marker, optionally wrapped in one matching pair of quotes:
//     the decrypted bytes are the value, verbatim. No trimming, no unquoting,
//     no re-parsing. Quoting is a property of how a value is written in a file;
//     a secret is opaque bytes and gets no interpretation at all.
//   - Anything else — a literal, or text with a marker embedded in it — is file
//     text, so dotenv quoting applies to it, and any markers inside are
//     decrypted and spliced in place. This is what keeps
//     `DATABASE_URL=postgres://u:ENC[...]@host/db` working.
func (p *envParser) value(ctx context.Context, start, end int) (string, error) {
	s, e := trimSpaceRange(p.content, start, end)

	if m, ok := p.soleMarker(s, e); ok {
		plaintext, err := p.dec.DecryptMarker(ctx, m.Raw)
		switch {
		case err == nil:
			return string(plaintext), nil
		case !errors.Is(err, ErrSkip):
			return "", err
		}
		// ErrSkip: a version this decryptor does not handle. The marker text
		// stays exactly as written, which is what every other read path does.
	}

	s, e = stripOneQuotePair(p.content, s, e)
	return p.splice(ctx, s, e)
}

// splice returns content[s:e) with every encrypted marker inside it replaced by
// its plaintext. Plaintext markers and versions the decryptor skips are left as
// the literal bytes they are.
func (p *envParser) splice(ctx context.Context, s, e int) (string, error) {
	var out bytes.Buffer
	cursor := s
	for _, m := range p.markers {
		if m.Start < cursor {
			continue
		}
		if m.End > e {
			break
		}
		if !m.Encrypted {
			continue
		}
		plaintext, err := p.dec.DecryptMarker(ctx, m.Raw)
		if errors.Is(err, ErrSkip) {
			continue
		}
		if err != nil {
			return "", err
		}
		out.Write(p.content[cursor:m.Start])
		out.Write(plaintext)
		cursor = m.End
	}
	out.Write(p.content[cursor:e])
	return out.String(), nil
}

// soleMarker reports the single encrypted marker that makes up the whole of
// content[s:e), ignoring one surrounding pair of matching quotes.
func (p *envParser) soleMarker(s, e int) (Marker, bool) {
	s, e = stripOneQuotePair(p.content, s, e)
	for _, m := range p.markers {
		if m.Start > s {
			break
		}
		if m.Start == s && m.End == e && m.Encrypted {
			return m, true
		}
	}
	return Marker{}, false
}

// logicalLine returns the end of the line beginning at start, and the offset to
// resume from.
//
// A plaintext marker may legitimately span newlines (a PEM key, a pasted JSON
// blob), so a physical line break inside a marker span does not end the line —
// otherwise the second half of a two-line value would be read as its own
// assignment, which is the injection shape this parser exists to prevent.
func (p *envParser) logicalLine(start int) (end, next int) {
	for end = start; ; {
		rel := bytes.IndexByte(p.content[end:], '\n')
		if rel < 0 {
			return len(p.content), len(p.content) + 1
		}
		nl := end + rel
		if m, ok := p.markerContaining(nl); ok && m.Start >= start {
			end = m.End
			continue
		}
		return nl, nl + 1
	}
}

// markerContaining returns the marker whose span covers pos, if any.
func (p *envParser) markerContaining(pos int) (Marker, bool) {
	for _, m := range p.markers {
		if pos < m.Start {
			break
		}
		if pos < m.End {
			return m, true
		}
	}
	return Marker{}, false
}

// commentStart returns the offset where a comment opens within the line
// [lineStart, lineEnd), or lineEnd when there is none. The answer comes from
// the scanner's comment regions — the one implementation of that question in
// the repo — so `run` agrees with `encrypt`, `decrypt` and `check` about what
// is commented out.
func (p *envParser) commentStart(lineStart, lineEnd int) int {
	for p.regionIdx < len(p.regions) && p.regions[p.regionIdx].start < lineStart {
		p.regionIdx++
	}
	if p.regionIdx < len(p.regions) && p.regions[p.regionIdx].start < lineEnd {
		return p.regions[p.regionIdx].start
	}
	return lineEnd
}

// indexAssign returns the offset of the '=' that separates name from value in
// content[s:e), or -1. An '=' inside a marker belongs to the ciphertext (or to
// a plaintext value), not to the grammar.
func (p *envParser) indexAssign(s, e int) int {
	for i := s; i < e; i++ {
		if p.content[i] != '=' {
			continue
		}
		if m, ok := p.markerContaining(i); ok && m.Start >= s {
			i = m.End - 1
			continue
		}
		return i
	}
	return -1
}

// stripExport drops a leading `export ` from an assignment. Without this the
// key becomes "export FOO", which is not a variable name any child process will
// ever look up.
func stripExport(content []byte, s, e int) (int, int) {
	after := s + len(exportPrefix)
	if after >= e || !bytes.Equal(content[s:after], []byte(exportPrefix)) {
		return s, e
	}
	if !isEnvSpace(content[after]) {
		return s, e
	}
	return trimSpaceRange(content, after, e)
}

// stripOneQuotePair removes exactly one matching pair of surrounding quotes —
// never two, never an unbalanced one. `FOO="'bar'"` is the value `'bar'`.
func stripOneQuotePair(content []byte, s, e int) (int, int) {
	if e-s < 2 {
		return s, e
	}
	q := content[s]
	if (q == '"' || q == '\'') && content[e-1] == q {
		return s + 1, e - 1
	}
	return s, e
}

// trimSpaceRange narrows [s, e) past leading and trailing whitespace.
func trimSpaceRange(content []byte, s, e int) (int, int) {
	for s < e && isEnvSpace(content[s]) {
		s++
	}
	for e > s && isEnvSpace(content[e-1]) {
		e--
	}
	return s, e
}

// trimTrailingCR drops one trailing '\r' from a line of a CRLF file.
func trimTrailingCR(content []byte, s, e int) int {
	if e > s && content[e-1] == '\r' {
		return e - 1
	}
	return e
}

func isEnvSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '\v', '\f':
		return true
	}
	return false
}
