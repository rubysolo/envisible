package processor

import (
	"strings"
	"testing"
)

// wantMarker describes an expected marker without hand-computing byte offsets:
// text is the exact slice content[Start:End] should cover.
type wantMarker struct {
	text      string
	value     string
	encrypted bool
}

func checkMarkers(t *testing.T, content string, got []Marker, want []wantMarker) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d markers, want %d\ncontent: %q\ngot: %+v", len(got), len(want), content, got)
	}
	for i, w := range want {
		m := got[i]
		if m.Start < 0 || m.End > len(content) || m.Start >= m.End {
			t.Fatalf("marker %d has nonsensical span [%d:%d) for content of length %d", i, m.Start, m.End, len(content))
		}
		if text := content[m.Start:m.End]; text != w.text {
			t.Errorf("marker %d span = %q, want %q", i, text, w.text)
		}
		if m.Value != w.value {
			t.Errorf("marker %d Value = %q, want %q", i, m.Value, w.value)
		}
		if m.Encrypted != w.encrypted {
			t.Errorf("marker %d Encrypted = %v, want %v", i, m.Encrypted, w.encrypted)
		}
		if wantRaw := w.text[len("ENC[") : len(w.text)-1]; m.Raw != wantRaw {
			t.Errorf("marker %d Raw = %q, want %q", i, m.Raw, wantRaw)
		}
	}
}

func checkDefects(t *testing.T, got []Defect, want []DefectKind) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d defects (%+v), want %d", len(got), got, len(want))
	}
	for i, k := range want {
		if got[i].Kind != k {
			t.Errorf("defect %d kind = %v, want %v", i, got[i].Kind, k)
		}
	}
}

// --- ciphertext mode: must be byte-identical to the regex it replaces ---

func TestScanMarkersCiphertextMode(t *testing.T) {
	// Standard base64 alphabet only — that's the whole reason the simple
	// scan-to-first-']' is safe for ciphertext.
	const b64 = "YWJjZGVm+/0123456789=="

	cases := []struct {
		name    string
		content string
		markers []wantMarker
		defects []DefectKind
	}{
		{
			name:    "v1_alone",
			content: "ENC[v1:" + b64 + "]",
			markers: []wantMarker{{"ENC[v1:" + b64 + "]", "v1:" + b64, true}},
		},
		{
			name:    "v1_mid_line",
			content: "password: ENC[v1:" + b64 + "]  # trailing note",
			markers: []wantMarker{{"ENC[v1:" + b64 + "]", "v1:" + b64, true}},
		},
		{
			name:    "v2_alone",
			content: "ENC[v2:" + b64 + "]",
			markers: []wantMarker{{"ENC[v2:" + b64 + "]", "v2:" + b64, true}},
		},
		{
			name:    "v2_mid_line",
			content: "sa_key = \"ENC[v2:" + b64 + "]\"\n",
			markers: []wantMarker{{"ENC[v2:" + b64 + "]", "v2:" + b64, true}},
		},
		{
			name:    "two_markers_one_line",
			content: "a: ENC[v1:AAA=] b: ENC[v2:BBB=]",
			markers: []wantMarker{
				{"ENC[v1:AAA=]", "v1:AAA=", true},
				{"ENC[v2:BBB=]", "v2:BBB=", true},
			},
		},
		{
			name:    "multi_digit_version",
			content: "ENC[v37:AAA=]",
			markers: []wantMarker{{"ENC[v37:AAA=]", "v37:AAA=", true}},
		},
		{
			name:    "unterminated_ciphertext",
			content: "key: ENC[v1:abc",
			defects: []DefectKind{MalformedCiphertext},
		},
		{
			name:    "ciphertext_may_not_span_lines",
			content: "key: ENC[v1:abc\ndef]\n",
			defects: []DefectKind{MalformedCiphertext},
		},
		{
			name:    "malformed_ciphertext_does_not_hide_later_markers",
			content: "bad: ENC[v1:abc\ngood: ENC[v1:AAA=]\n",
			markers: []wantMarker{{"ENC[v1:AAA=]", "v1:AAA=", true}},
			defects: []DefectKind{MalformedCiphertext},
		},
		{
			name:    "not_a_version_prefix_falls_through_to_plaintext",
			content: "ENC[version:1]",
			markers: []wantMarker{{"ENC[version:1]", "version:1", false}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			markers, defects := ScanMarkers([]byte(tc.content))
			checkMarkers(t, tc.content, markers, tc.markers)
			checkDefects(t, defects, tc.defects)
		})
	}
}

// --- plaintext mode: the new behavior ---

func TestScanMarkersPlaintextMode(t *testing.T) {
	const pem = "-----BEGIN KEY-----\nMIIEv\n-----END KEY-----"

	cases := []struct {
		name    string
		content string
		markers []wantMarker
		defects []DefectKind
	}{
		{
			name:    "balanced_json_array",
			content: `sa: ENC[{"scopes":["a","b"]}]`,
			markers: []wantMarker{{`ENC[{"scopes":["a","b"]}]`, `{"scopes":["a","b"]}`, false}},
		},
		{
			name:    "multi_line_pem",
			content: "key: ENC[" + pem + "]\nnext: value\n",
			markers: []wantMarker{{"ENC[" + pem + "]", pem, false}},
		},
		{
			name:    "escaped_close_bracket",
			content: `password: ENC[ab\]cd]`,
			markers: []wantMarker{{`ENC[ab\]cd]`, "ab]cd", false}},
		},
		{
			name:    "escaped_open_bracket",
			content: `x: ENC[a\[b]`,
			markers: []wantMarker{{`ENC[a\[b]`, "a[b", false}},
		},
		{
			name:    "escaped_backslash",
			content: `x: ENC[a\\b]`,
			markers: []wantMarker{{`ENC[a\\b]`, `a\b`, false}},
		},
		{
			name:    "lone_backslash_is_literal",
			content: `x: ENC[a\nb]`,
			markers: []wantMarker{{`ENC[a\nb]`, `a\nb`, false}},
		},
		{
			name:    "empty_value_is_a_valid_marker",
			content: "x: ENC[]",
			markers: []wantMarker{{"ENC[]", "", false}},
		},
		{
			name:    "nested_brackets",
			content: "x: ENC[a[b[c]d]e]",
			markers: []wantMarker{{"ENC[a[b[c]d]e]", "a[b[c]d]e", false}},
		},
		{
			name:    "unterminated",
			content: "key: ENC[oops",
			defects: []DefectKind{Unterminated},
		},
		{
			name:    "unbalanced_open_bracket_is_unterminated",
			content: "key: ENC[a[b]\n",
			defects: []DefectKind{Unterminated},
		},
		{
			name:    "two_plaintext_markers_one_line",
			content: "a: ENC[one] b: ENC[two]",
			markers: []wantMarker{
				{"ENC[one]", "one", false},
				{"ENC[two]", "two", false},
			},
		},
		{
			name:    "hash_inside_value_is_not_special_to_the_scanner",
			content: "HASHY=ENC[p@ss # word]",
			markers: []wantMarker{{"ENC[p@ss # word]", "p@ss # word", false}},
		},
		{
			name:    "nested_marker_text_is_part_of_the_value",
			content: `x: ENC[literal ENC\[inner\] text]`,
			markers: []wantMarker{{`ENC[literal ENC\[inner\] text]`, "literal ENC[inner] text", false}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			markers, defects := ScanMarkers([]byte(tc.content))
			checkMarkers(t, tc.content, markers, tc.markers)
			checkDefects(t, defects, tc.defects)
		})
	}
}

// --- comment interaction: markers first, then comments against marker spans ---

func TestScanComments(t *testing.T) {
	cases := []struct {
		name    string
		content string
		markers []wantMarker
		defects []DefectKind
	}{
		{
			name:    "ciphertext_in_full_line_comment_is_not_returned",
			content: "# ENC[v1:AAA=]\n",
		},
		{
			name:    "ciphertext_in_trailing_comment_is_not_returned",
			content: "PASSWORD=ENC[v1:AAA=]  # old: ENC[v1:BBB=]\n",
			markers: []wantMarker{{"ENC[v1:AAA=]", "v1:AAA=", true}},
		},
		{
			name:    "indented_comment",
			content: "   # ENC[secret]\n",
		},
		{
			name:    "hash_inside_a_marker_value_does_not_start_a_comment",
			content: "HASHY=ENC[p@ss # word]\n",
			markers: []wantMarker{{"ENC[p@ss # word]", "p@ss # word", false}},
		},
		{
			name:    "hash_not_preceded_by_space_is_not_a_comment",
			content: "NOSPACE=ENC[a#b]\n",
			markers: []wantMarker{{"ENC[a#b]", "a#b", false}},
		},
		{
			name:    "unterminated_marker_in_prose_is_not_a_defect",
			content: "# see ENC[\nREAL=ENC[v1:AAA=]\n",
			markers: []wantMarker{{"ENC[v1:AAA=]", "v1:AAA=", true}},
		},
		{
			name:    "unterminated_marker_in_code_is_a_defect",
			content: "REAL=ENC[\n",
			defects: []DefectKind{Unterminated},
		},
		{
			name:    "hash_on_a_continuation_line_of_a_multi_line_marker",
			content: "key: ENC[line1\n# not a comment\nline3]\nafter: 1\n",
			markers: []wantMarker{{"ENC[line1\n# not a comment\nline3]", "line1\n# not a comment\nline3", false}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			markers, defects := Scan([]byte(tc.content))
			checkMarkers(t, tc.content, markers, tc.markers)
			checkDefects(t, defects, tc.defects)
		})
	}
}

func TestScanMarkersIgnoresComments(t *testing.T) {
	// ScanMarkers is deliberately comment-blind; Scan is the filtering layer.
	content := "# ENC[v1:AAA=]\n"
	markers, _ := ScanMarkers([]byte(content))
	if len(markers) != 1 {
		t.Fatalf("ScanMarkers should see the commented marker; got %d", len(markers))
	}
	filtered, _ := Scan([]byte(content))
	if len(filtered) != 0 {
		t.Fatalf("Scan should drop the commented marker; got %+v", filtered)
	}
}

func TestLineCol(t *testing.T) {
	content := []byte("alpha\nbeta\n\ngamma")
	cases := []struct {
		offset    int
		line, col int
	}{
		{0, 1, 1},
		{4, 1, 5},
		{6, 2, 1},
		{11, 3, 1},
		{12, 4, 1},
		{16, 4, 5},
		{1000, 4, 6}, // clamped to EOF
	}
	for _, tc := range cases {
		line, col := LineCol(content, tc.offset)
		if line != tc.line || col != tc.col {
			t.Errorf("LineCol(%d) = %d:%d, want %d:%d", tc.offset, line, col, tc.line, tc.col)
		}
	}
}

func TestUnmatchedTrailingBracket(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"ambiguous_row_one", "password: ENC[ab]cd]", true},
		{"clean_marker", "password: ENC[abcd]", false},
		{"two_markers_on_a_line_are_balanced", "a: ENC[one] b: ENC[two]", false},
		{"bracket_pair_after_marker", "a: ENC[one] list: [x]", false},
		{"bracket_on_the_next_line_does_not_count", "a: ENC[one]\n]\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			markers, _ := Scan([]byte(tc.content))
			if len(markers) == 0 {
				t.Fatalf("no markers scanned from %q", tc.content)
			}
			if got := UnmatchedTrailingBracket([]byte(tc.content), markers[0]); got != tc.want {
				t.Errorf("UnmatchedTrailingBracket = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUnmatchedTrailingBracketIgnoresCiphertext(t *testing.T) {
	content := []byte("password: ENC[v1:AAA=]]")
	markers, _ := Scan(content)
	if len(markers) != 1 {
		t.Fatalf("want 1 marker, got %d", len(markers))
	}
	if UnmatchedTrailingBracket(content, markers[0]) {
		t.Errorf("the heuristic must only fire for plaintext markers")
	}
}

// --- escape/unescape round-trip properties ---

// fuzzCorpus is the shared seed corpus for both properties: brackets,
// backslashes, newlines, invalid UTF-8, and the shapes from the evidence table.
var fuzzCorpus = []string{
	"",
	"plain",
	"ab]cd",
	"a[b",
	`a\b`,
	`\`,
	`\]`,
	`\\]`,
	"]]][[[",
	`{"scopes":["a","b"]}`,
	"-----BEGIN KEY-----\nMIIEv\n-----END KEY-----",
	"line1\nline2\n",
	"p@ss # word",
	"ENC[nested]",
	"\x00\xff\xfe",
	"héllo · wörld",
	"tab\there",
}

func FuzzMarkerEscapeRoundTrip(f *testing.F) {
	for _, s := range fuzzCorpus {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got := unescapeMarkerValue(escapeMarkerValue(s)); got != s {
			t.Fatalf("unescape(escape(%q)) = %q", s, got)
		}
	})
}

// FuzzMarkerScanRoundTrip is the property that makes machine-written markers
// safe: whatever envisible emits, the scanner reads back verbatim as exactly
// one marker.
func FuzzMarkerScanRoundTrip(f *testing.F) {
	for _, s := range fuzzCorpus {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		escaped := escapeMarkerValue(s)
		// A plaintext value that itself looks like a versioned marker body is
		// irreducibly ambiguous with real ciphertext — the scanner enters
		// ciphertext mode, exactly as the pre-existing IsEncryptedInner check
		// always has. Out of scope for this property.
		if IsEncryptedInner(escaped) {
			t.Skip("value is indistinguishable from a versioned inner")
		}

		content := []byte("ENC[" + escaped + "]")
		markers, defects := Scan(content)
		if len(defects) != 0 {
			t.Fatalf("escaped %q produced defects: %+v", s, defects)
		}
		if len(markers) != 1 {
			t.Fatalf("escaped %q produced %d markers, want 1", s, len(markers))
		}
		m := markers[0]
		if m.Start != 0 || m.End != len(content) {
			t.Fatalf("marker span [%d:%d), want [0:%d)", m.Start, m.End, len(content))
		}
		if m.Encrypted {
			t.Fatalf("escaped %q was misread as ciphertext", s)
		}
		if m.Value != s {
			t.Fatalf("round trip lost data: Value = %q, want %q", m.Value, s)
		}
	})
}

// The scanner must never exceed depth 1 on machine-written content, so an
// escaped value can never swallow text that follows it.
func FuzzMarkerCannotSwallowFollowingText(f *testing.F) {
	for _, s := range fuzzCorpus {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		escaped := escapeMarkerValue(s)
		if IsEncryptedInner(escaped) {
			t.Skip("value is indistinguishable from a versioned inner")
		}
		const tail = "\nSENTINEL=untouched\n"
		content := []byte("KEY=ENC[" + escaped + "]" + tail)
		markers, defects := Scan(content)
		if len(defects) != 0 {
			t.Fatalf("defects: %+v", defects)
		}
		if len(markers) != 1 {
			t.Fatalf("got %d markers, want 1", len(markers))
		}
		if rest := string(content[markers[0].End:]); rest != tail {
			t.Fatalf("marker swallowed following text: remainder %q, want %q", rest, tail)
		}
	})
}

func TestEscapeMarkerValueShape(t *testing.T) {
	cases := map[string]string{
		"":         "",
		"plain":    "plain",
		"ab]cd":    `ab\]cd`,
		"a[b":      `a\[b`,
		`a\b`:      `a\\b`,
		"a\nb":     "a\nb", // newlines are legal inside a plaintext marker
		"[]\\":     `\[\]\\`,
		"héllo ·":  "héllo ·",
		"\x00\xff": "\x00\xff",
	}
	for in, want := range cases {
		if got := escapeMarkerValue(in); got != want {
			t.Errorf("escapeMarkerValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnescapeMarkerValueLeavesUnknownEscapes(t *testing.T) {
	// Only \, [ and ] are escapes. Everything else keeps its backslash, so a
	// literal "C:\path" or a JSON "\n" survives a scan unharmed.
	for _, s := range []string{`a\nb`, `C:\path\to`, `\`, `trailing\`} {
		if got := unescapeMarkerValue(s); got != s {
			t.Errorf("unescapeMarkerValue(%q) = %q, want unchanged", s, got)
		}
	}
}

func TestCommentRegionsRespectMarkerSpans(t *testing.T) {
	content := []byte("A=ENC[v1:AAA=] # note\n# whole line\nB=ENC[x # y]\n")
	markers, _ := ScanMarkers(content)
	regions := CommentRegions(content, markers)
	if len(regions) != 2 {
		t.Fatalf("want 2 comment regions, got %d (%+v)", len(regions), regions)
	}
	got := []string{
		string(content[regions[0].start:regions[0].end]),
		string(content[regions[1].start:regions[1].end]),
	}
	want := []string{"# note", "# whole line"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("region %d = %q, want %q", i, got[i], want[i])
		}
	}
	if strings.Contains(strings.Join(got, ""), "# y") {
		t.Errorf("a '#' inside a marker must not open a comment")
	}
}
