package processor

import (
	"reflect"
	"testing"
)

// Boundary cases for the marker scanner that mutation testing showed were not
// pinned by marker_test.go. Each case names the boundary it holds in place.

// checkDefectsAt is checkDefects plus the exact offset of every defect.
func checkDefectsAt(t *testing.T, got []Defect, want []Defect) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("defects = %+v, want %+v", got, want)
	}
}

// --- ScanMarkers: the input ends exactly at a boundary ---

func TestScanMarkersInputEndsAtBoundary(t *testing.T) {
	cases := []struct {
		name    string
		content string
		markers []wantMarker
		defects []Defect
	}{
		{
			// Nothing to scan at all.
			name:    "empty_input",
			content: "",
		},
		{
			// One byte short of an opener is not an opener.
			name:    "three_bytes_of_an_opener",
			content: "ENC",
		},
		{
			// The opener is the whole input: i+len("ENC[") == len(content) on
			// the first iteration, and the loop must still look at it.
			name:    "opener_is_the_whole_input",
			content: "ENC[",
			defects: []Defect{{Offset: 0, Kind: Unterminated}},
		},
		{
			// Same boundary, reached after a marker: the bytes left after the
			// first marker closes are exactly one opener.
			name:    "bare_opener_right_after_a_marker_at_eof",
			content: "ENC[a]ENC[",
			markers: []wantMarker{{"ENC[a]", "a", false}},
			defects: []Defect{{Offset: 6, Kind: Unterminated}},
		},
		{
			// ...and after a ciphertext marker, which resumes on its own path.
			name:    "bare_opener_right_after_ciphertext_at_eof",
			content: "ENC[v1:QUJD]ENC[",
			markers: []wantMarker{{"ENC[v1:QUJD]", "v1:QUJD", true}},
			defects: []Defect{{Offset: 12, Kind: Unterminated}},
		},
		{
			// A backslash as the very last byte has no byte after it to
			// escape: it is a literal, and the body is simply unterminated.
			name:    "backslash_is_the_last_byte",
			content: "ENC[ab\\",
			defects: []Defect{{Offset: 0, Kind: Unterminated}},
		},
		{
			// The same, but on a body that starts in ciphertext mode and is
			// handed to plaintext mode because of the backslash.
			name:    "backslash_is_the_last_byte_of_a_versioned_body",
			content: "K=ENC[v1:ab\\",
			defects: []Defect{{Offset: 2, Kind: Unterminated}},
		},
		{
			// An escaped ']' as the last two bytes does not close the marker.
			name:    "escaped_close_is_the_last_two_bytes",
			content: "ENC[ab\\]",
			defects: []Defect{{Offset: 0, Kind: Unterminated}},
		},
		{
			// A continuation as the last two bytes: the newline is consumed,
			// then the input ends.
			name:    "continuation_is_the_last_two_bytes",
			content: "ENC[ab\\\n",
			defects: []Defect{{Offset: 0, Kind: Unterminated}},
		},
		{
			// A marker that ends on the very last byte, no trailing newline.
			name:    "marker_closes_on_the_last_byte",
			content: "K=ENC[ab]",
			markers: []wantMarker{{"ENC[ab]", "ab", false}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			markers, defects := ScanMarkers([]byte(tc.content))
			checkMarkers(t, tc.content, markers, tc.markers)
			checkDefectsAt(t, defects, tc.defects)
		})
	}
}

// Adjacent markers: scanning must resume exactly after the ']' that closed the
// previous marker, for both modes and for an empty body.
func TestScanMarkersAdjacentMarkers(t *testing.T) {
	cases := []struct {
		name    string
		content string
		markers []wantMarker
		starts  []int
	}{
		{
			name:    "plaintext_then_plaintext",
			content: "ENC[a]ENC[b]",
			markers: []wantMarker{{"ENC[a]", "a", false}, {"ENC[b]", "b", false}},
			starts:  []int{0, 6},
		},
		{
			// closeIdx == inner: the shortest marker there is.
			name:    "empty_bodies",
			content: "ENC[]ENC[]",
			markers: []wantMarker{{"ENC[]", "", false}, {"ENC[]", "", false}},
			starts:  []int{0, 5},
		},
		{
			name:    "ciphertext_then_ciphertext",
			content: "ENC[v1:QQ]ENC[v2:Qg]",
			markers: []wantMarker{{"ENC[v1:QQ]", "v1:QQ", true}, {"ENC[v2:Qg]", "v2:Qg", true}},
			starts:  []int{0, 10},
		},
		{
			name:    "ciphertext_then_plaintext",
			content: "ENC[v1:QQ]ENC[b]",
			markers: []wantMarker{{"ENC[v1:QQ]", "v1:QQ", true}, {"ENC[b]", "b", false}},
			starts:  []int{0, 10},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			markers, defects := ScanMarkers([]byte(tc.content))
			checkMarkers(t, tc.content, markers, tc.markers)
			checkDefectsAt(t, defects, nil)
			for i, m := range markers {
				if m.Start != tc.starts[i] {
					t.Errorf("marker %d Start = %d, want %d", i, m.Start, tc.starts[i])
				}
			}
		})
	}
}

// --- isCiphertextStart: the edges of ^v\d+: ---

func TestCiphertextStartBoundaries(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"v0:", true}, // '0' is the lowest digit
		{"v9:", true}, // '9' is the highest digit, and still a digit
		{"v09:x", true},
		{"v19:x", true},
		{"v/:", false}, // '/' is the byte just below '0'
		{"v::", false}, // ':' is the byte just above '9': no digits at all
		{"v:x", false}, // no digits
		{"v12", false}, // digits run to the very end: no ':' to find
		{"v123", false},
		{"v1", false}, // shorter than any version prefix
		{"", false},
	}
	for _, tc := range cases {
		if got := isCiphertextStart([]byte(tc.in)); got != tc.want {
			t.Errorf("isCiphertextStart(%q) = %v, want %v", tc.in, got, tc.want)
		}
		// The byte-slice twin must agree with the regexp one.
		if got := IsEncryptedInner(tc.in); got != tc.want {
			t.Errorf("IsEncryptedInner(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestScanMarkersVersionPrefixBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		content string
		markers []wantMarker
		defects []Defect
	}{
		{
			// The version digits are the last bytes of the input.
			name:    "digits_run_to_eof",
			content: "ENC[v12",
			defects: []Defect{{Offset: 0, Kind: Unterminated}},
		},
		{
			// "v1:" exactly, then EOF: the shortest ciphertext start.
			name:    "prefix_then_eof",
			content: "ENC[v1:",
			defects: []Defect{{Offset: 0, Kind: MalformedCiphertext}},
		},
		{
			// v9 is a version; a body containing '\]' tells the modes apart
			// (ciphertext stops at the first ']').
			name:    "v9_is_ciphertext",
			content: "ENC[v9:QUJD]",
			markers: []wantMarker{{"ENC[v9:QUJD]", "v9:QUJD", true}},
		},
		{
			name:    "v0_is_ciphertext",
			content: "ENC[v0:QUJD]",
			markers: []wantMarker{{"ENC[v0:QUJD]", "v0:QUJD", true}},
		},
		{
			// 'v' followed by ':' with no digit is plaintext.
			name:    "v_colon_is_plaintext",
			content: "ENC[v:QUJD]",
			markers: []wantMarker{{"ENC[v:QUJD]", "v:QUJD", false}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			markers, defects := ScanMarkers([]byte(tc.content))
			checkMarkers(t, tc.content, markers, tc.markers)
			checkDefectsAt(t, defects, tc.defects)
		})
	}
}

// --- CommentRegions / Scan: where a comment starts and where it ends ---

func TestCommentRegionBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		content string
		regions []span
		markers []wantMarker // what Scan keeps
	}{
		{
			// The byte BEFORE '#' decides, not the byte after: space before,
			// no space after, is a comment.
			name:    "space_before_no_space_after",
			content: "a: b #ENC[x]",
			regions: []span{{5, 12}},
		},
		{
			// ...and no space before, space after, is not.
			name:    "no_space_before_space_after",
			content: "a# ENC[x]",
			markers: []wantMarker{{"ENC[x]", "x", false}},
		},
		{
			name:    "tab_before",
			content: "a: b\t#ENC[x]",
			regions: []span{{5, 12}},
		},
		{
			// '#' is the last byte of the line: there is no byte after it.
			name:    "hash_is_the_last_byte",
			content: "a #",
			regions: []span{{2, 3}},
		},
		{
			name:    "hash_is_the_last_byte_of_a_line",
			content: "a #\nK=ENC[x]\n",
			regions: []span{{2, 3}},
			markers: []wantMarker{{"ENC[x]", "x", false}},
		},
		{
			// '#' at offset 0 of the file.
			name:    "hash_at_offset_zero",
			content: "#ENC[x]\nK=ENC[y]\n",
			regions: []span{{0, 7}},
			markers: []wantMarker{{"ENC[y]", "y", false}},
		},
		{
			// The last line has no trailing newline: it is still a line, and
			// its comment runs to len(content).
			name:    "comment_on_last_line_without_newline",
			content: "A=1\n# ENC[x]",
			regions: []span{{4, 12}},
		},
		{
			name:    "comment_on_last_line_with_newline",
			content: "A=1\n# ENC[x]\n",
			regions: []span{{4, 12}},
		},
		{
			// A single unterminated line that is all comment.
			name:    "only_line_is_a_comment_without_newline",
			content: "# ENC[x]",
			regions: []span{{0, 8}},
		},
		{
			// CRLF: the region ends at the '\n', so it includes the '\r'.
			name:    "crlf",
			content: "# ENC[x]\r\nK=ENC[y]\r\n",
			regions: []span{{0, 9}},
			markers: []wantMarker{{"ENC[y]", "y", false}},
		},
		{
			// A '#' touching the outside of a marker on either side: neither
			// is inside the span, and neither follows whitespace.
			name:    "hash_hard_against_a_marker",
			content: "K=#ENC[a]#x\n",
			markers: []wantMarker{{"ENC[a]", "a", false}},
		},
		{
			// A marker ends, then a real comment begins after a space.
			name:    "comment_after_a_marker",
			content: "K=ENC[a] #ENC[b]",
			regions: []span{{9, 16}},
			markers: []wantMarker{{"ENC[a]", "a", false}},
		},
		{
			// '#' after a space INSIDE a marker is content; the one after the
			// marker closes is the comment.
			name:    "hash_inside_then_after_a_marker",
			content: "K=ENC[a #b] #c",
			regions: []span{{12, 14}},
			markers: []wantMarker{{"ENC[a #b]", "a #b", false}},
		},
		{
			name:    "empty_input",
			content: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.content)
			all, _ := ScanMarkers(content)
			regions := CommentRegions(content, all)
			if len(regions) != len(tc.regions) || (len(regions) > 0 && !reflect.DeepEqual(regions, tc.regions)) {
				t.Errorf("CommentRegions = %+v, want %+v", regions, tc.regions)
			}
			markers, defects := Scan(content)
			checkMarkers(t, tc.content, markers, tc.markers)
			checkDefectsAt(t, defects, nil)
		})
	}
}

// A defect is dropped only when its opener sits inside a comment; one that
// ends the file outside any comment is kept, at its exact offset.
func TestScanDefectsAgainstCommentBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		content string
		defects []Defect
	}{
		{"opener_in_trailing_comment_at_eof", "A=1 # ENC[", nil},
		{"opener_before_a_comment", "A=ENC[ # x", []Defect{{Offset: 2, Kind: Unterminated}}},
		{"opener_on_the_line_after_a_comment", "# x\nA=ENC[", []Defect{{Offset: 6, Kind: Unterminated}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			markers, defects := Scan([]byte(tc.content))
			checkMarkers(t, tc.content, markers, nil)
			checkDefectsAt(t, defects, tc.defects)
		})
	}
}

// --- UnmatchedTrailingBracket: depth must go up on '[' and down on ']' ---

func TestUnmatchedTrailingBracketDepth(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		// A balanced pair after the marker, then a ']' nothing opened.
		{"balanced_pair_then_stray_close", "p: ENC[ab] [x] y]", true},
		// Nested balanced pairs, then a stray close.
		{"nested_pairs_then_stray_close", "p: ENC[ab] [[x]] ]", true},
		// Balanced pairs only: every ']' was opened.
		{"balanced_pair_only", "p: ENC[ab] [x]", false},
		{"two_balanced_pairs", "p: ENC[ab] [x][y]", false},
		// An opener that never closes is not a stray close.
		{"unclosed_open", "p: ENC[ab] [x", false},
		// The stray close is on the next line: out of scope.
		{"stray_close_on_next_line", "p: ENC[ab] [x]\n]", false},
		// The marker is the last thing in the input.
		{"marker_at_eof", "p: ENC[ab]", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.content)
			markers, defects := ScanMarkers(content)
			checkMarkers(t, tc.content, markers, []wantMarker{{"ENC[ab]", "ab", false}})
			checkDefectsAt(t, defects, nil)
			if got := UnmatchedTrailingBracket(content, markers[0]); got != tc.want {
				t.Errorf("UnmatchedTrailingBracket(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

// LineCol clamps at both ends; offset 0 is line 1, column 1 either way.
func TestLineColClamps(t *testing.T) {
	content := []byte("ab\ncd")
	cases := []struct {
		offset, line, col int
	}{
		{-1, 1, 1},
		{0, 1, 1},
		{1, 1, 2},
		{3, 2, 1}, // first byte after the newline
		{5, 2, 3}, // len(content): one past the last byte
		{6, 2, 3}, // beyond the end clamps to len(content)
	}
	for _, tc := range cases {
		line, col := LineCol(content, tc.offset)
		if line != tc.line || col != tc.col {
			t.Errorf("LineCol(%d) = %d:%d, want %d:%d", tc.offset, line, col, tc.line, tc.col)
		}
	}
}
