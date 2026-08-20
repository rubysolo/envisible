# Plan 01 — Replace the `ENC[...]` regex with a real scanner

**Kind:** security fix (silent plaintext leak + silent value corruption)
**Status:** implemented, with one design revision — see below
**Depends on:** nothing
**Blocks:** nothing, but should land alone and first

> **Revision after adversarial review.** As written below, this plan let a
> plaintext body treat newlines as ordinary content so a PEM could be pasted in
> raw. Review showed that made a forgotten `]` silently destructive — the lines
> below it were absorbed into the secret and disappeared from the file, with
> `encrypt` exiting 0 and no defect reported. **A plaintext body now ends at the
> first unescaped newline**, and a value that really contains newlines is
> written with a backslash before each one (a continuation). Escape set is
> therefore `\[`, `\]`, `\\`, backslash-newline, plus the leading `\v` guard for
> a value beginning `vN:`.
>
> The escape is a backslash before a *real* line break, not the two characters
> `\n` — a single-line JSON service-account key carries literal `\n` in its
> `private_key` field, and reading those as newlines would corrupt it.
>
> Consequence: a raw multi-line paste is now a loud defect rather than a value.
> The answer for such payloads is plan 05's `envisible set`, which never puts
> plaintext in the file. The shipped grammar is recorded in
> [ADR 0001](../adr/0001-enc-marker-grammar.md), which supersedes the Design
> section below where they disagree.

---

## Problem

Marker parsing is a single non-greedy, line-scoped regex:

```go
// pkg/processor/processor.go:23
encRegex = regexp.MustCompile(`ENC\[(.*?)\]`)
```

Two properties of that pattern are load-bearing and wrong:

1. **`.*?` stops at the first `]`.** A plaintext value containing `]` is truncated.
2. **Go's `.` does not match `\n`,** and `walkOutsideComments` chops content at newlines
   before the regex ever runs, so a marker spanning lines cannot match at all.

Neither failure is reported. `envisible encrypt` prints success, and `envisible check`
— including the pre-commit hook installed by `envisible git install-hook` — passes.

### Evidence

Characterization run against the current `pkg/processor` (round-trip = encrypt then
decrypt with `--strip`; "check" columns are what `cmd/check.go` counts):

| input | after encrypt | round-trip | check |
|---|---|---|---|
| `password: ENC[ab]cd]` | `ENC[v1:…]cd]` | `password: abcd]` | 1 marker, **0 unencrypted → passes** |
| `sa: ENC[{"scopes":["a","b"]}]` | `ENC[v1:…]}]` | `sa: {"scopes":["a","b"}]` | 1 marker, **0 unencrypted → passes** |
| `key: ENC[-----BEGIN KEY-----\nMIIEv\n-----END KEY-----]` | *unchanged* | *unchanged* | **0 markers → passes** |
| `key: ENC[oops-no-close` | *unchanged* | *unchanged* | **0 markers → passes** |
| `a: ENC[one] b: ENC[two]` | both encrypted | `a: one b: two` | 2 markers, 0 unencrypted (correct — must not regress) |

Reading those rows in order:

- **Row 1 — partial encryption.** The stored secret is `ab`. The characters `cd]` stay in
  the file as plaintext. The round-trip *looks* right (`abcd]`), which is what makes it
  dangerous: nothing downstream notices that part of the secret was committed in the clear.
- **Row 2 — silent corruption.** The `]` closing the JSON array is consumed as the marker
  terminator and **destroyed**. The value that comes back out is not the value that went in,
  and it is no longer valid JSON. Nothing errors.
- **Rows 3 and 4 — total no-op.** The file is written back with the plaintext untouched,
  and because no marker matched, `check` sees nothing to complain about. A multi-line
  service-account JSON or PEM key pasted into a marker gets committed verbatim.

Row 3 also contradicts a documented promise. `README.md` (Cloud KMS wire format) says
*"Plaintexts are unbounded in size (PEM keys, certificates, etc. — the envelope handles
them)."* That is true of the envelope and false of the parser: there is currently no way to
get a multi-line value into a marker at all.

### Secondary defects in the same area

- **The regex is duplicated.** `cmd/check.go:49` compiles its own copy, so `check` and
  `encrypt` can drift. They must agree by construction — `check`'s entire job is predicting
  what `encrypt` will do.
- **`RewrapContent` does not skip comments.** `EncryptContent` and `DecryptContent` route
  through `walkOutsideComments`; `RewrapContent` (`pkg/processor/rewrap.go:26`) applies
  `encRegex` to raw content. So `kms rotate` sends a ciphertext parked in a comment to the
  KMS, while `DecryptContent`'s doc comment promises the opposite ("a ciphertext kept in a
  comment for reference is never sent to the KMS").
- **`DecryptContent(keepMarkers=true)` is lossy.** It writes `ENC[<plaintext>]` with no
  escaping, so `envisible edit` on a value containing `]` produces a file whose markers
  re-parse differently than they were written. Today this is masked by the fact that such a
  value cannot be encrypted in the first place.

---

## Goals

1. A plaintext value containing `]`, `[`, or newlines either encrypts correctly or fails
   loudly. Never silently truncated, never silently corrupted, never silently skipped.
2. An unterminated `ENC[` in a code position is an error, not invisible.
3. One scanner, used by every caller.
4. **Zero change to any existing encrypted file.** Not one byte of ciphertext moves, and
   scanning an already-encrypted file produces exactly today's result.

### Non-goals

- Changing the `v1:` / `v2:` wire formats. Untouched.
- Structured-format awareness (YAML/JSON/TOML parsing). The scanner stays text-level; that
  substring-granularity property is envisible's differentiator and is preserved.
- Resolving the genuinely ambiguous case (see "Known limitation" below).

---

## Design

### New file: `pkg/processor/marker.go`

```go
// Marker is one ENC[...] occurrence located in a byte slice.
type Marker struct {
    Start, End int    // content[Start:End] is the whole marker, brackets included
    Raw        string // bytes between the brackets, exactly as they appear on disk
    Value      string // Raw with escapes resolved; meaningless when Encrypted
    Encrypted  bool   // Raw carries a vN: prefix
}

// Defect is a malformed marker token that ScanMarkers could not turn into a Marker.
type Defect struct {
    Offset int
    Kind   DefectKind // Unterminated | MalformedCiphertext
}

func ScanMarkers(content []byte) (markers []Marker, defects []Defect)
```

`ScanMarkers` never returns an error — it reports defects and lets the caller decide
severity (see "Severity policy"). This also breaks the ordering cycle between marker
detection and comment detection, described below.

### Scanning algorithm

Walk the content looking for the literal `ENC[`. At each hit, look at what follows:

**Ciphertext mode** — the bytes after `ENC[` match `^v\d+:`.
Scan forward to the first `]`, refusing to cross a `\n`. Both `v1:` and `v2:` inners are
`vN:` + standard base64, whose alphabet is `A-Za-z0-9+/=` — it cannot contain `[`, `]`,
`\`, or a newline. So the simple scan is exactly correct, and *identical to today's regex*
for every marker envisible has ever written. If no `]` appears before the newline or EOF,
emit a `MalformedCiphertext` defect and resume scanning after the `ENC[`.

**Plaintext mode** — anything else.
Scan forward tracking bracket depth, starting at 1:

- `\` followed by `[`, `]`, or `\` — consume both bytes, depth unchanged.
- `[` — depth++
- `]` — depth--; at zero, the marker ends here.
- any other byte, **including `\n`** — consume.

If EOF is reached with depth > 0, emit an `Unterminated` defect at the `ENC[` offset and
resume scanning after it.

This gives us, in one pass:

- `ENC[{"scopes":["a","b"]}]` → `Value = {"scopes":["a","b"]}` (balanced, no escaping needed)
- `ENC[-----BEGIN KEY-----\nMIIEv\n-----END KEY-----]` → the whole PEM
- `ENC[ab\]cd]` → `Value = ab]cd`
- `ENC[oops-no-close` → `Unterminated` defect
- `a: ENC[one] b: ENC[two]` → two markers (unchanged)

### Escaping

Escape set: `\`, `[`, `]`. Two functions, mutual inverses:

```go
func escapeMarkerValue(s string) string   // \ → \\, [ → \[, ] → \]
func unescapeMarkerValue(s string) string
```

Escaping `[` as well as `]` matters: a machine-written value like `a[b` left unescaped
would push depth to 2 and swallow the rest of the file. With both escaped, anything
envisible emits has depth that never exceeds 1, so machine-written markers are
unambiguous by construction. Bracket *balancing* exists purely so a human pasting a JSON
blob does not have to escape anything.

`DecryptContent(..., keepMarkers=true)` must emit `ENC[escapeMarkerValue(plaintext)]`.
That is what makes the `envisible edit` round-trip lossless for values containing brackets.

### Comment interaction

Today `walkOutsideComments` splits on `\n`, and `splitLineComment` runs `encRegex` per
line so that a `#` inside a marker is not treated as a comment. With multi-line markers,
comment detection needs marker spans computed over the *whole* content, and marker
scanning needs to know about comments to decide whether an unterminated `ENC[` is a real
defect. That is circular, so break it in a fixed order:

1. `ScanMarkers(content)` over the full content, ignoring comments entirely.
2. Compute comment regions line by line: a `#` at line start or preceded by space/tab, and
   **not inside any marker span** from step 1, starts a comment that runs to end of line.
3. Drop every marker whose `Start` falls inside a comment region. (Preserves today's
   behavior: markers in comments are left alone by both encrypt and decrypt.)
4. Drop every defect whose offset falls inside a comment region. A `# TODO: wrap this in
   ENC[` is prose, not a malformed marker.

Then rewriting is a single pass over the surviving markers by byte offset. `walkOutsideComments`
and `splitLineComment` collapse into this; the per-line regex disappears.

### Severity policy

An unterminated `ENC[` in a code position means something. What to *do* about it depends
on whether the command is about to produce an artifact you might commit:

| Command | Defect handling | Why |
|---|---|---|
| `encrypt`, `edit`, `check` | **error**, non-zero exit, nothing written | Write and validate paths. Catch it before it reaches a commit. |
| `decrypt`, `run`, `kms rotate` | **warn** on stderr, continue | Read paths. A stray `ENC[` in a config file must not take down a deploy. |

This also bounds the blast radius of the change: the only way an existing project starts
*failing* is if it has a literal unterminated `ENC[` in a non-comment position **and** runs
`encrypt`/`check`. That file is already silently broken today.

### Known limitation (documented, not fixed)

An unbalanced, unescaped `]` in a hand-written plaintext marker is irreducibly ambiguous:

```yaml
password: ENC[ab]cd]      # is the secret "ab", or "ab]cd"?
```

Bracket balancing does not help — depth legitimately reaches zero at the first `]`. The
scanner will read `ab`, same as today. Three mitigations, in order of how much they matter:

1. **`envisible set` (plan 05).** Machine-sourced secrets never appear in the file as
   plaintext at all, so this grammar never sees them. This is the real answer for anything
   coming out of a secret manager, and it is why plan 05 exists.
2. **The documented escape.** `ENC[ab\]cd]` is unambiguous.
3. **A heuristic warning.** When a *plaintext* marker is followed on the same line by an
   unmatched `]`, warn: `plaintext marker at line N is followed by an unmatched ']' — if
   it is part of the secret, escape it as '\]'`. False positives are rare because the
   trigger requires a plaintext marker (a transient authoring state) *and* a trailing
   unmatched bracket on the same line.

Document the limitation in `README.md` under "How it Works" rather than leaving it implicit.

---

## Implementation

### Step 1 — `pkg/processor/marker.go` (new)

`Marker`, `Defect`, `ScanMarkers`, `escapeMarkerValue`, `unescapeMarkerValue`, and a
`CommentRegions(content []byte, markers []Marker) []span` helper. Pure functions over byte
slices, no I/O, no crypto. Fully unit-testable in isolation — this is where the bulk of the
new tests go.

Also add the filtering entry point the commands actually call:

```go
// Scan returns the effective markers (comments excluded) and the defects that
// matter (comments excluded).
func Scan(content []byte) (markers []Marker, defects []Defect)
```

### Step 2 — rewrite the three rewriters on top of it

In `pkg/processor/processor.go`:

- `EncryptContent(content, enc) ([]byte, []Defect, error)` — scan, skip `Encrypted`
  markers (idempotency, unchanged), seal `Value` for the rest, splice
  `ENC[<inner>]` by offset.
- `DecryptContent(ctx, content, dec, keepMarkers) ([]byte, []Defect, error)` — scan, skip
  plaintext markers, `ErrSkip` still means leave-in-place, and `keepMarkers` now re-escapes.

In `pkg/processor/rewrap.go`:

- `RewrapContent` switches to `Scan` too, which incidentally gives it the comment-skipping
  it was missing. **Behavior change** — call it out in the changelog.

Delete `walkOutsideComments`, `splitLineComment`, and `encRegex`.

The extra `[]Defect` return value is a signature change on three exported functions. The
package has no external consumers beyond `cmd/`, so this is cheap; the alternative
(stashing defects on a struct) is worse for testability.

### Step 3 — `cmd/check.go`

Delete the local `regexp.MustCompile` at line 49. Use `processor.Scan`. Add two new
counted categories alongside the existing unencrypted/malformed/verification-failed
tallies:

- unterminated markers (error)
- the unmatched-`]` heuristic (warning; does not fail the command)

`check` now reports rows 1–4 of the evidence table instead of passing them.

### Step 4 — thread defects through the commands

Per the severity table. `encrypt`, `edit`, `check` return an error listing file, line, and
column. `decrypt`, `run`, `kms rotate` call `ui.Warn` and proceed.

Line/column requires an offset→line:col helper; put it in `pkg/processor` next to the
scanner since `check` and the commands both want it.

### Step 5 — guard `ExtractEnv` (only if plan 02 has not landed)

This plan makes multi-line plaintext creatable for the first time. `ExtractEnv`
(`pkg/processor/processor.go:341`) splits decrypted output on `\n`, so a multi-line value in
a `.env` would let secret content inject additional variables into the child environment —
see plan 02 for the full write-up. If plan 02 has not landed, add the interim guard:

```go
if strings.ContainsRune(val, '\n') {
    return nil, fmt.Errorf("%s: multi-line values are not supported by `run` yet", key)
}
```

Loud failure instead of injection. Plan 02 removes it. Skip this step entirely if the two
ship together.

### Step 6 — docs

- `README.md` "How it Works": the actual grammar — bracket balancing, `\[`/`\]`/`\\`
  escapes, multi-line plaintext allowed, ciphertext always single-line, the ambiguity
  limitation.
- `README.md` Cloud KMS notes: the "plaintexts are unbounded" line can stand once
  multi-line markers actually work.
- Record the grammar as an ADR — it is a durable decision with real alternatives (escape
  as a hard requirement rather than balancing; an alternate delimiter like `ENC[[…]]`; a
  length-prefixed form). Suggest `docs/adr/0001-enc-marker-grammar.md`. This repo has no
  `docs/adr/` yet, so adopting the convention is part of the decision.

---

## Tests

New, in `pkg/processor/marker_test.go` — table-driven over `ScanMarkers`:

**Ciphertext mode (regression — must be byte-identical to today)**
- `ENC[v1:<base64>]`, `ENC[v2:<base64>]`, both alone and mid-line
- two markers on one line
- marker inside a `#` comment → not returned
- `#` inside a marker value → not a comment
- `ENC[v1:abc` (no close) → `MalformedCiphertext`
- `ENC[v1:abc\n…]` → `MalformedCiphertext` (ciphertext may not span lines)

**Plaintext mode (new behavior)**
- `ENC[{"scopes":["a","b"]}]` → full JSON, brackets intact
- multi-line PEM → whole value, newlines preserved
- `ENC[ab\]cd]` → `ab]cd`
- `ENC[a\\b]` → `a\b`
- `ENC[]` → empty value, valid marker
- `ENC[oops` → `Unterminated`
- `# see ENC[` → no defect (comment)
- nested: `ENC[a[b[c]d]e]` → `a[b[c]d]e`

**Round-trip properties**
- `unescape(escape(s)) == s` for a fuzz corpus including `]`, `[`, `\`, `\n`, invalid UTF-8
- for any `s`: `Scan("ENC[" + escape(s) + "]")` yields exactly one marker with `Value == s`
  — this is the property that makes machine-written markers safe, so make it a real
  `testing/quick` or fuzz target, not three examples

**Integration, in `pkg/processor/processor_test.go`**
- every evidence-table row above, asserting the *fixed* outcome
- `EncryptContent` idempotency on an already-encrypted file (existing tests must pass
  unchanged — this is the compatibility gate)
- `edit`-shaped round-trip: encrypt → `DecryptContent(keepMarkers=true)` → `EncryptContent`
  → decrypt, for a value containing `]`, `[`, `\`, and newlines
- `RewrapContent` now skips a ciphertext in a comment

**Command level, in `cmd/cmd_test.go`**
- `check` fails on each of rows 1–4
- `encrypt` errors on unterminated in code, succeeds with it in a comment
- `run`/`decrypt` warn but succeed on the same input

---

## Compatibility

**Existing encrypted files: unaffected.** Ciphertext inners are `vN:` + standard base64,
an alphabet with no `[`, `]`, `\`, or newline, so ciphertext-mode scanning returns exactly
what the regex returns. The existing `processor_test.go` and `cmd_test.go` suites passing
unchanged is the gate for this claim — do not modify an existing assertion to make the
build green.

**Behavior changes, all deliberate:**

| Change | Who notices |
|---|---|
| Plaintext markers may span lines and contain balanced brackets | Anyone who was silently getting a no-op or a truncation |
| `\[`, `\]`, `\\` are now escapes inside plaintext markers | Anyone with a literal backslash-bracket in a plaintext marker — vanishingly rare, and a transient state |
| Unterminated `ENC[` in code errors on `encrypt`/`edit`/`check` | A file that is already broken |
| `kms rotate` no longer rewraps ciphertext in comments | Aligns with `decrypt`; changelog it |
| `check` reports more failures | The point |

**Not a wire-format change**, so no `v3:`, no migration, no `envisible.pub` change. A file
encrypted before this lands and a file encrypted after are indistinguishable.

---

## Done when

- [ ] `ScanMarkers` exists, is the only marker parser in the repo, and `encRegex` is gone
      (`grep -rn 'ENC\\\[' --include='*.go'` finds it only in `marker.go` and tests)
- [ ] Every evidence-table row produces a correct result or a loud failure
- [ ] Existing `pkg/processor` and `cmd` tests pass **without modification**
- [ ] Escape/unescape round-trip holds under fuzzing
- [ ] `check` fails the pre-commit hook on all four defect shapes
- [ ] `go vet ./...` clean, `gofmt` clean
- [ ] README grammar section written; ADR recorded
