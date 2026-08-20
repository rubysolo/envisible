# ADR 0001 — The `ENC[...]` marker grammar

- **Status:** accepted
- **Date:** 2026-08-20
- **Context plan:** [`docs/plans/01-marker-scanner.md`](../plans/01-marker-scanner.md)

This is the first ADR in the repo, so it also adopts the convention: durable
decisions with real alternatives get a numbered file under `docs/adr/`; the
day-to-day design work stays in `docs/plans/`.

## Context

Envisible's differentiator is a marker that can wrap *any substring of any text
file*. That marker used to be parsed by a single line-scoped regex,
`ENC\[(.*?)\]`, which had two load-bearing and wrong properties: `.*?` stops at
the first `]`, and Go's `.` does not match `\n` (the caller also chopped content
at newlines first). Neither failure was reported. The consequences were all
silent:

- `password: ENC[ab]cd]` encrypted `ab` and left `cd]` in the file as
  plaintext, while `check` — and the pre-commit hook — reported success.
- `sa: ENC[{"scopes":["a","b"]}]` had the `]` closing the JSON array eaten as
  the terminator and destroyed; the value that came back out was not the value
  that went in.
- A multi-line PEM key or an unterminated `ENC[` matched nothing at all, so the
  plaintext was written straight back to disk and `check` saw zero markers.

The last case also contradicted a documented promise — the Cloud KMS section
claimed "plaintexts are unbounded in size (PEM keys, certificates, etc.)",
which was true of the envelope and false of the parser.

So a grammar had to be chosen, written down, and implemented once for every
command. The hard constraints:

1. **The `v1:` / `v2:` wire formats are frozen.** Not one byte of any existing
   ciphertext may move, and scanning an already-encrypted file must produce
   exactly the previous result.
2. **No structured-format parsing.** The scanner stays text-level; YAML/JSON/
   TOML awareness would throw away substring granularity.
3. **Failures must be loud.** Truncation, corruption and no-ops all had to
   become either a correct result or a reported defect.

## Decision

A hand-written scanner (`pkg/processor/marker.go`) with two modes, chosen by
what follows `ENC[`:

- **Ciphertext mode**, entered when the body matches `^v\d+:`. The body runs to
  the first `]` and may not cross a newline. A versioned inner is a prefix plus
  standard base64 — an alphabet with no `[`, `]`, `\` or newline — so this is
  byte-for-byte what the old regex produced for every marker envisible has ever
  written. That equivalence is what satisfies constraint 1. Truncation before
  the `]` is a `MalformedCiphertext` defect.
- **Plaintext mode** for everything else: bracket-depth tracking (so balanced
  brackets need no escaping), the escapes `\[`, `\]`, `\\`, and
  backslash-newline. **The body ends at the first unescaped newline**; depth
  still positive there is an `Unterminated` defect. A value that genuinely
  contains newlines is written with a backslash before each one, a continuation
  in the shell tradition.

  The newline escape is a backslash before a *real* line break, deliberately
  not the two characters `\n`: a single-line JSON service-account key carries
  literal `\n` inside its `private_key` field, and reading those as line breaks
  would corrupt the exact payload this tool exists to protect.

Everything envisible *writes* is escaped (`escapeMarkerValue`), so a
machine-written marker never exceeds depth 1 and is unambiguous by
construction. Bracket balancing exists purely so a human pasting a JSON blob
does not have to escape anything.

Defects are returned, not raised: the write and validate paths (`encrypt`,
`edit`, `check`) turn them into errors with `file:line:col`, and the read paths
(`decrypt`, `run`, `kms rotate`) warn and continue, because a stray `ENC[` in a
config file must not take down a deploy.

Three refinements were added during implementation and are part of the decision:

- **A plaintext body may not cross a bare newline.** The first draft treated
  newlines as ordinary content so that a PEM could be pasted in raw. Adversarial
  review showed that this made a single forgotten `]` silently destructive:

  ```
  DB_PASSWORD=ENC[hunter2
  ALLOWED_HOST=example.com]
  ```

  scanned as one two-line value, so `encrypt` wrote a single marker, exited 0,
  and the `ALLOWED_HOST` line was gone — absorbed into the secret, with no
  defect reported. Requiring an explicit backslash before each newline makes the
  deliberate case explicit and the typo loud. The cost is that a raw pasted PEM
  is now a defect rather than a value; the answer for such payloads is
  `envisible set`, which never puts plaintext in the file at all.

- **No marker body may contain another unescaped `ENC[`.** Without this
  invariant a lone `ENC[` in a comment opens a body that runs on, absorbs the
  real `ENC[v1:...]` below it, and is then discarded as commented-out — leaving
  a file with zero markers, zero defects, and a secret nobody is going to
  encrypt. Anything envisible writes escapes `[`, so a machine-written value
  never trips it. Newline termination alone would not have covered this, since
  the swallow can happen within a single line.
- **A plaintext value that itself begins `vN:` is written with a leading
  escape** (`ENC[\v1:…]`), and the escape is only honored at offset 0. Without
  it the `edit` round-trip would write such a secret back to disk in the clear
  and report success. Symmetrically, a backslash inside a `vN:` body means the
  body is not base64 after all, so the scanner re-reads it in plaintext mode
  rather than stopping mid-value.

The one case the grammar cannot resolve is documented rather than fixed (see
Consequences).

## Alternatives considered

### 1. Escaping as a hard requirement, no bracket balancing

Every `[` and `]` inside a marker must be written `\[` / `\]`; the scanner
takes the first unescaped `]` and nothing else.

Simplest possible scanner, and it makes machine-written markers safe by exactly
the same argument the chosen design uses. It loses on the human path, which is
the path the marker syntax exists for: the common authoring move is pasting a
service-account JSON or a connection string into `ENC[…]`, and this rule
silently truncates every one of them unless the author hand-escapes a 4 KB
blob correctly. That is the *current* bug with a manual workaround bolted on,
and "you were supposed to escape it" is not a defense when the failure is
silent and the artifact gets committed.

Balancing costs one integer of state and makes the overwhelmingly common paste
Just Work; escaping is still there underneath for the cases balancing cannot
express. Rejected as strictly worse for humans and no better for machines.

### 2. An alternate delimiter, e.g. `ENC[[…]]`

Give plaintext its own delimiter pair so it cannot collide with a single `]`.

This does not actually remove the ambiguity, it relocates it: a value
containing `]]` has the identical problem, and JSON with a nested array
(`{"a":[["x"]]}`) contains `]]` routinely. It also breaks constraint 1 the
moment the same delimiter is used for ciphertext, or forces two grammars
(`ENC[` for ciphertext, `ENC[[` for plaintext) that every command, the
pre-commit hook, every existing file, the README, and the agent skill would
have to learn. Every marker envisible has ever written would need a migration,
for a property that bracket balancing plus an escape already provides.
Rejected.

### 3. A length-prefixed form, e.g. `ENC[12:hunter2xxxxx]`

Put the byte count in front of the body; the scanner reads exactly that many
bytes and needs no delimiter reasoning at all.

Unambiguous for any byte sequence, including `]` and newlines — the strongest
alternative on correctness. It fails on the *human authoring* requirement in a
way the others do not: nobody can hand-write or hand-edit a length prefix
correctly, so every plaintext marker would have to be produced by a tool, and
a stale count after a one-character edit is a new silent-corruption class of
its own. It also collides with the frozen wire format (`ENC[12:` and `ENC[v1:`
would have to be told apart, and a length prefix in front of the *ciphertext*
would be a v3 format), and it makes diffs worse: changing a secret's length
changes a second thing on the line.

The right place for machine-only precision is a machine-only path, and that is
what `envisible set` (plan 05) provides — the plaintext never enters the file's
grammar at all. Given that escape hatch exists, paying for length prefixes in
the hand-authored grammar buys nothing. Rejected.

## Consequences

- One scanner, `processor.Scan`, is used by `encrypt`, `decrypt`, `check`,
  `edit`, `run` and `kms rotate`. `check` predicts what `encrypt` will do by
  construction rather than by keeping a second regex in sync.
- Multi-line plaintext became creatable for the first time — via explicit
  backslash continuations, or via `envisible set` — which is why `ExtractEnv`
  had to be rewritten to parse structure before decrypting (plan 02).
  Otherwise a multi-line secret could inject variables into a child environment.
- Comment handling is resolved in a fixed order — markers over the whole
  content, then comment regions against those spans, then filter — which
  removes the old per-line regex and gives `kms rotate` the comment skipping it
  was silently missing.
- **The one irreducible ambiguity is documented, not fixed.** In
  `password: ENC[ab]cd]` the secret may be `ab` or `ab]cd`; depth legitimately
  reaches zero at the first `]`. Envisible reads `ab` (unchanged from before)
  and emits a heuristic warning suggesting `\]`. It warns; it never fails. This
  is now the *only* ambiguity left: the multi-line form of the same problem was
  removed outright by requiring a backslash before a newline.
- Behavior changes for existing projects: an unterminated `ENC[` in a
  non-comment position now fails `encrypt` / `edit` / `check` (that file was
  already silently broken), `\[` / `\]` / `\\` / backslash-newline are now
  escapes inside plaintext markers, a plaintext marker written raw across lines
  is now a defect rather than a value, and `kms rotate` no longer re-wraps
  ciphertext parked in comments.
- Not a wire-format change: no `v3:`, no migration, no `envisible.pub` change.
  A file encrypted before this landed and one encrypted after are
  indistinguishable.
