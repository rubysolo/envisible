# Plan 02 — Byte-exact values in `envisible run`

**Kind:** correctness fix (value mangling, plus one latent injection path)
**Status:** proposed
**Depends on:** nothing to ship; **must land with or before** plan 01's multi-line support
becomes usable in a `.env` (see "Interaction with plan 01")

---

## Problem

`ExtractEnv` (`pkg/processor/processor.go:341`) decrypts the whole file to text and *then*
parses the result as dotenv:

```go
decrypted, err := DecryptContent(ctx, content, dec, false)
...
for _, line := range strings.Split(string(decrypted), "\n") {
    line = strings.TrimSpace(line)
    if line == "" || strings.HasPrefix(line, "#") { continue }
    parts := strings.SplitN(line, "=", 2)
    if len(parts) == 2 {
        key := strings.TrimSpace(parts[0])
        val := strings.TrimSpace(parts[1])
        val = strings.Trim(val, `"'`)
        env[key] = val
    }
}
```

Decrypt-then-parse means **the plaintext of a secret is fed back into the parser**. The
value the child process receives is therefore not the value that was encrypted:

| stored plaintext | `run` delivers | cause |
|---|---|---|
| `sk_live_abc ` (trailing space) | `sk_live_abc` | `TrimSpace(val)` |
| `"quoted"` | `quoted` | `Trim(val, "\"'")` |
| `pa'ss` → written as `pa'ss'` | `pa'ss` | `Trim` strips from both ends, any count |
| anything, in `export FOO=ENC[…]` | key is `export FOO` | `SplitN` on `=` without stripping `export ` |
| anything, in `FOO=ENC[…] # note` | value gains ` # note` | `DecryptContent` preserves comment text; `ExtractEnv` does not strip it |
| a multi-line value | first line only, **plus** every subsequent `k=v` line becomes its own env var | `strings.Split(…, "\n")` runs over plaintext |

The last row is the one with teeth. A secret whose plaintext is

```
hunter2
PATH=/tmp/evil
```

yields `PASSWORD=hunter2` **and** `PATH=/tmp/evil` in the child environment. Secret content
controls the environment of the process it is handed to. That is an injection path, not
merely a formatting bug.

It is currently unreachable — the marker grammar (plan 01) makes multi-line plaintext
impossible to create — but it becomes reachable the moment plan 01 or plan 05 lands. This
plan closes it before the door opens.

The quoting behavior matters more once secrets start arriving from an external store. A
store worth using is byte-exact about what it hands back, right down to whether a trailing
newline is part of the credential. Feeding a byte-exact value to a consumer that silently
trims whitespace and quotes reintroduces exactly the bug the store was avoiding: a
credential that fails *at the point of use*, long after the step that broke it reported
success. `Authorization: Bearer sk-…` with a stray trim is a 401 three layers away from
the cause.

---

## Goals

1. The value delivered to the child process is the exact plaintext that was encrypted —
   every byte, including newlines, quotes, `=`, and whitespace.
2. Secret content can never introduce, remove, or alter an environment variable other than
   the one it is assigned to.
3. Dotenv quoting is applied to *file text*, never to decrypted secret bytes.
4. `export FOO=…` and inline `# comments` parse correctly.

### Non-goals

- Full dotenv compatibility: no `$VAR` interpolation, no command substitution, no
  multi-line `"""` literals in the file. envisible files are not shell.
- Changing `run`'s child-process or signal behavior.

---

## Design

Invert the order: **parse structure first, decrypt values second.**

```go
func ExtractEnv(ctx context.Context, content []byte, dec Decryptor) (map[string]string, error)
```

Per line of the *original* (still-encrypted) content:

1. Strip the inline comment using the same marker-aware comment logic the rewriters use
   (plan 01's `CommentRegions`; until then, the existing `splitLineComment`).
2. Skip blank and comment-only lines.
3. Strip an optional leading `export ` (with trailing whitespace).
4. Split at the **first** `=`. Left side trimmed and validated as an env var name
   (`[A-Za-z_][A-Za-z0-9_]*`); a line whose left side is not a valid name is skipped with a
   warning rather than silently dropped, which is what happens today.
5. Classify the right side:
   - **Exactly one marker**, optionally surrounded by whitespace and one matching pair of
     quotes → decrypt it and use the resulting bytes **verbatim**. No trimming, no unquoting,
     no re-parsing. This is the path essentially every value takes.
   - **Otherwise** (literal text, or text with an embedded marker) → apply dotenv quoting
     rules to the *text*, then decrypt any markers inside it and substitute. This preserves
     the substring case — `DATABASE_URL=postgres://u:ENC[…]@host/db` — which is envisible's
     whole reason for existing.

Quoting rules for the literal path, stated precisely because the current behavior is
accidental:

- Trim leading and trailing whitespace from the raw text.
- If the result starts and ends with the same quote character (`"` or `'`) and is at least
  two characters, remove **exactly that one pair**. Never more.
- Otherwise use the trimmed text as-is.

Note the asymmetry, and that it is intentional: quoting is a property of how a value is
written *in the file*, so it applies to file text only. A decrypted secret is opaque bytes
and gets no interpretation whatsoever.

### Interaction with plan 01

Plan 01 makes multi-line plaintext creatable. If 01 ships first, add a temporary guard to
the current `ExtractEnv`:

```go
if strings.ContainsRune(val, '\n') {
    return nil, fmt.Errorf("%s: multi-line values are not supported by `run` yet", key)
}
```

Loud failure instead of environment injection, removed by this plan. Cheap insurance if the
two land separately; unnecessary if they ship together.

---

## Implementation

1. **`pkg/processor/env.go` (new)** — move `ExtractEnv` out of `processor.go` and rewrite
   it as described. It is now a parser with real structure and deserves its own file and
   test file.
2. **Line splitting** must handle `\r\n`. The current code does not, so a CRLF `.env`
   leaves `\r` on every value; `TrimSpace` currently hides it, and the new no-trim path
   would expose it. Strip a trailing `\r` at the line level, before value handling.
3. **`cmd/run.go`** — no logic change, but stop assuming values are single-line in any
   logging. Confirm `ui.Info` never prints a value (it currently prints only the file path;
   keep it that way).
4. **`cmd/run.go:56`** — `fmt.Sprintf("%s=%s", k, v)` is correct for multi-line values;
   `exec` passes the bytes through. No change, but assert it in a test rather than assuming.

---

## Tests

New `pkg/processor/env_test.go`:

**Fidelity** — for each, encrypt the value, build a `.env`, `ExtractEnv`, assert byte equality:
- trailing space, leading space, both
- value that is `"quoted"` including the quotes
- value containing `=`, `#`, `'`, `"`, backslashes
- multi-line value (PEM-shaped) — including that no extra keys appear in the map
- empty value
- value that is not valid UTF-8

**Injection** — a secret whose plaintext is `hunter2\nPATH=/tmp/evil`:
- `PASSWORD` is the full two-line string
- `PATH` is **not** in the returned map

**Structure**
- `export FOO=ENC[…]` → key `FOO`
- `FOO=ENC[…] # note` → value has no ` # note`
- `# FOO=ENC[…]` → not present
- `FOO=bar` (plain literal, no marker) → `bar`
- `FOO="bar"` → `bar`; `FOO="'bar'"` → `'bar'` (**changed** from today's `bar`)
- `DATABASE_URL=postgres://u:ENC[…]@h/db` → substring substituted, rest intact
- `not-a-valid-name=x` → skipped, warning emitted
- CRLF file → no `\r` anywhere in any value
- blank lines, whitespace-only lines

**Command level** (`cmd/cmd_test.go`)
- `envisible run -f <file> -- printenv KEY` reproduces a multi-line value exactly
- the injection case does not set `PATH`

---

## Compatibility

`FOO="'bar'"` now yields `'bar'` where it used to yield `bar`, and a value with meaningful
surrounding whitespace or quotes is no longer silently stripped. That is the fix, but it
*is* a behavior change: a project that accidentally depended on the sloppy trim will see a
different value. Two consequences for the release:

- Ship in a minor version with a changelog entry titled around "values are now delivered
  byte-exactly", not buried under "bug fixes".
- Mention the `export ` and inline-comment fixes in the same entry — a project relying on
  the current broken `export FOO` key name will see that key disappear.

No wire-format change. No re-encryption. Existing files are read more accurately, not
differently on disk.

---

## Done when

- [ ] Every fidelity case round-trips byte-exactly through `encrypt` → `run`
- [ ] The injection test passes: secret content cannot add an env var
- [ ] `export ` and inline comments handled
- [ ] CRLF files produce clean values
- [ ] The temporary multi-line guard (if plan 01 landed first) is removed
- [ ] Changelog entry describes the behavior change explicitly
