# Plan 05 — `envisible set`: write a secret into a file without the plaintext ever being in it

**Kind:** feature
**Status:** proposed
**Depends on:** plan 03 (shares the stdin intake helper and its TTY guard). Also pairs with
plan 02: `set` can produce multi-line values, which `ExtractEnv` currently mishandles — ship
02 alongside, or carry plan 01's interim guard.

---

## Problem

Every route into an envisible file goes through a plaintext `ENC[<value>]` marker:

- `envisible encrypt` — you write the plaintext into the file, then encrypt in place.
- `envisible edit` — the whole file is decrypted to a temp file, you edit, it re-encrypts.

Both require the plaintext to exist, in a file, on disk, before it can be protected. Three
consequences:

1. **A plaintext window.** The file (or `os.CreateTemp`'s output in `edit`) holds the secret
   in the clear until the command completes. An interrupted `encrypt -i` leaves it there.
   `edit` writes the entire decrypted file to `/tmp` for the duration of an editor session.
2. **It defeats a secret manager.** If a credential lives somewhere safe, the only way to
   get it into an envisible file today is to take it *out* of safety, write it to disk in
   the clear, and then re-protect it. That is the exact motion the manager exists to prevent.
3. **It exposes the marker grammar to arbitrary bytes.** A secret containing `]` is
   ambiguous even after plan 01 fixes the parser, because a bare `]` inside a plaintext
   marker cannot be distinguished from the terminator. Plan 01 documents an escape for this;
   requiring a human to correctly escape a 4 KB blob they pasted is not a real answer.

The third point is why this plan and plan 01 are complementary rather than redundant. Plan
01 makes the plaintext grammar as good as a plaintext grammar can be. This plan lets you
skip it.

---

## Goals

1. Encrypt a value into a file **without the plaintext ever appearing in that file**, on
   disk, or in argv.
2. Work with `envisible.pub` alone — no private key, no KMS decrypt permission. A developer
   with no decrypt capability can still add and rotate secrets.
3. Upsert a whole set of key/values in one invocation, so a caller holding many secrets
   pays whatever it costs to unlock them exactly once.
4. Preserve the file's existing layout — comments, ordering, unrelated lines, trailing
   newline.

### Non-goals

- **YAML/JSON/TOML targets.** Addressing "the password inside this connection string in
  this nested YAML key" needs a path expression and a structure-preserving writer. That is
  a much bigger feature, and `edit` remains the answer for it. v1 is dotenv-shaped files
  only, and the command says so when pointed at something else.
- Reading, printing, or verifying existing values (that needs decrypt capability).
- Deleting keys — `edit` or a text editor.

---

## Design

### Surface

```
envisible set [file] KEY -                 # one value from stdin
envisible set [file] --from-json -         # a JSON object of KEY→value from stdin
envisible set [file] --from-env -          # dotenv-shaped input from stdin
  --dry-run        report what would change; write nothing
  --if-changed     skip keys whose current value already decrypts to the new one
                   (requires decrypt capability)
```

`file` defaults to the global `-f` / `.env`, matching every other command.

**There is deliberately no `--value` flag.** Anything passed as an argument is visible in
`ps`, in shell history, and in every process listing on the machine. stdin only. Any secret
store worth piping from enforces the same rule on its own read path, and the two sides
compose precisely because they agree on it.

### Behavior

For each incoming `KEY` → plaintext:

1. Validate `KEY` against `[A-Za-z_][A-Za-z0-9_]*`. Reject early — a bad key would write a
   line that no consumer can read back.
2. Encrypt the plaintext with the configured encryptor (`loadEncryptor`, which already
   picks NaCl v1 or the KMS envelope v2 from `envisible.pub`).
3. Splice `KEY=ENC[<inner>]` into the file:
   - **Key exists** → replace only the value portion of that line, leaving the key, any
     `export ` prefix, indentation, and any trailing `# comment` exactly as they were.
   - **Key absent** → append at end of file, preserving/adding a single trailing newline.
4. Write atomically: temp file in the same directory, `fsync`, `rename`. Preserve the
   existing mode; use 0644 for a new file, consistent with `encrypt -i`.

The plaintext exists only in memory, and only between the read and the `EncryptValue` call.
The bytes written to disk are already ciphertext. **Marker escaping is not involved at any
point** — the value goes straight to the encryptor and never passes through the plaintext
grammar. That is the property that makes this the right path for machine-sourced secrets.

### Guards

- **Empty stdin is an error** (exit non-zero, nothing written). A command that dies upstream
  in a pipe closes it with no bytes, which is indistinguishable from success at this end,
  and a shell pipeline reports the *last* command's status. Without this guard,
  `secret-source | envisible set .env KEY -` would cheerfully replace a live credential
  with an empty one and report success. Add `--allow-empty` for the rare legitimate case.
- **TTY refusal** on stdin, from plan 03.
- **Trailing newline.** Trim exactly one trailing `\n` by default; `--raw` keeps the bytes
  verbatim. Editors, heredocs, and `echo` all add one, and a credential stored with a stray
  newline fails at the point of use, far from the command that broke it
  (`Authorization: Bearer sk-…\n` is a 401). Trimming exactly one means a multi-line secret
  keeps its shape. Match whatever the upstream store does here, so a value does not change
  shape as it crosses the boundary.
- **No value ever reaches stdout or stderr,** including in error messages. Report keys, never
  values: `set STRIPE_KEY (updated), AWS_REGION (added)`.

### The re-encryption churn problem

Encryption is randomized — a fresh ephemeral keypair and nonce per value in v1, a fresh data
key and nonce in v2. So **re-running `set` with an unchanged value produces a different
ciphertext**, and the file diffs every time.

That matters more than it sounds. Once the same credential lives in both a local store and
an envisible file, the natural instinct is a periodic "sync everything" — which then rewrites
every marker on every run, producing a diff that reviewers learn to skim past. A noisy diff
is a security regression in a tool whose central claim is that secret changes show up in
code review.

So, deliberately:

- `set` writes **only the keys it was given**. There is no "sync the whole file" mode.
- `--from-json` writes every key in the payload, and therefore churns every one of them. The
  help text says so.
- `--if-changed` decrypts the current value and skips keys that already match. It needs
  decrypt capability, so it is opt-in rather than default — a developer with only
  `envisible.pub` cannot use it, and that is the common case this command is built for.
- `--dry-run` reports added/updated/unchanged **by key name**, and works without decrypt
  capability for added-vs-updated (it needs `--if-changed` to distinguish unchanged).

The honest framing for the docs: `set` is for adding a key and for rotating a key. It is not
a sync primitive, and building a sync loop on top of it will produce diffs nobody reads.

### Two sources of truth

This command creates a durable consequence worth stating in the README rather than
discovering later: once a credential exists in both a local store and a committed envisible
file, **rotation has to touch both**, and nothing detects the drift automatically. Drift
detection requires decrypt capability, which by design the developer machine may not have.

The realistic placement is CI: a job that holds decrypt permission runs `envisible check
--verify` and, if the project wants it, compares against whatever the canonical source is.
`set` should not pretend to solve this on the laptop.

---

## Implementation

1. **`pkg/processor/dotenv.go` (new)** — a layout-preserving dotenv editor.
   `Upsert(content []byte, key, rawValue string) (out []byte, action Action)` where `Action`
   is `Added`/`Updated`. Parses lines only enough to locate `[export ]KEY=`, and rewrites the
   value span. Shares line/comment handling with plan 02's parser — same grammar, one
   implementation, so `set` writes what `run` reads.
2. **`cmd/set.go` (new)** — flag wiring, `readTarget` from plan 03, JSON/dotenv payload
   parsing, the guards above, atomic write, per-key reporting to stderr.
3. **Format detection** — refuse a target that does not look dotenv-shaped (e.g. the first
   non-comment line is `---`, or the file parses as JSON) with a message pointing at `edit`.
   Better a clear rejection than a `.env` line appended to the bottom of a YAML file.
4. **`README.md`** — a "Setting a value without writing plaintext" section, the churn note,
   and a piped-from-a-secret-store one-liner as the motivating example.

---

## Tests

`cmd/set_test.go` and `pkg/processor/dotenv_test.go`:

**Core**
- new key appended to an existing file; existing keys and comments untouched
- existing key updated in place; its inline comment, `export ` prefix, and indentation survive
- file does not exist → created with 0644 and one trailing newline
- existing file mode preserved
- `--from-json -` with several keys → all written, one pass
- `--from-env -` with dotenv input
- v2/KMS mode → `v2:` markers, and no KMS call at write time (assert with a stub wrapper —
  "no network at encrypt time" is a documented property worth a regression test)
- **only `envisible.pub` present** (no `envisible.key`) → succeeds. This is the headline
  capability; make it an explicit test.

**Value fidelity** — for each, `set` then decrypt and compare bytes:
- value containing `]`, `[`, `\` → round-trips exactly, and the file contains no escape
  sequences because the plaintext never entered a marker
- multi-line value (PEM) → exact
- value containing `=`, `#`, quotes
- trailing newline trimmed once; `--raw` keeps it
- non-UTF-8 bytes

**Guards**
- empty stdin → non-zero exit, **file byte-identical to before** (assert the file, not just
  the exit code — the failure mode being guarded against is a destructive write)
- `--allow-empty` → writes
- TTY stdin → refused
- invalid key name → rejected before any write
- YAML target → rejected with a pointer to `edit`

**Behavioral**
- `--dry-run` writes nothing and reports the right actions
- `--if-changed` with an unchanged value → file byte-identical
- `--if-changed` without decrypt capability → clear error, not a silent full rewrite
- no test output, on any path, contains a plaintext value

**Cross-command**
- `set` then `run` returns the exact value (ties this to plan 02)
- `set` then `check` passes
- `set` twice with the same value → different ciphertext both times (documents the churn)

---

## Compatibility

New command; nothing existing changes. Output is an ordinary envisible file — `encrypt`,
`decrypt`, `edit`, `check`, `run`, and `kms rotate` all treat it identically to a
hand-authored one, because it is.

---

## Done when

- [ ] `printf '%s' "$V" | envisible set .env KEY -` writes ciphertext, with the plaintext
      never on disk and never in argv
- [ ] Works with `envisible.pub` alone
- [ ] Layout, comments, ordering, and file mode preserved
- [ ] Empty stdin leaves the file byte-identical
- [ ] Values containing `]`, newlines, and non-UTF-8 bytes round-trip exactly
- [ ] `--dry-run` and `--if-changed` behave as specified
- [ ] The churn behavior and the two-sources-of-truth consequence are documented, not
      discovered
