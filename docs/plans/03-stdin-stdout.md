# Plan 03 — `-` for stdin on `encrypt`, `decrypt`, and `check`

**Kind:** feature (small)
**Status:** proposed
**Depends on:** nothing
**Blocks:** plan 05 (shares the stdin intake helper)

---

## Problem

`encrypt` reads only from a file:

```go
// cmd/encrypt.go:29
content, err := os.ReadFile(targetFile)
```

`decrypt` (`cmd/decrypt.go:26`) and `check` (`cmd/check.go:38`) do the same. Output is
already stdout-by-default with `-i` for in-place, so the write half of the pipe works —
it is only the read half that is missing.

That asymmetry has a specific cost. To encrypt a value that is currently held somewhere
other than a file — a secret manager, a CI variable, an OS keychain — you must first *write the
plaintext to disk* in a file containing `KEY=ENC[<plaintext>]`, then run `encrypt -i` over
it. For a tool whose purpose is keeping plaintext secrets off disk, making a plaintext file
a mandatory intermediate step is backwards, and the window is not theoretical: the file
exists on disk, with default permissions, until the encrypt succeeds, and it survives an
interrupted run.

`envisible decrypt` already documents the pipe idiom in the README ("command substitution
and pipes just work"). Reading from a pipe should work the same way.

---

## Goals

1. `-` as the file argument means stdin, for `encrypt`, `decrypt`, and `check`.
2. Plaintext can go from a producing process into ciphertext on stdout without ever
   touching the filesystem.
3. Failure modes are loud: no silently hanging on an empty TTY, no `-i` with a pipe.

### Non-goals

- `edit -` (there is nothing to open an editor on) and `run -f -` (conflicts with the child
  process's stdin) — both explicitly rejected with a clear message rather than half-working.
- Changing the default output stream behavior. Already correct.

---

## Design

One shared helper, since three commands need identical semantics:

```go
// cmd/input.go
//
// readTarget returns the bytes to operate on and whether they came from stdin.
// A target of "-" reads stdin to EOF; anything else is a file path.
func readTarget(cmd *cobra.Command, target string) (content []byte, isStdin bool, err error)
```

Rules:

- `target == "-"` → read `cmd.InOrStdin()` to EOF.
- **Refuse to read from a TTY.** If stdin is a character device, error immediately with
  `refusing to read from a terminal; pipe input or pass a file path`. Without this, `envisible
  encrypt -` at a prompt looks like a hang, and the user's next move is Ctrl-C or,
  worse, typing a secret into a terminal that records it in scrollback. Refusing a TTY on
  secret intake is standard practice for this reason.
- **`-i`/`--inplace` with `-` is an error**: `--inplace has no meaning when reading stdin`.
  Silently ignoring the flag would let a script think it wrote a file it did not write.
- Empty stdin is *not* an error here (an empty file is a legitimate thing to encrypt), but
  see plan 05, where it is — the difference is that `set` is a mutation and a dead upstream
  in a pipe must not be mistaken for success.
- `-f -` works identically to a positional `-`, since `filePath` feeds the same variable.

`check`'s messages currently interpolate `targetFile` ("found %d unencrypted values in
%s"). When reading stdin, render the target as `<stdin>`.

The `--textconv` path in `decrypt` is unaffected: git always passes a real path to a diff
driver.

---

## Implementation

1. **`cmd/input.go` (new)** — `readTarget` plus the TTY check
   (`os.Stdin.Stat()` and `mode & os.ModeCharDevice != 0`).
2. **`cmd/encrypt.go`** — replace `os.ReadFile` with `readTarget`; reject `-i` + stdin.
3. **`cmd/decrypt.go`** — same.
4. **`cmd/check.go`** — same, plus `<stdin>` in messages.
5. **`cmd/edit.go`, `cmd/run.go`** — explicit rejection of `-` with a message pointing at
   the right command.
6. **`README.md`** — a short "Reading from stdin" subsection under the output-streams note,
   with the pipe example.

---

## Tests

`cmd/cmd_test.go` (cobra commands are already exercised there with `SetIn`/`SetOut`):

- `encrypt -` over a piped buffer → ciphertext on stdout, nothing written to disk
- `decrypt -` round-trips it back
- `check -` reports correctly and names `<stdin>`
- `encrypt -i -` → error mentioning `--inplace`
- `-f -` behaves the same as positional `-`
- `edit -` and `run -f -` → clear rejection errors
- TTY refusal: inject a fake stat or gate the check behind a seam so it is testable

---

## Compatibility

Purely additive. `-` is not currently a valid path in practice, and no existing invocation
changes behavior.

One edge case worth a test: a file literally named `-`. It becomes unreachable by name.
That is the universal Unix convention, and `./-` still works.

---

## Done when

- [ ] `printf 'K=ENC[v]' | envisible encrypt -` emits ciphertext on stdout
- [ ] The full pipe works with no plaintext file at any point
- [ ] `-i` with stdin errors; a TTY errors
- [ ] `edit`/`run` reject `-` with a useful message
- [ ] README documents it
