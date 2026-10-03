# Plan 10 — Test the CLI's documented contracts, not just its code paths

**Kind:** test hardening — test-only, plus two small output-stream fixes it will surface
**Status:** proposed
**Depends on:** 11 is easier after this lands (both touch `cmd/cmd_test.go`; see "Coupling")

---

## Problem

`cmd` is at 86% line coverage. The audit started from a case where that number hid a
complete gap: the `ENVISIBLE_KEY` resolver had full line coverage and no test asserting its
behavior, because every command test executed it incidentally. (Fixed in `5de265e`.) The
same pattern recurs across the rest of the CLI's documented surface.

### Evidence

Single-change mutations, `go test ./...`, all green — every row re-verified in the main
session:

| # | Mutation | Contract broken |
|---|----------|-----------------|
| C1 | `cmd/decrypt.go:55` — `cmd.OutOrStdout()` → `cmd.ErrOrStderr()` | decrypted content goes to stdout (`AGENTS.md`, README) |
| C2 | `cmd/keygen.go:48` — same change for `--print-key` | the printed key goes to stdout, so it can be piped into a store |
| C3 | `cmd/root.go:72` — `envOrDefault("ENVISIBLE_FILE", ".env")` → `".env"` | `--file` help: *default .env, or $ENVISIBLE_FILE* |
| C4 | `cmd/root.go:69` — `envOrDefault("ENVISIBLE_PUB_PATH", ...)` → `"envisible.pub"` | README: *`--pub`, then `ENVISIBLE_PUB_PATH`, then `envisible.pub`* |
| C5 | `cmd/root.go:68` — `if !flagChanged(cmd, "pub")` → `if true` | `--pub` / `-p` silently ignored |
| C6 | `cmd/check.go:84` — delete `verificationFailedCount++` | `check --verify` reports corrupt values |
| C7 | `cmd/git.go:116` — `if ! envisible check` → `if envisible check` in the hook script | the pre-commit hook blocks unencrypted secrets |

Why each survives:

- **C1/C2:** `resetRoot` (`cmd_test.go:21`) calls both `rootCmd.SetOut(out)` and
  `rootCmd.SetErr(out)`. Every assertion reads one merged buffer, so no test *can* tell the
  streams apart.
- **C3:** `TestEnvisibleFileEnvVar` does `t.Logf("run failed: %v", err); return` when `run`
  errors — which is exactly what happens when the variable is ignored (no `.env` exists).
  Both env-file tests also assign `filePath = ...` by hand, which `PersistentPreRunE`
  overwrites on every `Execute`, so the assignment is dead code that makes them look like
  coverage.
- **C4/C5:** no test sets `ENVISIBLE_PUB_PATH` or passes `-p`/`--pub`. (`TestMain` now
  unsets the variable, so the developer's shell can't accidentally exercise it either.)
- **C6:** only the passing case of `--verify` runs (`TestSetThenCheckPasses`).
- **C7:** `TestGitIntegration` only `stat`s `.git/hooks/pre-commit`.

---

## Goals

1. Stdout and stderr are captured separately in every command test, and the stream split is
   asserted for each command that produces payload.
2. Every documented flag and env var has a test that fails when it is ignored.
3. `check --verify`, `decrypt --textconv` and the pre-commit hook are tested on their
   failure paths, not just their happy ones.

---

## Design

### 1. Separate the streams in the harness

Change `resetRoot(out io.Writer)` to set **only** `SetOut`, and add a sibling that returns
both buffers:

```go
// runRoot executes args against a freshly reset rootCmd and returns what the
// command wrote to its stdout and stderr writers separately.
func runRoot(t *testing.T, args ...string) (stdout, stderr string, err error)
```

`ui.*` writes to `os.Stderr` rather than to cobra's writer, so `runRoot` should also swap
`os.Stderr` for a pipe (reuse `captureStdStreams`). Migrate call sites gradually; a test that
only cares about stdout keeps working once `resetRoot` stops merging.

Then add a stream-contract table test: for `decrypt`, `decrypt --strip`, `encrypt -`,
`keygen --print-key` (non-TTY stub), `set --dry-run` and `run -- printf`, assert the payload
is on stdout and absent from stderr; for each, also run with `-q` and assert stderr is empty.

**Expect this to find two real violations,** which this plan fixes in production code:

- `cmd/version.go:19` uses `fmt.Printf` — it bypasses cobra's writer entirely, so it is
  untestable. Use `fmt.Fprintf(cmd.OutOrStdout(), ...)`. (Version output on stdout is
  correct; it *is* the payload.)
- `cmd/git.go:35` prints `"Configuring git diff driver..."` to **stdout**. That is a banner;
  move it to `ui.Info` so it goes to stderr and respects `-q`.

### 2. Path resolution, mirroring `TestKeySourcePrecedence`

`TestKeySourcePrecedence` (`cmd/root_test.go`) is the model: every source that should lose
holds a *wrong* value, so success proves which one won.

- **Env file:** `ENVISIBLE_FILE=custom.env` with no `.env` present → `decrypt --strip` (no
  positional arg) prints the secret; `-f other.env` beats `ENVISIBLE_FILE`; `run -- printf`
  sees the value; `set KEY -` writes to `custom.env`. Use `t.Fatalf` on any error. Delete the
  hand assignments to `filePath` in the existing tests (`cmd_test.go:612, 616, 767, 770`).
- **Public key:** keypair under `keys/x.pub`, no `envisible.pub` in cwd. `encrypt -` succeeds
  with `ENVISIBLE_PUB_PATH=keys/x.pub`, with `-p keys/x.pub`, with `--pub keys/x.pub`, and
  with `-p` beating a `ENVISIBLE_PUB_PATH` that points at a different keypair. Decrypting the
  output with the matching private key proves which public key was used.

### 3. Failure paths

- **`check --verify`:** a file with one marker sealed to a different key → non-zero exit,
  error text `invalid/corrupt`, and the success line absent.
- **`decrypt --textconv`** when decryption fails (key present but wrong): must print the raw
  content and exit 0, so `git diff` degrades instead of breaking. Today only the
  "no key loaded" branch (`decrypt.go:33`) is tested; the decrypt-failure branch
  (`decrypt.go:43-46`) has zero coverage.
- **Pre-commit hook — execute it.** After `git install-hook` in a temp repo, put the test
  binary on `PATH` (build it once with `go build -o $TMP/envisible .` in a `sync.Once`, or
  skip with a clear message if `go` is unavailable), stage a file with `ENC[plaintext]` and
  run `.git/hooks/pre-commit` → exit 1 and `Commit rejected.`; encrypt it, re-stage, run
  again → exit 0. Also: a second `install-hook` refuses with *already exists*
  (`git.go:135`).
- **`git setup`:** after running it, read back `git config diff.envisible.textconv` and
  assert the exact value `envisible decrypt --textconv`.

### 4. Isolate git

`TestGitIntegration` runs real `git`, which reads the developer's global config: an
`init.templateDir` that installs its own pre-commit hook makes `install-hook` fail. Set
`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1` and `GIT_TEMPLATE_DIR=` (empty) via
`t.Setenv` in every git-touching test.

---

## Open question — `check` prints plaintext

`cmd/check.go:66` warns `Unencrypted value found: ENC[hunter2]` — the full plaintext, on
stderr. `AGENTS.md` and the README (`set`: *"No value ever reaches stdout or stderr,
including in error messages"*) point one way; the purpose of `check` — telling you *which*
marker is unencrypted — points the other. **Decide before implementing**, then pin the
decision with a test either way. A middle option: print the file, line and column, plus the
first few characters and the length (`ENC[hun… (7 chars)]`), which still locates the
marker. This plan does not choose.

---

## Coupling

Plan 11 cleans up `cmd_test.go` broadly. Land this plan first: changing `resetRoot` to stop
merging streams is the structural change, and 11's cleanups are easier on top of the new
`runRoot` helper.

---

## Done when

- [ ] C1–C7 each fail at least one test when applied alone.
- [ ] No test helper sends stdout and stderr to the same buffer.
- [ ] `version` and `git setup` respect the stream contract.
- [ ] The pre-commit hook is executed by a test, both rejecting and accepting.
- [ ] The `check` plaintext question is decided and pinned.
