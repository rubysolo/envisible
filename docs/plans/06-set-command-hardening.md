# Plan 06 — Bring `envisible set` in line with the rest of the CLI

**Kind:** correctness + consistency follow-up
**Status:** proposed
**Depends on:** plans 01–05 (all landed on `feat/implement-plans`)

---

## Problem

`envisible set` (plan 05) was implemented last, by an agent working from its own plan, and it
never had to reconcile with the conventions plans 01–03 had established in the same
codebase. A cross-plan coherence review found six places where it diverges. Two of them can
lose data or block a commit; the rest are papercuts that make the CLI feel like two tools.

The structural point worth keeping in mind while fixing these: **`set` is the command built
for the person with the least capability** — a developer holding only `envisible.pub`, who
cannot decrypt and therefore cannot check their own work. Every divergence below hits that
persona hardest, because they have no way to notice it.

Every finding was reproduced against a binary built from `a8ec4b6`. The commands and their
actual output are given so nobody has to take this document on faith.

### 1. `set` opted out of the defect-severity contract (major)

ADR 0001 and the README both state the policy: `encrypt` / `edit` / `check` error on a
scanner defect and write nothing; `decrypt` / `run` / `kms rotate` warn and continue. `set`
does neither. `cmd/set.go` reaches `pkg/processor/dotenv.go` through `Upsert`,
`LookupValue` and `LooksLikeDotenv`, each of which builds a parser and discards the defect
slice (`p, _ := newEnvParser(...)` at `dotenv.go:161`, `:225`, `:271`). It never calls
`defectError` or `warnAmbiguousMarkers`.

```console
$ printf 'A=ENC[oops\nB=1\n' > d.env
$ envisible check   d.env   ; echo $?     # 1, writes nothing
$ envisible encrypt -i d.env ; echo $?    # 1, writes nothing
$ printf v | envisible set d.env B - ; echo $?
0                                          # green success, file rewritten
```

So the one command a pub-key-only developer can use is the one command that will hand them
a file the pre-commit hook then rejects — with no signal at the point of the write.

The same gap covers the ambiguity heuristic: `set` writing into a file that contains an
unmatched trailing `]` emits no `UnmatchedTrailingBracket` warning, so the operator gets no
hint that the next `encrypt` will read that secret differently than they intended.

> The coherence review also flagged a missing `MultiLinePlaintext` warning here. That is
> now stale: the grammar revision in `9424c19` ends a plaintext body at the first unescaped
> newline and deletes the heuristic, because a body can only span lines via an explicit
> backslash continuation, which is deliberate rather than suspicious.

### 2. `set` replaces symlinked targets instead of following them (major)

`writeFileAtomic` in `cmd/set.go` does CreateTemp → Sync → Chmod → `os.Rename`, and a
rename over a symlink replaces the **link**. Every other write path in the repo —
`encrypt -i` (`cmd/encrypt.go:50`), `decrypt -i` (`cmd/decrypt.go:52`), `edit`
(`cmd/edit.go:96`), `kms rotate` (`cmd/kms_rotate.go`) — uses `os.WriteFile`, which follows
the link and updates the target.

```console
$ printf 'A=1\n' > real.env && ln -s real.env link.env
$ printf x | envisible set link.env A -
$ test -L link.env && echo symlink || echo replaced
replaced
$ cat real.env
A=1                                        # untouched

$ printf 'A=ENC[1]\n' > real2.env && ln -s real2.env link2.env
$ envisible encrypt -i link2.env
$ test -L link2.env && echo symlink
symlink                                    # encrypt followed it
```

`.env -> .env.local`, or `.env -> ../shared/.env`, is a common layout. After one `set` the
two files silently diverge, and every later `encrypt -i` or `edit` writes to a different
file than the one `set` wrote — so a rotated credential can be written to a file nothing
reads, with both commands reporting success.

Nothing in plan 05 required rename semantics for a symlinked path. Atomicity and mode
preservation are both compatible with resolving the link first.

### 3. `check` prints every defect twice (minor)

`cmd/check.go:65` calls `ui.Error(describeDefect(...))` per defect; `cmd/check.go:96` then
returns `defectError(...)`, which re-renders the same lines, and `main.go` prints that.

```console
$ printf 'A=ENC[oops\n' > e.env && envisible check e.env 2>&1 | grep -c unterminated
2
```

No other command double-reports: `encrypt` and `edit` only call `defectError`;
`decrypt` / `run` / `kms rotate` only call `warnDefects`.

### 4. Messages written for one command are reused where they are wrong (minor)

- **`describeDefect`'s `MalformedEnvLine` text** (`cmd/defects.go:20`) says the line was
  *"skipped: not a NAME=value assignment, so `run` cannot turn it into an environment
  variable"*. Under `set --from-env` nothing is skipped, `run` is uninvolved, and the input
  is the caller's own stdin payload:

  ```console
  $ printf 'A=1\nnot an assignment\n' | envisible set --from-env x.env -
  ✖ --from-env: 1 unreadable line(s) in the payload:
    <stdin>:2:1: skipped: not a NAME=value assignment, so `run` cannot turn it into an environment variable
  ```

- **The TTY refusal** (`cmd/input.go:71`) says *"pipe input or pass a file path"*. Sound
  advice for `encrypt`/`decrypt`/`check`; impossible for `set`, whose entire design forbids
  the value coming from anywhere but stdin.

- **The empty-value error** (`cmd/set.go:107`) says *"stdin carried no bytes"* even when
  stdin carried a perfectly good payload and it is one value inside it that is empty:

  ```console
  $ printf '{"A":""}' | envisible set --from-json y.env -
  ✖ refusing to write an empty value for A: stdin carried no bytes, which is what a dead
    process upstream in a pipe looks like (pass --allow-empty if you meant it)
  ```

  The dead-upstream reasoning is right for a bare `set FILE KEY -` and simply false here.

### 5. `set --dry-run` always exits 0 (minor)

`cmd/set.go:139` reports through `ui.Info` and returns nil whether the outcome is
`added`/`updated` or `unchanged` — and `ui.Info` is silenced by the global `-q`, so
`envisible -q set --dry-run .env K -` produces no output on either stream and exit 0
regardless.

That makes `--dry-run` unusable as the CI drift check that the README's "Two sources of
truth" section points at, even though `check` and `check --verify` — the other half of that
same story — do return non-zero.

### 6. In payload mode a lone positional argument is always a filename (minor)

`parseSetArgs` (`cmd/set.go`) branches on `payloadMode` and takes `rest[0]` as the file with
no validation, while in non-payload mode the same argument means KEY.

```console
$ printf '{"A":"1"}' | envisible set --from-json MYKEY -
✔ set A (added) in MYKEY
$ ls MYKEY
MYKEY                                      # a file named MYKEY, in the working directory
```

Exit 0, green success, junk file. The distinction is resolvable: `processor.ValidEnvName` is
already imported and used a few lines later for exactly this class of pre-flight rejection.

---

## Goals

1. `set` obeys the same defect contract as every other write path.
2. No write path can silently redirect where a credential lands.
3. A message never describes a command the user did not run.
4. `--dry-run` is usable as a CI gate.
5. A plausible typo does not create a file.

### Non-goals

- Re-litigating plan 05's design. Everything here is a consistency defect, not a change of
  intent.
- Extending `set` beyond dotenv-shaped files. Still out of scope, per plan 05.

---

## Design

### Defect contract (finding 1)

Route `set`'s three parser entry points through the defect-aware forms and apply the write
path's severity: **error with `file:line:col`, write nothing.** `set` is a write path; there
is no case for warn-and-continue, because the artifact it produces is the thing that gets
committed.

Two distinct sources of defects need distinct messages, and conflating them is what caused
finding 4a:

| Source | Meaning | Handling |
| --- | --- | --- |
| The **target file** already contains a defect | pre-existing damage `set` did not cause | error, name the file, write nothing |
| The **stdin payload** is malformed | the caller's input is wrong | error, name `<stdin>` and the payload line |

Also call `warnAmbiguousMarkers` on the target before writing, matching `encrypt`.

`Upsert`, `LookupValue` and `LooksLikeDotenv` should return their defects rather than
dropping them — the `p, _ :=` at three sites in `dotenv.go` is the actual bug, and fixing it
there prevents the next caller from repeating it.

### Symlinks (finding 2)

Resolve the target with `filepath.EvalSymlinks` before choosing the temp directory and the
rename destination, so the temp file lands on the resolved file's filesystem and the rename
updates the target rather than the link. A dangling symlink should be an explicit error, not
a silently-created regular file.

Worth doing in a shared helper rather than inside `set`: `encrypt -i`, `decrypt -i`, `edit`
and `kms rotate` all use `os.WriteFile`, which is symlink-correct but **not atomic** — an
interrupted `encrypt -i` on a large file can truncate it. Moving all five onto one
symlink-resolving atomic writer fixes the divergence and the durability gap together. That
is a slightly larger change than this finding strictly requires; if it is split out, `set`
should still resolve links now.

### Messages (finding 4)

Give `describeDefect` a caller-supplied context so the same defect kind can be phrased for
the command at hand, rather than hard-coding `run`. Same for the TTY refusal: `readTarget`
should take the remedy string from its caller. The empty-value error should distinguish
"stdin was empty" from "this key's value within the payload was empty."

### Exit codes (finding 5)

`--dry-run` exits non-zero when any outcome is `added` or `updated`, 0 when everything is
`unchanged` — the same shape as `check`. Report on **stdout** so it survives `-q`, one
machine-readable line per key, since the documented use is a CI drift check.

This is a behavior change to a flag shipped moments ago on an unreleased branch, so no
compatibility concern — but it should be in the README next to the "Two sources of truth"
section that motivates it.

### Argument parsing (finding 6)

In payload mode, reject a lone positional that looks like a key rather than a path — passes
`ValidEnvName`, no separator, no dot — with `--from-json takes a file, not a key`. Prefer a
false rejection here over creating a file: a file named `MYKEY` full of secrets in someone's
working directory is a much worse outcome than an error message they can route around with
`./MYKEY`.

---

## Implementation

1. `pkg/processor/dotenv.go` — `Upsert`, `LookupValue`, `LooksLikeDotenv` return defects.
2. `cmd/set.go` — consume them, split target-vs-payload errors, call `warnAmbiguousMarkers`,
   fix the empty-value message, fix `parseSetArgs`, make `--dry-run` a gate reporting on
   stdout.
3. `cmd/writefile.go` (new) — symlink-resolving atomic writer; adopt in `set`, and in
   `encrypt`/`decrypt`/`edit`/`kms rotate` if that scope is kept.
4. `cmd/defects.go` — context-parameterized `describeDefect`.
5. `cmd/input.go` — caller-supplied TTY remedy text.
6. `cmd/check.go` — drop the duplicate render.
7. `README.md` — `--dry-run` exit semantics; note that `set` refuses a defective target.

---

## Tests

- `set` on a target with an unterminated marker: exit non-zero, **target byte-identical**
  (assert the bytes, not just the code).
- `set --from-env` with a malformed payload line: error names `<stdin>` and does not mention
  `run`.
- `set` into a file with an unmatched trailing `]`: warning emitted, write still succeeds.
- Symlinked target: link survives as a link, the resolved file gets the new value, mode
  preserved. Dangling symlink: explicit error, no file created.
- Same symlink assertion for `encrypt -i` / `decrypt -i` / `edit` — locks in the behavior
  they already have so this cannot regress.
- `check` on one defect prints it exactly once; exit code unchanged.
- `--dry-run` with a changing value exits non-zero and prints to stdout under `-q`;
  unchanged value exits 0.
- `set --from-json MYKEY -` errors and creates no file.
- `{"A":""}` payload: error names the key and does not claim stdin was empty.

---

## Compatibility

Everything here is on an unreleased branch, so there is no external contract to break. The
one change a user could notice if these ship separately from the rest is `--dry-run`'s exit
code.

Findings 1 and 2 are the ones worth prioritizing: both can cost someone a credential — 1 by
producing a file that fails the hook, 2 by writing the rotated value somewhere nothing
reads.

---

## Done when

- [ ] `set` errors and writes nothing on a defective target, with `file:line:col`
- [ ] No message mentions a command the user did not run
- [ ] A symlinked target keeps its link and updates its target, in `set` and everywhere else
- [ ] `check` prints each defect once
- [ ] `--dry-run` is a usable CI gate under `-q`
- [ ] `set --from-json MYKEY -` creates nothing
- [ ] Full suite green; compatibility gate intact
