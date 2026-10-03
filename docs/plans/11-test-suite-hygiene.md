# Plan 11 — Test-suite hygiene: tests that fail when they should

**Kind:** test hardening — test-only
**Status:** proposed
**Depends on:** 10 (shares `cmd/cmd_test.go`; land 10's harness change first)

---

## Problem

Plans 07, 08 and 10 add missing tests. This plan fixes how the existing tests are written,
because several patterns in `cmd/cmd_test.go` let real regressions through even where a
test nominally covers the behavior. Plan 10's `ENVISIBLE_FILE` gap (C3) is the worked
example: the test existed, ran the code and passed whatever the code did.

Nothing here adds coverage. Every item makes an existing test stricter or less dependent on
its surroundings.

---

## Findings and fixes

### 1. Tests that pass by returning early

`cmd_test.go:282, 491, 515, 621, 669, 912` all do some form of:

```go
if runErr != nil {
	t.Logf("run failed (maybe env missing?): %v", runErr)
	return
}
```

If `run` breaks, these tests pass. The banner-on-stderr and `-q` tests
(`TestBannerGoesToStderrNotStdout`, `TestQuietFlagSuppressesBanner`) pass vacuously the
same way. The child commands they use (`env`, `echo`, `printf`, `sh`) are POSIX-guaranteed
on every platform CI runs. **Fix:** `t.Fatalf`. If a command is genuinely unavailable
somewhere, `exec.LookPath` it first and `t.Skip` with the reason — a visible skip, never a
silent pass.

### 2. Ignored setup errors

About twenty setup calls discard the error from `rootCmd.Execute()` (`cmd_test.go:265, 273,
306, 369, 378, 401, 541, 576, 597, 606, 644, 655, 659, 696, 704, 755, 795, 821, 832, 836,
870`). A broken `keygen` or `encrypt` then surfaces as a confusing downstream failure, or
none — `TestEdit` at `:401` can pass with setup failed.

**Fix:** a helper that fails the test, and use it for every setup step:

```go
// mustRun executes args against a freshly reset rootCmd and fails the test on error.
// For setup steps, whose failure would otherwise surface as a misleading later one.
func mustRun(t *testing.T, args ...string) {
	t.Helper()
	if _, _, err := runRoot(t, args...); err != nil {
		t.Fatalf("setup `envisible %s`: %v", strings.Join(args, " "), err)
	}
}
```

(`runRoot` comes from plan 10.)

### 3. Package-level flag state that leaks between tests

`resetRoot` resets the persistent flags and some subcommand vars, but not `verify`
(`cmd/check.go:12`). `TestSetThenCheckPasses` (`set_test.go:720`) runs `check --verify`, and
every later `check` in the same process runs in verify mode. It is latent only because that
test happens to run late in file order. The `set` flags are reset by `resetSet` but not by
`resetRoot`.

**Fix — make it impossible to forget:** instead of listing variables by hand, have
`resetRoot` walk every command and reset every flag to its default:

```go
var walk func(*cobra.Command)
walk = func(c *cobra.Command) {
	for _, fs := range []*pflag.FlagSet{c.Flags(), c.PersistentFlags()} {
		fs.VisitAll(func(f *pflag.Flag) {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		})
	}
	for _, sub := range c.Commands() {
		walk(sub)
	}
}
walk(rootCmd)
```

This covers any flag added later. Slice-valued flags need care (`Set` appends): check
whether any exist (`StringSliceVar` etc.) and reset those explicitly. Keep the explicit
resets for non-flag package state (`privKeyMaterial`, `ui.Quiet` if it isn't flag-backed).
Then add a guard test: run every subcommand's flags through a non-default value, call
`resetRoot`, and assert all are back at their defaults.

### 4. Working directory not restored on failure

Many tests do `os.Chdir(tmpDir); defer os.Chdir(oldWd)`, and some do it without the
`defer`. A `t.Fatal` before the deferred call still runs it, but the tests that skip the
`defer` leave every later test in the wrong directory. **Fix:** `t.Chdir(dir)` (Go 1.24+,
the module is on 1.25) everywhere, which restores automatically and also refuses to run
under `t.Parallel`, catching a whole class of future bugs.

### 5. Weak assertions

- Error tests that only assert `err != nil` — for example `TestKmsCreateRejectsIncomplete*`
  (see plan 08) and `TestStructureCheck` (see plan 07). Assert on the error text, and where
  an output is produced, on the output too.
- Weak substrings: `"azure"` in `TestNewUnwrapperRejectsBadResource`, `"required"` in the
  flag-validation tests. Match the distinctive part of the message.

### 6. Environment isolation (partly done)

`TestMain` in `cmd/root_test.go` (added in `5de265e`) unsets `ENVISIBLE_KEY`,
`ENVISIBLE_KEY_PATH`, `ENVISIBLE_PUB_PATH` and `ENVISIBLE_FILE`. Extend the same idea:

- `pkg/kms/*`: unset the cloud SDK variables that could make a test reach real credentials
  (`AWS_PROFILE`, `AWS_REGION`, `GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_*`) in a `TestMain`
  per provider package, so a developer's environment can never turn a unit test into a live
  call.
- `EDITOR`/`VISUAL` for `edit` tests already use `t.Setenv`; confirm all of them do.
- git isolation is covered in plan 10 §4.

### 7. Untestable-in-process paths (document, don't chase)

`run.go:86-88` propagates a child's exit code with `os.Exit`, and `main()` /
`cmd.Execute()` are at 0%. Cover exit-code propagation with one subprocess test (re-exec
the test binary with an env var selecting a helper mode, the standard `os/exec` test
pattern), asserting `envisible run -- sh -c 'exit 3'` exits 3. Leave `main()` uncovered.

---

## Implementation

Order matters only for item 2, which needs plan 10's `runRoot`.

1. Item 3 (flag reset walker + guard test) — do this first; it may expose order-dependent
   failures that the other items would otherwise be blamed for.
2. Items 1, 2, 4 together, file by file through `cmd_test.go` and `set_test.go`.
3. Item 5 alongside plans 07/08 where they overlap, otherwise standalone.
4. Item 6 `TestMain`s in the `pkg/kms` provider packages.
5. Item 7's subprocess test.

Run `go test -count=1 -shuffle=on ./...` several times after step 1 and again at the end.
The suite must pass under shuffle; today it may not.

---

## Done when

- [ ] No test returns early on an error from the code under test without `t.Fatal` or an
      explicit `t.Skip`.
- [ ] No ignored `Execute()` error anywhere in `cmd/*_test.go`.
- [ ] `resetRoot` resets every flag on every command, and a test proves it.
- [ ] No `os.Chdir` left in tests.
- [ ] `go test -count=1 -shuffle=on ./...` passes five runs in a row.
