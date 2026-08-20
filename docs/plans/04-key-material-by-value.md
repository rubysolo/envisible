# Plan 04 — Accept the private key by value, not just by path

**Kind:** feature (small)
**Status:** proposed
**Depends on:** nothing

---

## Problem

The v1 private key can only be supplied as a **file path**:

```go
// cmd/root.go:29
rootCmd.PersistentFlags().StringVarP(&privKeyPath, "key", "k",
    os.Getenv("ENVISIBLE_KEY_PATH"), "path to private key file (default: envisible.key)")
```

```go
// cmd/keys.go:47
if privData, err := os.ReadFile(privKeyPath); err == nil {
```

So `envisible.key` must exist, in plaintext, on the filesystem of every machine that
decrypts. The README is upfront about it: *"The private key file (`envisible.key`) must be
kept off-repo and provisioned to anything that needs to decrypt."* Provisioning it is the
user's problem, and the only supported answer is "put the plaintext key on disk."

That is fine for a CI runner with an ephemeral filesystem. It is the weakest link on a
developer laptop, where the key is a long-lived 0600 file that outlives the project,
gets swept into backups and Spotlight indexes, and is readable by every process running as
that user.

Every serious solution to this — an OS keychain, Vault, a CI secret store, Docker/Kubernetes
secrets, `systemd` credentials — hands you **the material**, in memory, not a path. Today
envisible cannot accept that without the caller writing it back out to a temp file, which
is precisely the artifact they were avoiding.

The KMS (v2) path already sidesteps this, since the private half never leaves the cloud.
This plan brings the local-keypair path to parity on the provisioning question.

---

## Goals

1. The private key can be supplied as material via the environment, with no file anywhere.
2. Provider-agnostic — nothing in envisible knows or cares where the material came from.
3. `keygen` can emit the private key to stdout so it can be captured directly into a store
   without a disk round-trip.
4. Key material never appears in argv, in a log line, or in an error message.

### Non-goals

- A plugin interface for secret backends. An env var composes with every backend already;
  a plugin API composes with the ones we anticipated.
- Public key by value. `envisible.pub` is not secret and is meant to be committed.
- A `--key-command` subprocess hook. Reconsider if the env var proves insufficient; it is
  strictly more machinery for the same result.

---

## Design

### `ENVISIBLE_KEY` carries the material

The base64 key exactly as `keygen` writes it — the same string `crypto.DecodeKey` already
parses, whitespace-trimmed. It sits alongside the existing `ENVISIBLE_KEY_PATH`, which
keeps meaning *path*.

The two names are one word apart, which is a real readability cost. It is worth it:
`ENVISIBLE_KEY` = "the key" is what someone reaches for without reading the docs, and it
matches the neighbours (`DOTENV_PRIVATE_KEY`, `SOPS_AGE_KEY` — both material, both with
`*_FILE`/`*_KEY_FILE` siblings for the path). Document them adjacently and in contrast.

### Resolution order

Highest wins:

1. `--key` / `-k` **explicitly passed on the command line** — a path
2. `ENVISIBLE_KEY` — material
3. `ENVISIBLE_KEY_PATH` — a path
4. `envisible.key` — the default path

An explicit flag beating an ambient env var is the least surprising order, and it gives an
operator a way to override an inherited `ENVISIBLE_KEY` without unsetting it.

This needs care, because today the flag's *default value* is `os.Getenv("ENVISIBLE_KEY_PATH")`,
which makes "flag passed" and "env var set" indistinguishable after parsing. Use
`cmd.Flags().Changed("key")` to tell them apart, which means resolution has to move out of
`init()` and into a `PersistentPreRunE` (or into `loadDecryptor`, which has access to the
command). `init()` currently also defaults `pubKeyPath` and `filePath`; move all three
together rather than leaving one resolved in a different place from the others.

### `loadDecryptor`

`cmd/keys.go:47` grows a source selection in front of the read:

```go
material, err := resolvePrivateKeyMaterial(cmd)  // returns ("", nil) when absent
```

- material present → `crypto.DecodeKey(strings.TrimSpace(material))`
- otherwise → today's `os.ReadFile(privKeyPath)`, with `fs.ErrNotExist` still meaning
  "no v1 key, that's fine" so fully-migrated v2 projects keep working

The `haveNacl` / composite-decryptor logic below it is unchanged.

**Error text must not leak the material.** The current not-found error interpolates paths
(`"no decryption key available (looked for %s and %s)"`) — keep that shape, and when the
source is `ENVISIBLE_KEY`, say `ENVISIBLE_KEY` rather than echoing any part of the value.
A malformed-key error from `crypto.DecodeKey` currently wraps the base64 error, which for
a corrupt value can include an offset but not content; confirm and add a test asserting the
material never appears in `err.Error()`.

### `keygen --print-key`

Write `envisible.pub` as usual; write the private key to **stdout** and skip
`envisible.key` entirely:

```sh
envisible keygen --print-key | <store> set envisible-key    # never touches disk
```

Refuse when stdout is a TTY, mirroring plan 03's intake rule and for the same reason: the
one thing worse than a key file is a key in scrollback.

### File-mode warning

While in `loadDecryptor`: if the key is read from a file whose mode is group- or
world-readable, `ui.Warn` once. `keygen` writes 0600 (`cmd/keygen.go:25`); a key that has
since been copied, checked out, or `chmod`'d loses that, and nothing currently notices.
Warn, never fail — breaking a working setup over a permission bit is worse than the bit.

---

## Security note (document honestly, in the README)

An env var is not strictly safer than a 0600 file — it is differently safe, and users
should be able to reason about the trade:

- **Better:** no disk artifact. Nothing to back up, index, `scp`, or find in 2027.
- **Worse:** on Linux, `/proc/<pid>/environ` exposes it to any process of the same user,
  and it is inherited by every child unless the caller scopes it.
- **Roughly equal:** a process running as you can read either one.

The mitigation is scoping, and it belongs to the caller. A store that injects the material
into a single child process — `<store> exec envisible-key --as ENVISIBLE_KEY -- envisible
run …` — puts it in exactly one environment and never in the parent shell. A CI runner that
exports it globally for the whole job gets the weaker version. Say that plainly rather than
implying the env var is an upgrade on its own.

---

## Implementation

1. **`cmd/root.go`** — move path defaulting from `init()` to `PersistentPreRunE`; add
   `resolvePrivateKeyMaterial`.
2. **`cmd/keys.go`** — `loadDecryptor` prefers material; unchanged composite logic; file-mode
   warning.
3. **`cmd/keygen.go`** — `--print-key`, TTY refusal.
4. **`README.md`** — a "Providing the private key" subsection: the three sources, the
   resolution order, the `ENVISIBLE_KEY` vs `ENVISIBLE_KEY_PATH` contrast, and the security
   note, with one worked example of a secret-manager-backed key.

---

## Tests

`cmd/keys_test.go` and `cmd/cmd_test.go`:

- `ENVISIBLE_KEY` set, no `envisible.key` on disk → `decrypt` and `run` succeed
- both set → material wins over `ENVISIBLE_KEY_PATH`
- explicit `--key <path>` beats `ENVISIBLE_KEY`
- malformed `ENVISIBLE_KEY` → clear error, and **the material does not appear in the error
  string** (assert on `err.Error()`)
- neither present, v2 pubkey present → KMS-only decryptor still builds (regression on the
  best-effort read at `cmd/keys.go:47`)
- neither present, no pubkey → today's "no decryption key available" error
- `keygen --print-key` → key on stdout, no `envisible.key` created, `envisible.pub` written
- `keygen --print-key` to a TTY → refused
- group-readable key file → warning on stderr, command still succeeds

---

## Compatibility

Purely additive. With `ENVISIBLE_KEY` unset, resolution collapses to today's behavior. The
`init()` → `PersistentPreRunE` move is the only structural risk; cover it with a test that
`-k`, `ENVISIBLE_KEY_PATH`, and the bare default each still resolve as before.

---

## Done when

- [ ] `ENVISIBLE_KEY=$(cat envisible.key) envisible run -- printenv X` works with the key
      file deleted
- [ ] Resolution order holds in all four combinations
- [ ] No test can find key material in any error or log output
- [ ] `keygen --print-key` writes nothing secret to disk
- [ ] README documents the sources, the order, and the honest security trade
