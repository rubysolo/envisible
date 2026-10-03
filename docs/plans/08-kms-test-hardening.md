# Plan 08 — KMS: rotate atomicity, descriptor validation, and real request assertions

**Kind:** test hardening — test-only except one small injection seam in `cmd/kms_create.go`
**Status:** proposed
**Depends on:** nothing (09 touches `pkg/kms/aws`; land in either order, see "Coupling")

---

## Problem

`pkg/kms` and its providers sit at 89–94% line coverage. The audit found that the tests run
the important code but rarely assert what it does, in three areas:

1. **`kms rotate` promises an all-or-nothing pre-write phase** (`cmd/kms_rotate.go:71-73`:
   *"If any file fails ... abort before touching disk — half-rotated projects are very hard
   to recover"*). Only one test exercises rotate, with one file and no failures.
2. **Loading a v2 `envisible.pub` validates the version, provider, resource, algorithm and
   key size** (`pkg/kms/pubkey.go:80-108`). Every bad-input case in
   `TestLoadPublicKeyRejectsBadInputs` carries `"public_key": ""`, so each one fails at PEM
   parsing whatever its own check does. The checks are executed by nothing.
3. **Provider fakes ignore the request.** The GCP fake ignores `req.Name` in
   `AsymmetricDecrypt` and `GetPublicKey`; the Azure `fakeKVClient.GetKey` ignores name and
   version; the AWS `GetPublicKey` fake ignores `KeyId`. The tests prove *something* came
   back, not that the right key was asked for.

### Evidence

Single-change mutations, `go test ./...` across the module, all green:

| # | Mutation | Consequence | Verified |
|---|----------|-------------|----------|
| K1 | `cmd/kms_rotate.go:88` — `return fmt.Errorf("rewrap %s: %w", f, err)` → `continue` | the failing file is skipped, the rest rotate, `envisible.pub` moves to the new key; the skipped file is unrecoverable once the old key version is destroyed | re-verified |
| K2 | `pkg/kms/pubkey.go:100` — `ValidateAlgorithm` result ignored | a descriptor with `"algorithm":"bogus"` or an RSA-1024 key loads and is used to encrypt | re-verified |
| K3 | `pkg/kms/pubkey.go:85` — `f.Version != 2` → `false` | a future-version descriptor is silently read as v2 | re-verified |
| K4 | `pkg/kms/azure/azure.go:139` — `GetKey(ctx, res.name, res.version, nil)` → `GetKey(ctx, res.name, "", nil)` | fetches the *latest* key version while the descriptor pins an older one; after a vault-side rotation every new value is wrapped for the wrong key | re-verified |
| K5 | `pkg/kms/gcp/gcp.go:68` — `Name: u.resource` → `Name: ""` | unasserted request identifier | audit |
| K6 | `pkg/kms/gcp/create.go:65` — `CryptoKeyId: p.Name` → `p.Keyring` | key created under the wrong ID | audit |
| K7 | `cmd/kms_create.go:46` — `Name: kmsCreateName` → `Name: gcpCreateKeyring` | flag→param mapping unasserted (`createProviderKeyReal`, 40% coverage) | audit |

---

## Goals

1. Rotate's pre-write abort is proven: a failure in any file leaves every file and
   `envisible.pub` byte-identical.
2. Every descriptor check fails a test when removed, and an old descriptor is pinned by a
   golden fixture.
3. Every provider test asserts the identifiers sent to the SDK.
4. `kms create`'s flag→parameter mapping is testable without cloud credentials.

### Non-goals

- Making the **write** phase of rotate transactional across files. Today a failure while
  writing file 2 leaves file 1 rotated; the code comment at `:94-97` acknowledges this and
  orders writes to minimize it. Pin the current order with a test, but redesigning it
  (e.g. stage everything to temp files, then rename) is its own plan.
- Live-cloud integration tests.

---

## Design

### Rotate (`cmd/kms_test.go`)

`TestKmsRotateAbortsBeforeWritingOnAnyFailure`, table-driven over where the failure is:

- second of two files has a v2 marker with a garbage wrapped key (unwrap fails)
- second file has a structurally truncated v2 marker
- second file is unreadable (path does not exist)
- `--to` bootstrap fails (the fake bootstrap returns an error)

Each case snapshots every input file and `envisible.pub` first, then asserts: non-nil error
naming the offending file; every snapshot byte-identical afterward; no `.envisible-*` temp
files left in the directory.

Also assert on the success path that already exists (`TestKmsRotateRewrapsFileAndUpdatesPubkey`):
the reported marker count, and that each rotated marker's secretbox payload (`blob[256:]`)
is bit-for-bit unchanged — promised at `README.md:378` and in the `RewrapContent` doc
comment (`pkg/processor/rewrap.go:15`), and asserted nowhere at the command level.

### Descriptor validation (`pkg/kms/kms_test.go`)

Rebuild the bad-input table on a **valid** base descriptor (real PEM, real resource) and
change one field per case, asserting the error names that field:

| case | expected error mentions |
|------|-------------------------|
| `"version": 3` | `version` |
| `"provider": "icloud"` | `provider` |
| `"resource": ""` / `"  "` | `resource` |
| `"algorithm": "RSA-OAEP-SHA1"` | `algorithm` |
| PEM of a 1024-bit key | key size |
| PEM of an EC key | not RSA |

Plus one case with an **unknown extra field** that must still load, pinning today's
forward-compatible behavior (`encoding/json` ignores unknowns) so it cannot change by
accident.

**Golden descriptor:** commit `pkg/kms/testdata/envisible.pub.v2.golden`, written by
`v0.0.5`'s `kms.WritePublicKey` (the first release with v2) for a fixed RSA key, and assert it loads to exact
`Kind`/`Resource`/`Alg`/modulus. Same rule as plan 07: a failure means the format changed.

### Provider fakes record their requests

Give each fake a `last<Op>Input` field (or a slice, for the GCP create-then-poll sequence)
and assert in the existing happy-path tests:

- **GCP:** `AsymmetricDecrypt.Name`, `GetPublicKey.Name`, `CreateCryptoKey.Parent` and
  `.CryptoKeyId`, the poll's `GetCryptoKeyVersion.Name`. Also assert `info.Resource` in
  `TestFetchPublicKeyHappyPath`, which currently checks neither.
- **Azure:** `GetKey` name **and version**. Make the fake return a *different* key when
  `version == ""`, so K4 fails loudly rather than by an equality check someone might weaken.
- **AWS:** `GetPublicKey.KeyId` (the `Decrypt` side is already asserted at
  `aws_test.go:172-177`).

### `kms create` seam (`cmd/kms_create.go`)

`createProviderKeyReal` is pure field mapping into `gcpkms.CreateKey`, `awskms.CreateKey`
and `azurekms.CreateKey`. Route those three through package-level function vars (the same
pattern `aws.newKMSClient` already uses) and add a table test per provider asserting the
captured params against the flags passed.

While there: `TestKmsCreateRejectsIncompleteGCPFlags` / `...AzureFlags` only assert
`err != nil`, and would still pass with `PreRunE` deleted because the provider's own
`CreateKey` also rejects. Stub the creators to `t.Fatal` if reached, and assert the
command-level message.

### Registry identity

`TestReplaceUnwrapperAndBootstrap` checks the returned constructor is non-nil. Assert it is
the sentinel that was installed, and that the restore function reinstalls the original —
`withFakeKMSProvider` depends on that, and a restore bug would leak fakes across the whole
`cmd` package.

---

## Coupling with plan 09

Plan 09 changes how `pkg/kms/aws` builds its client. Its tests extend the same AWS fake this
plan teaches to record requests. Either order works; whichever lands second rebases onto the
other's fake.

---

## Done when

- [ ] K1–K7 each fail at least one test when applied alone.
- [ ] Rotate leaves every file and `envisible.pub` byte-identical on each failure case.
- [ ] `pkg/kms/testdata/envisible.pub.v2.golden` exists, came from `v0.0.5`, and loads.
- [ ] No provider test passes with an identifier blanked out of its request.
