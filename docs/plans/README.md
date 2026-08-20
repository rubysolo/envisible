# Envisible plans

Working plans for in-flight and proposed changes. Each file is self-contained: problem,
evidence, design, implementation steps, tests, and done criteria. `PLAN.md` at the repo
root stays the high-level roadmap; these are the detailed designs behind individual items.

## Current set

| # | Plan | Kind | Depends on |
|---|------|------|------------|
| 01 | [ENC[...] marker scanner](01-marker-scanner.md) | **Security fix** — silent plaintext leak & value corruption | — |
| 02 | [Env value fidelity in `run`](02-env-value-fidelity.md) | Correctness — `ExtractEnv` mangles values | — (but see the coupling with 01 below) |
| 03 | [`-` for stdin/stdout](03-stdin-stdout.md) | Feature — pipe support, no plaintext temp files | — |
| 04 | [Private key by value](04-key-material-by-value.md) | Feature — let a secret manager hold `envisible.key` | — |
| 05 | [`envisible set`](05-envisible-set.md) | Feature — write a secret into a file without the plaintext ever being in it | 03 (shares stdin intake) |

## Suggested landing order

```
01 ──────────────► (ship alone, it is a security fix)
   │
02 ─┤ independent, any order after 01 lands
03 ─┤
04 ─┘
        05 ── after 03
```

01 first and by itself. It is the only plan that fixes an active silent-failure path
(a secret that looks encrypted and is partly plaintext in a committed file, with
`envisible check` reporting success). Everything else is additive.

**One coupling to respect:** 01 makes multi-line plaintext creatable for the first time, and
`ExtractEnv` splits decrypted output on newlines — so a multi-line value in a `.env` would
let secret content inject extra variables into the child environment. Either ship 01 and 02
together, or include the one-line interim guard in 01 (step 5) that turns that case into a
loud error. Same applies to 05, which can also produce multi-line values.

## Motivation: secrets that live in an external store

Plans 03–05 came out of a question envisible does not currently answer well: if a
credential already lives somewhere safe — a cloud secret manager, Vault, an OS keychain, a
CI variable — how does it get into an envisible file without being written to disk in the
clear along the way?

The seam is a good one, because envisible encryption is a public-key operation. A developer
can seal secrets into a committable file while holding no decrypt capability at all. Two
directions, and what each needs:

**A. The store holds the envisible private key.** Today `envisible.key` is a plaintext
private key sitting on disk — the longest-lived unprotected artifact in a local-keypair
project. Needs **plan 04**, and nothing on the store's side beyond its ability to inject an
env var into a child process:

```sh
<store> exec envisible-key --as ENVISIBLE_KEY -- envisible run -- npm start
```

**B. Seal store-held secrets into an envisible file.** Needs **plan 05** (preferred — the
plaintext never enters the file) or **plans 01 + 03** (the pipe route, which requires the
marker grammar to survive arbitrary secret bytes):

```sh
<store> get my-project | envisible set .env --from-json -   # whole set, one unlock
```

Both examples are written against a generic store; nothing in these plans is specific to
one. Plans 01 and 02 are worth doing regardless of whether any such integration ships —
they are bugs, not features.

## Conventions

- Wire formats (`v1:` NaCl, `v2:` KMS envelope) are frozen. No plan here changes a byte of
  ciphertext or the meaning of an existing marker. Where a plan changes behavior, it says
  so explicitly under "Compatibility".
- Decrypted content goes to **stdout**; everything informational goes to **stderr**.
- Tests live next to the code (`*_test.go`), per `AGENTS.md`.
