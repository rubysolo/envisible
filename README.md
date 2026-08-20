# Envisible

**Envisible** is a CLI tool to safely manage encrypted secrets within your configuration files (YAML, JSON, TOML, .env, etc.) using explicit `ENC[...]` markers.

Your secrets normally live somewhere your config doesn't: a separate secret store, a `.env` that's gitignored and passed around by hand, a wiki page that drifts out of date. Envisible keeps the secret *next to the setting it belongs to* and encrypts only that value, so the file stays safe to commit. That means your configuration is versioned alongside your code — every change to a secret shows up in `git history`, code review, and rollbacks like any other line. Deploys get simpler too: there's one source of truth in the repo and nothing to sync at release time, since values are decrypted on the fly at runtime (injected into the environment with `envisible run`, or emitted to stdout for build pipelines). Start with a local keypair and no infrastructure; move to cloud KMS when you want managed keys and audit logs — the file format doesn't change.

Two key-management modes are supported:

- **Local keypair** (default) — a NaCl Box keypair (Curve25519 + XSalsa20-Poly1305) generated with `envisible keygen`. Simple, no network, no cost. The private key must be kept off-repo and provisioned to anything that needs to decrypt — as a file (`envisible.key`) or as material in `ENVISIBLE_KEY`; see [Providing the private key](#providing-the-private-key).
- **Cloud KMS** — an asymmetric RSA-OAEP-SHA-256 key in **Google Cloud KMS**, **AWS KMS**, or **Azure Key Vault**. The private half never leaves the cloud; only the public key is downloaded into `envisible.pub`. Decryption authenticates via the cloud SDK's default credential chain (gcloud auth / IAM role / Managed Identity / etc.). See [Cloud KMS-backed keys](#cloud-kms-backed-keys) below.

## Installation

```bash
go install github.com/rubysolo/envisible@latest
```

or via homebrew:

```bash
brew tap rubysolo/tools
brew install envisible
```

## Use with AI coding agents

Envisible ships with a setup skill so coding agents can wire encrypted secrets into a project for you — discovering plaintext secrets, choosing a key mode (local keypair or cloud KMS), encrypting, and wiring decryption into the runtime, CI, and git.

**Claude Code** — install the plugin (bundles the skill):

```text
/plugin marketplace add rubysolo/envisible
/plugin install envisible@rubysolo-tools
```

Then just ask: *"set up envisible to encrypt the secrets in this repo"* and the agent follows the skill end-to-end.

**Other agents (Cursor, Codex, Aider, Zed, …)** — the skill is a plain Markdown file at [`skills/envisible/SKILL.md`](skills/envisible/SKILL.md). Point your agent at it, or copy it into your agent's rules/skills directory. This repo also includes an [`AGENTS.md`](AGENTS.md) describing the project for any agent that lands here.

## How it compares

Plenty of good tools encrypt secrets for version control. Envisible's particular niche is **value-level markers in any text file**: you wrap a single value (or even a substring of one) in `ENC[...]`, and only that value becomes ciphertext. Everything else — keys, structure, comments, the rest of a connection string — stays plaintext, so diffs and code review stay readable and there's no extra metadata block in your files.

| Tool | Granularity | Works in | Keys | Diff stays readable? |
| --- | --- | --- | --- | --- |
| **Envisible** | Per-value `ENC[...]`, including partial substrings | any text file (YAML/JSON/TOML/.env/INI/…) | local NaCl keypair, or GCP/AWS/Azure KMS (private key stays in the cloud) | Yes — only the marked value is ciphertext |
| [SOPS](https://github.com/getsops/sops) | Per-value (whole file, or keys matching `encrypted_regex`) | structured formats; adds a `sops` metadata block | age, PGP, AWS/GCP/Azure KMS, HashiCorp Vault | Mostly — values encrypt, plus an appended MAC block |
| [git-crypt](https://github.com/AGWA/git-crypt) | Whole file | any file (via `.gitattributes`) | GPG or a symmetric key | No — the file is an opaque blob in git |
| [dotenvx](https://github.com/dotenvx/dotenvx) | Per-value | `.env` files | ECIES keypair (private key in `.env.keys`) | Yes, within `.env` |
| [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) | Whole Secret | Kubernetes `Secret` manifests | in-cluster controller key | N/A (Kubernetes CRD) |

**Reach for something else when:**

- You want **age or PGP keys, HashiCorp Vault, or a mature GitOps/Flux workflow** → SOPS is the deeper, more battle-tested ecosystem.
- You want **whole files encrypted transparently** with no change to how your app reads them → git-crypt.
- Your secrets are **Kubernetes `Secret`s** and you want an in-cluster operator to do the decryption → Sealed Secrets.
- You live **entirely in `.env` files** and want that workflow polished end to end → dotenvx.

Envisible is the right fit when your secrets don't map one-to-one with key names (e.g. encrypt just the password in a database connection string), you want diffs and reviews to stay legible, or you'd like to start with zero infrastructure (a local keypair) and graduate to managed cloud keys later **without changing the file format**. It also ships a SKILL.md, so a coding agent can handle the setup for you.

## Quick Start

### 1. Generate Keys
Generate a keypair. This creates `envisible.pub` (safe to check in) and `envisible.key` (keep secret / add to .gitignore).

```bash
envisible keygen
# Generated keys:
#   Public:  envisible.pub
#   Private: envisible.key
```

### 2. Add Secrets
Edit your configuration file and wrap sensitive values in `ENC[...]`.

**config.yaml**
```yaml
database:
  host: localhost
  password: ENC[my-secret-password]
```

### 3. Encrypt
Run the encrypt command. This will encrypt the values in-place (with `-i`).

```bash
envisible encrypt -i config.yaml
```

Your file now looks like:
```yaml
database:
  host: localhost
  password: ENC[v1:hk9RWQA3BRsmYT4FY...]
```

### 4. Run with Secrets
Use the `run` command to execute your application. Envisible will decrypt the secrets and inject them into the environment variables.

```bash
# Injects decrypted values into the environment
envisible run -e .env -- npm start
```

*Note: For non-environment variable use cases (like config files), you can decrypt to a temporary file or use the `decrypt` command.*

### A note on output streams

`decrypt` writes the file contents (or a decrypted value) to **stdout**, so command substitution and pipes just work — no flags needed:

```bash
export DB_PASSWORD=$(envisible decrypt --strip secrets.env)
envisible decrypt config.yaml | jq '.database'
```

All informational output (`Loading environment…`, `Starting:`, KMS summaries, etc.) goes to **stderr**, alongside errors. If you want to silence the chatter — for cleaner CI logs or interactive sessions — pass `--quiet` (or `-q`); it's a global flag and works on every subcommand:

```bash
envisible -q run -- ./deploy.sh   # no banner on stderr either
```

### Reading from stdin

`encrypt`, `decrypt` and `check` accept `-` as the file argument, meaning "read stdin to EOF". Output already defaults to stdout, so both halves of a pipe work and a value can go from a producing process to ciphertext with no plaintext file at any point:

```bash
# encrypt whatever a generator produces, straight into a committable file
render-config | envisible encrypt - > config.enc.yaml

# validate content before it is written anywhere
render-config | envisible check -
```

- `-f -` is identical to a positional `-`.
- `--inplace` / `-i` together with `-` is an **error**, not a silently ignored flag — there is no file to rewrite, and a script must not believe it wrote one.
- Reading from a terminal is refused immediately (`refusing to read from a terminal; pipe input or pass a file path`) rather than looking like a hang. Empty piped input is fine: an empty file is a legitimate thing to encrypt.
- `check` names the target `<stdin>` in its messages.
- `edit -` and `run -f -` are rejected with a pointer at the right command: `edit` has no file to open, and `run` must leave stdin to the child process.
- A file literally named `-` becomes unreachable by that name; `./-` still works.

To move a secret that lives in an external store into a file, prefer [`envisible set`](#setting-a-value-without-writing-plaintext) — the plaintext never enters the file at all.

### 5. Editing Secrets
To edit secrets without manually decrypting and re-encrypting:

```bash
envisible edit config.yaml
```
This opens the decrypted file in your `$EDITOR`. When you save and quit, it automatically re-encrypts the file.

### 6. CI/CD Checks
Ensure no unencrypted secrets are committed:

```bash
envisible check config.yaml
```

### Providing the private key

Decryption (`decrypt`, `run`, `edit`, `check --verify`) needs the local private key. It can be supplied as a **path** or as **material** — the base64 string `keygen` writes, with surrounding whitespace ignored:

| Source | Kind | Example |
| --- | --- | --- |
| `--key` / `-k` | path | `envisible run -k /run/secrets/envisible.key -- ./app` |
| `ENVISIBLE_KEY` | key material | `ENVISIBLE_KEY="$(cat envisible.key)" envisible run -- ./app` |
| `ENVISIBLE_KEY_PATH` | path | `export ENVISIBLE_KEY_PATH=~/.config/envisible/app.key` |
| `envisible.key` | path | the built-in default |

Resolution order, highest wins:

1. **`--key` / `-k` explicitly passed** — always a path. Passing it also disables `ENVISIBLE_KEY` for that run, so an operator can override an inherited env var without unsetting it.
2. **`ENVISIBLE_KEY`** — the key material itself.
3. **`ENVISIBLE_KEY_PATH`** — a path.
4. **`envisible.key`** in the working directory.

**`ENVISIBLE_KEY` vs `ENVISIBLE_KEY_PATH`.** One word apart, and the difference is the whole point: `ENVISIBLE_KEY` *is* the key; `ENVISIBLE_KEY_PATH` *points at a file* holding it. Material never reaches a log line, an error, or argv — a malformed `ENVISIBLE_KEY` reports `failed to decode private key from ENVISIBLE_KEY: …` with the decoder's offset or length, never any of the value. (The public key resolves the same way, minus the by-value option: `--pub` / `-p`, then `ENVISIBLE_PUB_PATH`, then `envisible.pub`. In Cloud KMS mode there is no private key on this side at all.)

When the key is read from a **file** whose mode is group- or world-readable, envisible warns on stderr and carries on — breaking a working setup over a permission bit would be worse than the bit:

```
private key envisible.key is mode 0644 (readable beyond its owner); consider `chmod 600 envisible.key`
```

To capture a fresh key into a store with no disk round-trip:

```bash
envisible keygen --print-key | secret-store set envisible-key
```

`--print-key` writes `envisible.pub` as usual, prints the private key to **stdout**, and writes no `envisible.key`. It refuses when stdout is a terminal — the one thing worse than a key file is a key in scrollback — and it refuses *before* generating anything, so a refused run leaves no artifacts.

#### Is an env var safer than a 0600 file?

Not strictly. It is **differently** safe, and the trade is worth making on purpose:

- **Better:** no disk artifact. Nothing to back up, index, `scp`, or find still sitting there in 2027.
- **Worse:** on Linux, `/proc/<pid>/environ` exposes it to any process running as the same user, and it is inherited by every child process unless the caller scopes it.
- **Roughly equal:** anything already running as you can read either one.

The mitigation is **scoping, and it belongs to the caller**. A store that injects the material into a single child process puts it in exactly one environment and never in the parent shell:

```bash
secret-store exec envisible-key --as ENVISIBLE_KEY -- envisible run -- npm start
```

A CI runner that exports the same variable globally for the whole job gets the weaker version of this. Envisible cannot tell the two apart; the env var is a better provisioning *mechanism*, not an upgrade on its own.

## Values are delivered byte-exactly

**This is a behavior change.** `envisible run` now hands the child process exactly the bytes that were encrypted. Previously the whole file was decrypted first and the *result* was parsed as dotenv, which fed the plaintext of every secret back through a parser that trimmed whitespace and stripped quotes. Structure is now resolved against the still-encrypted file, and values are decrypted afterwards.

| `.env` line | `run` used to deliver | `run` delivers now |
| --- | --- | --- |
| `PW=ENC[sk_live_abc ]` (trailing space in the secret) | `sk_live_abc` | `sk_live_abc ` |
| `PW=ENC["quoted"]` (quotes are part of the secret) | `quoted` | `"quoted"` |
| `PW="'bar'"` (a literal, no marker) | `bar` | `'bar'` |
| `export FOO=ENC[…]` | key `export FOO` | key `FOO` |
| `FOO=ENC[…] # note` | value with ` # note` glued on | value without it |
| a CRLF file | `\r` on every value (masked by the trim) | no `\r` anywhere |

Quoting is a property of **how a value is written in the file**, never of the secret:

- A value that is exactly one marker — optionally wrapped in one matching pair of quotes — is delivered **verbatim**. No trimming, no unquoting. Whitespace and quotes *inside* the marker belong to the secret.
- Anything else is file text: it is trimmed, exactly one matching surrounding quote pair is removed (so `FOO="'bar'"` is `'bar'`, not `bar`), and any markers embedded in it are decrypted and spliced in place — which is what keeps `DATABASE_URL=postgres://u:ENC[…]@host/db` working.

Because parsing happens before decryption, **secret content can no longer alter the environment**. A secret whose plaintext is

```
hunter2
PATH=/tmp/evil
```

produces exactly one variable holding that two-line string; no `PATH` entry appears. Lines that are not `NAME=value` assignments are skipped *out loud* — `run` warns with `file:line:col` instead of dropping them in silence.

Upgrade note: a project that accidentally relied on the old trimming will see a different value, and one relying on the broken `export FOO` key name will find that key gone and `FOO` present instead. envisible files are still not shell — no `$VAR` interpolation, no command substitution, no `"""` literals.

## Setting a value without writing plaintext

`envisible encrypt` and `envisible edit` both require the plaintext to exist in a file before it can be protected. `envisible set` does not: it reads the value from **stdin**, encrypts it in memory, and splices only the ciphertext into a `.env`-shaped file.

```bash
printf '%s' "$TOKEN" | envisible set .env API_TOKEN -
secret-store get api-token   | envisible set API_TOKEN -      # file defaults to -f / .env
secret-store export --json   | envisible set --from-json -    # a whole set, one unlock
cat some.env                 | envisible set --from-env -
```

Encryption is a public-key operation, so this works with **`envisible.pub` alone** — a developer holding no decrypt capability at all can still add and rotate secrets.

The trailing `-` is mandatory and there is deliberately **no `--value` flag**: an argument is visible in `ps`, in shell history, and in every process listing on the machine.

Flags: `--from-json` (a JSON object of `KEY` → string) and `--from-env` (dotenv-shaped lines) for multi-key payloads on stdin, plus `--dry-run`, `--if-changed`, `--raw` and `--allow-empty`. The two payload flags are mutually exclusive, and `--from-env` reads its input as plaintext — an `ENC[...]` in the payload stays literal text rather than being opened.

What it guarantees:

- **Layout is preserved.** An existing key keeps its `export ` prefix, indentation, spacing and trailing `# comment`; only the value span is rewritten. A new key is appended with exactly one trailing newline. Everything else — comments, ordering, unrelated lines — is copied byte for byte. If a key is assigned more than once, the last assignment is the one rewritten, because that is the one `run` would use.
- **Writes are atomic**: a temp file in the same directory, `fsync`, `rename`, with the file's existing mode preserved (0644 for a new file). A symlinked target stays a symlink and its target is what changes; a dangling symlink is an error rather than a new file where the link used to point. The same writer backs `encrypt -i`, `decrypt -i`, `edit` and `kms rotate`.
- **A damaged target is refused.** `set` is a write path and follows the write path's defect contract (see [Marker grammar](#marker-grammar)): a file that already holds an unterminated `ENC[` fails with `file:line:col` and is left byte-identical, rather than producing a file the pre-commit hook then rejects — which matters most for the developer with only `envisible.pub`, who cannot check their own work.
- **Exactly one trailing newline is trimmed** from stdin, since editors, heredocs and `echo` all add one and a credential with a stray `\n` fails far from the command that broke it. Trimming exactly one means a multi-line secret keeps its shape; `--raw` keeps the bytes verbatim.
- **Empty stdin is an error and nothing is written.** A process that dies upstream in a pipe closes it with no bytes, which at this end is indistinguishable from success — without the guard, a live credential would be replaced with an empty one and reported as done. Pass `--allow-empty` when you mean it.
- A terminal on stdin is refused, an invalid key name is rejected before the file is touched, and a target that is not dotenv-shaped (a JSON document, a YAML `---`, a file of `key: value` lines) is rejected with a pointer at `envisible edit`.
- **No value ever reaches stdout or stderr**, including in error messages. Reports name keys only: `set STRIPE_KEY (updated), AWS_REGION (added)`.

The value goes straight to the encryptor, so it never passes through the plaintext marker grammar — no escaping, no ambiguity, whatever bytes the secret contains.

### `set` is not a sync primitive

Encryption is randomized: a fresh ephemeral keypair and nonce per value in v1, a fresh data key and nonce in v2. **Re-encrypting an unchanged value always produces different ciphertext**, so re-running `set` always produces a diff even when nothing changed.

That matters more than it sounds. A noisy diff is a security regression in a tool whose central claim is that secret changes show up in code review. So, deliberately:

- `set` writes **only the keys it was given**. There is no "sync the whole file" mode.
- `--from-json` writes — and therefore churns — every key in the payload.
- `--if-changed` decrypts the current value and skips keys that already match. It needs decrypt capability, so it is opt-in; without one it fails loudly rather than quietly rewriting everything.
- `--dry-run` writes nothing and is a gate: it prints one `action<TAB>KEY<TAB>file` line per key (`added` / `updated` / `unchanged`) on **stdout** — so `-q` cannot silence it — and exits non-zero if anything would change, the same shape as `check`. `envisible -q set --dry-run --if-changed .env KEY -` is therefore a usable CI drift check.

Use `set` to **add** a key and to **rotate** a key. A periodic "push everything" loop built on top of it will produce diffs nobody reads.

### Two sources of truth

Once a credential lives both in an external store and in a committed envisible file, **rotation has to touch both**, and nothing detects the drift for you. Drift detection needs decrypt capability, which the developer machine deliberately may not have. The realistic place for that check is CI: a job that does hold decrypt permission runs `envisible check --verify` and, if the project wants it, compares against whatever the canonical source is.

## Cloud KMS-backed keys

In Cloud KMS mode, the project's asymmetric private key lives in GCP KMS / AWS KMS / Azure Key Vault and never leaves it. Only the public key is downloaded into `envisible.pub` — the file is safe to commit. Decryption (`envisible run`, `envisible decrypt`, `envisible edit`) authenticates to the cloud at runtime using each SDK's default credential chain.

### Wire format

Cloud-backed values use a `v2:` envelope marker:

```
ENC[v2:base64( RSA-OAEP-SHA256(data_key) || nonce || secretbox.Seal(plaintext, nonce, data_key) )]
```

For each value, envisible generates a random 32-byte data key, seals the payload locally with NaCl secretbox, and wraps the data key with the KMS public key via stdlib RSA-OAEP. **No network at encrypt time.** At decrypt time the wrapped data key is sent to KMS for unwrapping — one call per `ENC[...]` value, parallelized inside `envisible run`.

Plaintexts are unbounded in size (PEM keys, certificates, etc. — the envelope handles them).

### Choosing a setup path

You have a key already (Terraform, console, gcloud, etc.):

```bash
envisible kms init --provider gcp \
    --resource projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N
```

You want envisible to provision the key (requires KMS-admin permission):

```bash
envisible kms create --provider gcp \
    --project P --location L --keyring R --name K
```

Both commands end the same way: `envisible.pub` is written with the key's public half + the resource pointer. From there, `envisible encrypt` / `envisible run` work just like the local-keypair case — no `envisible.key` is needed.

### Per-provider quick setup

**GCP KMS** — create an asymmetric decryption key:

```bash
# One-time: provision the keyring and key
gcloud kms keyrings create my-app --location us
gcloud kms keys create my-key \
    --keyring my-app --location us \
    --purpose asymmetric-encryption \
    --default-algorithm rsa-decrypt-oaep-2048-sha256

# Register with envisible
envisible kms init --provider gcp \
    --resource projects/MY-PROJECT/locations/us/keyRings/my-app/cryptoKeys/my-key/cryptoKeyVersions/1
```

Auth: any source picked up by Application Default Credentials — `gcloud auth application-default login` for local dev, workload identity in GKE, service-account JSON via `GOOGLE_APPLICATION_CREDENTIALS`. Required roles: `cloudkms.viewer` to read the public key during `kms init`, `cloudkms.cryptoKeyDecrypter` at decrypt time.

**AWS KMS** — create an asymmetric customer-managed key:

```bash
aws kms create-key \
    --key-spec RSA_2048 \
    --key-usage ENCRYPT_DECRYPT \
    --description "envisible asymmetric envelope key"
# (note the KeyId from the output)
aws kms create-alias --alias-name alias/my-app --target-key-id <KEY_ID>

# Register with envisible — full ARN or alias ARN both work
envisible kms init --provider aws \
    --resource arn:aws:kms:us-east-1:123456789012:key/<KEY_ID>
```

Auth: the AWS SDK's standard credential chain — env vars, `~/.aws/credentials`, IMDSv2 on EC2, IRSA in EKS, SSO. Required actions: `kms:GetPublicKey` for init, `kms:Decrypt` at runtime.

**Azure Key Vault** — create an RSA-2048 key:

```bash
az keyvault key create \
    --vault-name myvault \
    --name my-key \
    --kty RSA \
    --size 2048

# Register with envisible — note the version segment is required
envisible kms init --provider azure \
    --resource https://myvault.vault.azure.net/keys/my-key/<VERSION>
```

Auth: `DefaultAzureCredential` — `az login` for local dev, managed identity on Azure compute, env vars (`AZURE_CLIENT_ID`/`AZURE_TENANT_ID`/`AZURE_CLIENT_SECRET`) for service principals. Required permissions: `keys/get` to read the public key during init, `keys/decrypt` at runtime.

### Rotation

To rotate to a new key version (or a different key under the same provider):

```bash
# 1. Create the new version
gcloud kms keys versions create --location us --keyring my-app --key my-key
#    (note the new version number, e.g. 2)

# 2. Re-wrap every v2 marker in the file. The secretbox payload stays bit-for-bit
#    identical; only the wrapped data key is swapped. envisible.pub is updated
#    last to point at the new resource.
envisible kms rotate --to projects/.../cryptoKeyVersions/2 config.yaml .env

# 3. Once you've confirmed everything decrypts with the new version, disable
#    or destroy the old version via your cloud provider's UI/CLI.
```

Rotation is same-provider only. For cross-provider migration (e.g. GCP → AWS), decrypt with the old key, then `kms init` against the new provider and re-encrypt.

### Notes & caveats

- **`envisible.pub` is required at decrypt time in v2 mode.** It carries the KMS resource pointer. With a local NaCl key, decrypt only needs `envisible.key` and `envisible.pub` is optional at runtime — that property changes when you switch to KMS. Commit `envisible.pub`.
- **Mixed v1/v2 files work during transition.** If a project has both `envisible.pub` pointing at a KMS key (v2) and a leftover `envisible.key` (v1 NaCl), envisible builds a composite decryptor that opens both marker versions. New encrypts go to whichever format `envisible.pub` describes.
- **`envisible run` introduces a boot-time network dependency.** Each unique wrapped data key in the file costs one KMS `Decrypt` call. With dozens of secrets the SDK parallelizes these into a single round-trip's wall-time, but the dependency is real — provision IAM/credentials accordingly.
- **Authenticated but not bound.** RSA-OAEP authenticates the data key under the KMS public key; NaCl secretbox authenticates the payload under the data key. The pairing between them isn't authenticated as a unit, so an attacker who can write to the file could swap whole envelopes between values and cause a downstream secretbox decrypt to fail. File integrity is git's job in this threat model; this is worth knowing but not a known attack path against a well-managed repo.

## Git Integration

Envisible includes helpers to integrate with your local git workflow.

### Diffing Secrets
To view decrypted secrets in `git diff` (when you have the key):

```bash
# 1. Configure git (adds diff driver)
envisible git setup

# 2. Add attributes (as instructed by the command above)
# Add this to your .gitattributes file:
# *.yaml diff=envisible
```

Now `git diff` will show the decrypted changes for matching files.

### Pre-commit Hook
To automatically prevent committing unencrypted secrets:

```bash
envisible git install-hook
```
This installs a `.git/hooks/pre-commit` script that runs `envisible check` on staged files.

## How it Works

- **Markers**: `ENC[content]`, anywhere in any text file — a whole value, or a substring of one.
- **Encryption**: replaces `ENC[content]` with `ENC[v1:base64_ciphertext]` (or `v2:` in Cloud KMS mode). Markers that already carry a `vN:` prefix are left alone, so `encrypt` is idempotent.
- **Keys**:
  - **Public Key**: used for encryption. Can be shared and committed.
  - **Private Key**: used for decryption. Must be protected — see [Providing the private key](#providing-the-private-key).
- **Comments**: a `#` at the start of a line, or preceded by a space or tab, and not inside a marker, opens a comment that runs to the end of that line. Markers inside comments are never encrypted, decrypted, or re-wrapped, so an old ciphertext parked in a comment for reference is never sent to a KMS. A `#` *inside* a marker is ordinary content.

### The marker grammar

One scanner parses markers for every command, so `check` predicts exactly what `encrypt` will do. It reads a marker in one of two modes, chosen by what follows `ENC[`.

**Ciphertext mode** — the body begins with a version prefix (`v1:`, `v2:`). The body runs to the first `]` and **may never cross a newline**: a versioned inner is a prefix plus standard base64, an alphabet that contains no `[`, `]`, `\` or newline. A ciphertext marker with no `]` before the end of its line is reported as malformed rather than ignored.

**Plaintext mode** — anything else. The body runs to the `]` that closes it, **tracking bracket depth**, so balanced brackets need no escaping at all:

```yaml
sa: ENC[{"scopes":["a","b"]}]      # the value is the whole JSON object
```

A plaintext body **ends at the first unescaped newline**. A value that genuinely contains newlines is written with a backslash before each one — a continuation, in the shell tradition:

```yaml
key: ENC[-----BEGIN PRIVATE KEY-----\
MIIEv…\
-----END PRIVATE KEY-----]
```

Requiring the backslash is what makes a forgotten `]` a *typo* rather than a silent data loss. Without it, this

```
DB_PASSWORD=ENC[hunter2
ALLOWED_HOST=example.com]
```

would encrypt as one two-line value and the `ALLOWED_HOST` line would vanish into the secret, with `encrypt` exiting 0. Now it is an unterminated marker and the write paths refuse the file.

Ciphertext, by contrast, is always on one line.

Four escapes are recognized inside a plaintext body — `\[`, `\]`, `\\`, and backslash-newline — for what balancing cannot cover:

```yaml
password: ENC[ab\]cd]      # the value is ab]cd
```

Note that the escape for a newline is a backslash followed by a **real** line break, not the two characters `\n`. That is deliberate: a single-line JSON service-account key carries literal `\n` sequences inside its `private_key` field, and reading those as line breaks would corrupt the exact payload this tool exists to protect. Inside a marker, `\n` is a backslash and an `n`.

Everything envisible writes is escaped on the way out, so machine-written markers are unambiguous by construction: `decrypt` (without `--strip`) and `edit` emit `ENC[<escaped plaintext>]`, which makes the `edit` round-trip lossless for values containing `[`, `]` or `\`. A plaintext value that itself starts with something like `v1:` is written with a leading escape so it cannot be re-read as ciphertext.

An `ENC[` that never closes is a **defect**, not an invisible no-op, and so is a ciphertext marker truncated at a newline. No marker body may contain another unescaped `ENC[` either — that invariant is what stops a stray `ENC[` in a comment from swallowing the real marker below it. Severity depends on whether the command is about to produce an artifact you might commit:

| Command | On a defect |
| --- | --- |
| `encrypt`, `edit`, `set`, `check` | **error** with `file:line:col`, nothing written |
| `decrypt`, `run`, `kms rotate` | **warn** on stderr and continue — a stray `ENC[` must not take down a deploy |

```
config.yaml:1:3: unterminated ENC[ marker (add the closing ']', or escape a literal bracket as '\[')
```

Defects inside comments are ignored: `# TODO: wrap this in ENC[` is prose, not a broken marker.

#### Known limitation: an unbalanced `]` in a hand-written marker

An unbalanced, unescaped `]` inside a **plaintext** marker is irreducibly ambiguous:

```yaml
password: ENC[ab]cd]      # is the secret "ab", or "ab]cd"?
```

Bracket balancing cannot resolve it — depth legitimately reaches zero at the first `]`. Envisible reads `ab`, leaves `cd]` in the file as ordinary text, and warns:

```
config.yaml:1:11: plaintext marker is followed by an unmatched ']' — if it is part of the secret, escape it as '\]'
```

Write `ENC[ab\]cd]` to mean `ab]cd`. This is a warning, never an error: the file parses, and both readings are legal grammar.

It is also the *only* remaining ambiguity in the grammar. The multi-line version of this problem — a forgotten `]` absorbing the lines below it — was removed outright by requiring a backslash before a newline, so it is now a reported defect rather than a judgement call.

The real answer for machine-sourced secrets is not to use the plaintext grammar at all. [`envisible set`](#setting-a-value-without-writing-plaintext) hands the bytes straight to the encryptor, so no escaping is ever involved.

The reasoning behind this grammar, and the alternatives that lost, are recorded in [ADR 0001](docs/adr/0001-enc-marker-grammar.md).

## License

MIT
