# Envisible

**Envisible** is a CLI tool to safely manage encrypted secrets within your configuration files (YAML, JSON, TOML, .env, etc.) using explicit `ENC[...]` markers.

Your secrets normally live somewhere your config doesn't: a separate secret store, a `.env` that's gitignored and passed around by hand, a wiki page that drifts out of date. Envisible keeps the secret *next to the setting it belongs to* and encrypts only that value, so the file stays safe to commit. That means your configuration is versioned alongside your code — every change to a secret shows up in `git history`, code review, and rollbacks like any other line. Deploys get simpler too: there's one source of truth in the repo and nothing to sync at release time, since values are decrypted on the fly at runtime (injected into the environment with `envisible run`, or emitted to stdout for build pipelines). Start with a local keypair and no infrastructure; move to cloud KMS when you want managed keys and audit logs — the file format doesn't change.

Two key-management modes are supported:

- **Local keypair** (default) — a NaCl Box keypair (Curve25519 + XSalsa20-Poly1305) generated with `envisible keygen`. Simple, no network, no cost. The private key file (`envisible.key`) must be kept off-repo and provisioned to anything that needs to decrypt.
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

- **Markers**: Look for `ENC[content]`.
- **Encryption**: Replaces `ENC[content]` with `ENC[v1:base64_ciphertext]`.
- **Keys**:
  - **Public Key**: Used for encryption. Can be shared.
  - **Private Key**: Used for decryption. Must be protected.

## License

MIT
