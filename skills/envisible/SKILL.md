---
name: envisible
description: Set up envisible to manage encrypted secrets in a project's config and env files. Use when the user wants to encrypt secrets in a repo, mentions envisible, wants to replace plaintext credentials in `.env` / yaml / json / toml with `ENC[...]` markers, or needs to migrate an existing project to encrypted-at-rest secrets.
---

# Envisible setup

You are integrating [envisible](https://github.com/rubysolo/envisible) into a project. Envisible encrypts inline `ENC[...]` markers in any text file (`.env`, yaml, json, toml, ini, dotenv-style) and decrypts them at runtime — either by injecting into the environment for a child process (`envisible run -- <cmd>`) or by emitting plaintext for code/build pipelines (`envisible decrypt`).

This skill walks the agent through a clean setup. Do not skip discovery — half the work is finding the secrets that are already there.

---

## Mental model

- **Markers**: anywhere in a text file, `ENC[plaintext]` marks a value to encrypt. After encryption, it becomes `ENC[v1:base64...]` (local NaCl keypair) or `ENC[v2:base64...]` (cloud KMS envelope). Surrounding text is preserved, so partial-value encryption works: `postgres://user:ENC[v1:...]@host/db`.
- **Two key modes** — pick one per project:
  - **Local NaCl keypair** — `envisible.pub` (commit) + `envisible.key` (NEVER commit). Anyone with the private key can decrypt. Zero infra, no network at runtime.
  - **Cloud KMS** (GCP / AWS / Azure) — `envisible.pub` carries both the public key and a resource pointer. The private half stays in KMS. Decrypt-time calls `Decrypt` via the cloud SDK's default credential chain. **Commit `envisible.pub`.**
- **Encryption needs only the public key**; decryption needs the private key (NaCl mode) or KMS access (cloud mode). Plan key distribution accordingly.

---

## Step 1 — Discover the project

Before changing anything, run these in parallel:

1. **Confirm envisible is installed and KMS-capable**: `which envisible`, `envisible version`, and `envisible kms --help`.
  - If `kms` is unavailable, upgrade to a KMS-capable release before choosing KMS mode.
  - Do this check anywhere envisible is installed, not just on your laptop (Docker images, CI runners, release/runtime environments).
  - If missing, install:
   - `go install github.com/rubysolo/envisible@latest` (needs Go)
   - or `brew tap rubysolo/tools && brew install envisible` (macOS/Linux)
   - or download a release from https://github.com/rubysolo/envisible/releases

2. **Find candidate files** for secrets:
   ```bash
   # env-style files
   find . -name '.env*' -not -path './node_modules/*' -not -path './.git/*'
   # configs that often hold credentials
   find . \( -name '*.yaml' -o -name '*.yml' -o -name '*.json' -o -name '*.toml' \) \
     -not -path './node_modules/*' -not -path './.git/*' -not -path './vendor/*'
   ```

3. **Scan for plaintext-looking secrets** — `grep -RInE '(password|secret|token|api[_-]?key|aws_|private[_-]?key)\s*[:=]' --include='*.{env,yaml,yml,json,toml,ini}' .` — and surface them to the user for triage before you encrypt anything.
4. **Check `.gitignore`** for `envisible.key`, `*.key`, `.env`. Note what's already protected.
5. **Read `package.json` / `Makefile` / `Procfile` / `docker-compose.yml` / CI workflow files** — these are where the runtime command lives, and they're what you'll wrap with `envisible run`.

Report findings to the user with a short table: which files have secrets, which are gitignored, what's already encrypted (look for `ENC[v1:` or `ENC[v2:`). **Do not auto-encrypt without confirmation.**

---

## Step 2 — Choose a key mode

Ask the user, framing the tradeoff:

- **Local keypair** if: solo / small team, no cloud account, simple infra, OK with manually getting `envisible.key` to each developer and to production.
- **Cloud KMS** if: team has GCP/AWS/Azure already, wants no shared private key file, wants per-identity audit logs and rotation, OK adding a network call at boot.

If they're unsure, recommend local for now — migration to KMS later is mechanical (`decrypt` → `kms init` → `encrypt` again).

---

## Step 3a — Set up local keypair

```bash
envisible keygen           # writes envisible.pub and envisible.key
```

Then:

1. **Add `envisible.key` to `.gitignore`** if not already covered. If `*.key` is already ignored, you're good — but verify with `git check-ignore -v envisible.key`.
2. **Commit `envisible.pub`** — it's the encryption key and is safe to share.
3. **Plan distribution of `envisible.key`** — out-of-band channel (password manager, 1Password vault, secure file share). Never paste into chat / PR / ticketing.

## Step 3b — Set up cloud KMS

Pick the provider the user already authenticates with. The three flows differ only in the resource string.

Before proceeding, re-check the installed binary supports KMS commands:

```bash
envisible version
envisible kms --help
```

If `kms` is unavailable, stop and upgrade envisible first.

**GCP**:
```bash
gcloud kms keyrings create my-app --location us
gcloud kms keys create my-key \
  --keyring my-app --location us \
  --purpose asymmetric-encryption \
  --default-algorithm rsa-decrypt-oaep-2048-sha256
# Important: envisible uses Application Default Credentials (ADC),
# not only gcloud CLI login state.
gcloud auth application-default login
envisible kms init --provider gcp \
  --resource projects/PROJECT/locations/us/keyRings/my-app/cryptoKeys/my-key/cryptoKeyVersions/1
```

Important for GCP: `envisible kms init` and KMS-backed decrypts use ADC. `gcloud auth login`
alone is often not enough for local runs.

**AWS**:
```bash
aws kms create-key --key-spec RSA_2048 --key-usage ENCRYPT_DECRYPT \
  --description "envisible for <project>"
# capture KeyId from the JSON
aws kms create-alias --alias-name alias/my-app --target-key-id <KEY_ID>
envisible kms init --provider aws \
  --resource arn:aws:kms:us-east-1:ACCOUNT:key/<KEY_ID>
```

**Azure**:
```bash
az keyvault key create --vault-name myvault --name my-key --kty RSA --size 2048
envisible kms init --provider azure \
  --resource https://myvault.vault.azure.net/keys/my-key/<VERSION>
```

If the user already has a key provisioned (Terraform, console), skip the create step and run `envisible kms init` straight against the existing resource.

If the project already manages cloud infrastructure with Terraform/Terragrunt, prefer Terraform
to create and IAM-bind the KMS key and use `envisible kms init` only to materialize `envisible.pub`.
Avoid mixing `envisible kms create` with Terraform-managed infrastructure long-term.

Then:
1. **Commit `envisible.pub`** — required at decrypt time in v2 mode (it carries the KMS pointer). This is non-negotiable; the file is safe.
2. **Wire runtime correctly for Docker/Cloud Run KMS mode**:
  - Commit `envisible.pub` into the image/repo.
  - Do not inject `envisible.key` or `ENVISIBLE_KEY`.
  - Start with `--pub` (not `--key`) and the target env file, for example:
    `envisible run --pub /app/envisible.pub -f /app/.env -- ./myapp`
  - Ensure the runtime identity can decrypt.
3. **Verify IAM/roles** for every identity that needs to decrypt (dev laptops, CI, production):
  - For deployed containers, the critical identity is the runtime identity (for example, the Cloud Run service account), not only the CI/deploy identity.
  - GCP: `roles/cloudkms.cryptoKeyDecrypter` on the crypto key
   - AWS: `kms:Decrypt` (and `kms:GetPublicKey` for `kms init`)
   - Azure: `keys/decrypt` (and `keys/get` for init)
4. **Note on GCP IAM scope**: `envisible.pub` may reference a specific `cryptoKeyVersion`, but IAM bindings are typically granted on the parent `cryptoKey` resource.
5. **Do not add `envisible.key` to `.gitignore` for any special reason** — it shouldn't exist in KMS mode. If it does, delete it.

---

## Step 4 — Mark and encrypt the secrets

For each plaintext secret the user confirmed in Step 1:

1. **Wrap it in `ENC[...]`** with the plaintext inside. Partial-value encryption is fine:
   ```yaml
   # before
   database:
     url: postgres://user:hunter2@db.internal:5432/app

   # after, before encryption
   database:
     url: postgres://user:ENC[hunter2]@db.internal:5432/app
   ```

2. **Encrypt in place**:
   ```bash
   envisible encrypt -i path/to/file.yaml
   envisible encrypt -i .env
   ```

3. **Verify** — grep the file for `ENC[..]` markers and confirm everything is encrypted; the file should no longer contain plaintext. Also run `envisible check path/to/file` — it exits non-zero if any `ENC[...]` marker is still unencrypted (i.e. doesn't start with `v1:` or `v2:`).

4. **Test round-trip**:
   ```bash
   envisible decrypt --strip path/to/file.yaml | diff - <original-plaintext-version>
   ```
   (or just spot-check `envisible decrypt path/to/file.yaml | head`).

5. **Integrate with existing lint/static analysis:**

If the project already has a lint or static analysis command (e.g. `make lint`, `npm run lint`), wire `envisible
check` into that command so secret checks always run with the rest of your code quality gates.  This ensures
unencrypted secrets are caught early and consistently.  If there isn't an existing lint step, consider adding a new
one that runs `envisible check` against all candidate files.

---

## Step 5 — Wire decryption into the runtime

This is project-specific. Common patterns:

### Env-style files (`.env`)
For apps that read env vars at startup, prefix the plaintext launch command with `envisible run -e <envfile> --`:

```bash
# before
node server.js
# after
envisible run -e .env -- node server.js
```

In `package.json`:
```json
{
  "scripts": {
    "start": "envisible run -e .env -- node server.js",
    "dev": "envisible run -e .env.development -- nodemon server.js"
  }
}
```

In `Procfile`:
```
web: envisible run -e .env -- gunicorn app:app
```

In a `Makefile`:
```makefile
run:
	envisible run -e .env -- ./bin/myapp
```

In `docker-compose.yml`, mount the key and prefix the command:
```yaml
services:
  app:
    image: myapp:latest
    volumes:
      - ./envisible.key:/app/envisible.key:ro
      - ./envisible.pub:/app/envisible.pub:ro
      - ./.env:/app/.env:ro
    command: envisible run -e .env -- ./myapp
```

### Config files (yaml / json / toml)
The app reads these directly — `envisible run` only injects env vars, so emit decrypted config at boot or build:

- **Boot-time**: shell out and write to a temp file:
  ```bash
  envisible decrypt --strip config.yaml > /tmp/config.yaml && ./myapp --config /tmp/config.yaml
  ```
- **Build-time** (immutable artifacts): decrypt during the build into the image. Acceptable only if the image itself is treated as a secret (private registry, restricted pulls).
- **In-process** (preferred for libraries): shell out to `envisible decrypt --strip` once at startup and parse the result, instead of teaching every config-loader about `ENC[...]`.

Envisible writes decrypted content to stdout and all informational banners (`ℹ Loading…`, `✔ Starting…`, KMS summaries) to stderr, so `VAR=$(envisible decrypt --strip f)` and `envisible decrypt … | jq` are clean by default. Pass `-q` only when you also want to silence the stderr chatter (cleaner CI logs, quieter interactive sessions); it's a global flag that works on every subcommand.

### Dockerfile
Don't bake `envisible.key` into the image layers. Either:
- Mount it at runtime (Compose / Kubernetes secret / ECS task secret).
- For KMS mode, give the container an IAM role / workload identity — no key file needed.

---

## Step 6 — Git integration

Both are optional but worth offering:

```bash
envisible git install-hook     # pre-commit hook that runs `envisible check`
envisible git setup            # configures a git diff driver
```

For the diff driver to apply, add to `.gitattributes`:
```
*.env    diff=envisible
*.yaml   diff=envisible
config/*.json diff=envisible
```

After this, `git diff` shows decrypted changes locally (only for people with the key), while the stored blobs remain encrypted.

---

## Step 7 — CI/CD

In CI, the agent typically needs to **decrypt at runtime** (for tests / deploys) but not encrypt. Two patterns:

### Local-keypair CI
Store `envisible.key` as a CI secret. Example for GitHub Actions:
```yaml
- name: Restore envisible key
  run: echo "${{ secrets.ENVISIBLE_KEY }}" > envisible.key && chmod 600 envisible.key
- name: Run tests
  run: envisible run -e .env.test -- npm test
```

Set the secret to the base64-encoded contents or the raw key — match what your runner can store. Avoid printing the key.

### KMS CI
Authenticate the runner to the cloud (workload identity federation for GitHub Actions → GCP/AWS, OIDC, etc.), then `envisible run` just works:
```yaml
- uses: google-github-actions/auth@v2
  with:
    workload_identity_provider: ...
    service_account: ...
- run: envisible run -e .env.test -- npm test
```

In both cases, add a **lint job** in CI that runs `envisible check` against all candidate files so unencrypted markers fail PRs:


```yaml
- name: Check for unencrypted secrets
  run: |
    for f in .env .env.production config/*.yaml; do
      [ -e "$f" ] || continue
      envisible check "$f"
    done
```

---

## Step 8 — Document for the team

Add a short section to the project README (or a `SECRETS.md`) covering:

1. **Key mode** (local vs which KMS provider/resource).
2. **How a new developer gets bootstrapped**:
   - Local mode: *"Ask <name> for `envisible.key`; drop it in the repo root; do not commit it."*
   - KMS mode: *"Run `gcloud auth application-default login` (or equivalent). Confirm decrypt works with `envisible decrypt .env | head`."*
3. **How to add a new secret**: edit the file, wrap the value in `ENC[plaintext]`, run `envisible encrypt -i <file>`, commit.
4. **How to edit an existing secret**: `envisible edit <file>` — opens decrypted in `$EDITOR`, re-encrypts on save.
5. **Rotation**: when, who, and the command (`envisible kms rotate --to <new-resource> file1 file2 ...` for KMS; for local, generate new keys and re-encrypt every file).

---

## Verification checklist (do this before reporting done)

- [ ] No plaintext form of any encrypted secret remains in the repo. Grep for old values.
- [ ] `envisible check <file>` passes on every modified file.
- [ ] `envisible run -e .env -- env | grep <KEY>` prints the expected decrypted value.
- [ ] `git status` shows `envisible.pub` staged and `envisible.key` **not** present (local mode) — check `git check-ignore -v envisible.key`.
- [ ] The app's normal start command, prefixed with `envisible run`, boots successfully.
- [ ] CI changes pass on a draft branch before merging.

---

## Common pitfalls

- **Plaintext leaked in git history.** Encrypting now doesn't remove a value committed earlier. If the secret was ever in a public or shared history, rotate the underlying credential (DB password, API token) — don't just encrypt the leaked one.
- **Wrong file got `-i`.** `envisible encrypt -i` overwrites; back up or stage first so a mistake is reversible (`git checkout -- file`).
- **`ENC[]` marker inside a string that gets templated/escaped.** YAML anchors, JSON inside a string, shell `$()`... encryption operates on raw bytes between the brackets, so triple-check anything not literal.
- **CI can't decrypt** in KMS mode → the runner identity is missing the role. Test locally with `gcloud auth print-access-token` / `aws sts get-caller-identity` to confirm credential plumbing before blaming envisible.
- **GCP local auth confusion**: `gcloud auth login` and ADC are not the same. If local KMS calls fail, run `gcloud auth application-default login` and retry.
- **KMS mode without committing `envisible.pub`.** Decryption fails with no obvious error — the resource pointer lives in that file. Commit it.
- **Mixing v1 and v2 in the same file** works during migration (envisible builds a composite decryptor when both `envisible.key` and a v2-flagged `envisible.pub` exist), but don't leave it that way long-term. Pick a mode and re-encrypt.
- **Banner mixed with the child's stderr under `envisible run`.** The banner goes to stderr, which is the right place — but if the child also writes structured stderr (e.g., JSON logs another tool parses), the banner will interleave. Pass `-q` to suppress it in that case. (Stdout is clean by default; capturing or piping decrypted values needs no flag.)

---

## Reference: commands the agent will use

| Goal | Command |
| --- | --- |
| Install (Go) | `go install github.com/rubysolo/envisible@latest` |
| Install (Homebrew) | `brew tap rubysolo/tools && brew install envisible` |
| Generate local keypair | `envisible keygen` |
| Init from existing KMS key | `envisible kms init --provider {gcp,aws,azure} --resource <ref>` |
| Provision KMS key | `envisible kms create --provider gcp --project P --location L --keyring R --name K` |
| Encrypt in place | `envisible encrypt -i <file>` |
| Decrypt to stdout | `envisible decrypt <file>` |
| Decrypt to stdout, no markers | `envisible decrypt --strip <file>` |
| Silence informational banner on stderr | `envisible -q <subcommand> ...` |
| Edit in `$EDITOR` (decrypt → edit → encrypt) | `envisible edit <file>` |
| Run with decrypted env injected | `envisible run -e <envfile> -- <cmd> <args...>` |
| CI lint for unencrypted markers | `for f in <files>; do envisible check "$f"; done` |
| Install pre-commit hook | `envisible git install-hook` |
| Set up git diff driver | `envisible git setup` |
| Rotate KMS version | `envisible kms rotate --to <new-resource> <file>...` |

For full flag details: `envisible <command> --help`. README at https://github.com/rubysolo/envisible.
