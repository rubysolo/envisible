# Envisible

**Envisible** is a CLI tool to safely manage encrypted secrets within your configuration files (YAML, JSON, TOML, .env, etc.) using explicit `ENC[...]` markers. It uses NaCl Box (Curve25519, XSalsa20, Poly1305) for strong asymmetric encryption.

## Installation

```bash
go install github.com/rubysolo/envisible@latest
```

or via homebrew:

```bash
brew tap rubysolo/tools
brew install envisible
```

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
