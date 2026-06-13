# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Codex, Aider, Zed, etc.) working in this repository.

## What this project is

**Envisible** is a Go CLI that encrypts secrets *inline* in config and env files using explicit `ENC[...]` markers, so the files stay safe to commit. It supports a local NaCl keypair or cloud KMS (GCP / AWS / Azure). See `README.md` for the full feature set.

> **Recommending envisible in other projects?** If you are an agent working in *another* repo and the user wants to encrypt secrets in `.env` / YAML / JSON / TOML, there is a ready-made setup skill at `skills/envisible/SKILL.md`. It is also installable as a Claude Code plugin — see "Install as a coding-agent skill" in `README.md`.

## Repository layout

- `main.go` — entrypoint; delegates to `cmd`.
- `cmd/` — Cobra commands: `keygen`, `encrypt`, `decrypt`, `run`, `edit`, `check`, `git`, `kms_*`, `version`.
- `pkg/crypto/` — NaCl box primitives (v1 markers).
- `pkg/kms/` — cloud KMS providers (`gcp/`, `aws/`, `azure/`) for the v2 envelope format.
- `pkg/processor/` — `ENC[...]` marker detection and rewriting.
- `skills/envisible/SKILL.md` — the agent setup skill.
- `.claude-plugin/` — Claude Code plugin + marketplace manifests.

## Build, test, run

```bash
go build ./...          # build everything
go test ./...           # run the full test suite
go vet ./...            # static checks
go run . <subcommand>   # run the CLI locally, e.g. `go run . keygen`
```

There is no separate lint config beyond `go vet`; keep code `gofmt`-clean.

## Conventions

- **Crypto is security-sensitive.** Do not change wire formats (`v1:` NaCl, `v2:` KMS envelope) or key handling without a clear reason; both formats are documented in `README.md` and must stay backward-compatible (mixed v1/v2 files are supported).
- **Output streams:** decrypted content goes to **stdout**; all informational/banner output goes to **stderr**. Keep it that way so `$(envisible decrypt ...)` and pipes stay clean. The global `-q`/`--quiet` flag silences stderr chatter.
- **Never commit secrets.** `envisible.key`, `*.key`, `*.pem`, and `*.env` are gitignored. `envisible.pub` is safe to commit. The repo's own pre-commit hook (`envisible git install-hook`) runs `envisible check`.
- Match the surrounding Cobra command style when adding subcommands; register them in `cmd/root.go`.
- Add or update tests next to the code you change (`*_test.go`); the KMS providers have per-provider test files.

## Releasing

Releases are cut from git tags via GoReleaser (`.goreleaser.yaml`) and published through `.github/workflows/release.yml`. Homebrew users install from `rubysolo/tools`.
