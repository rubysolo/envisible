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
go test -race -shuffle=on ./...   # what CI runs: race detector, random test order
go vet ./...            # static checks
go run . <subcommand>   # run the CLI locally, e.g. `go run . keygen`
```

There is no separate lint config beyond `go vet`; keep code `gofmt`-clean.

## Conventions

- **Crypto is security-sensitive.** Do not change wire formats (`v1:` NaCl, `v2:` KMS envelope) or key handling without a clear reason; both formats are documented in `README.md` and must stay backward-compatible (mixed v1/v2 files are supported).
- **Wire-format exemplars** live in `pkg/processor/testdata/` (ciphertext written by `v0.0.1` and `v0.0.5`). A failing exemplar test means the wire format changed; fix the code, never the exemplar. Add a new exemplar only alongside a new format version.
- **Output streams:** decrypted content goes to **stdout**; all informational/banner output goes to **stderr**. Keep it that way so `$(envisible decrypt ...)` and pipes stay clean. The global `-q`/`--quiet` flag silences stderr chatter.
- **Never commit secrets.** `envisible.key`, `*.key`, `*.pem`, and `*.env` are gitignored. The only exceptions are the fixed, test-only exemplar keys under `pkg/processor/testdata/`. `envisible.pub` is safe to commit. The repo's own pre-commit hook (`envisible git install-hook`) runs `envisible check`.
- Match the surrounding Cobra command style when adding subcommands; register them in `cmd/root.go`.
- Add or update tests next to the code you change (`*_test.go`); the KMS providers have per-provider test files.
- **Documented commands are tested.** `TestDocumentedCommandsExist` (`cmd/docs_test.go`) resolves every `envisible ...` command in `README.md`, `AGENTS.md` and `skills/envisible/SKILL.md` against the real command tree. Removing or renaming a command or flag fails that test until the docs are updated; `CHANGELOG.md` is exempt because it describes old releases.

## Releasing

Run `scripts/release vX.Y.Z` from a clean `main` that is level with `origin/main`. `scripts/release --dry-run vX.Y.Z` runs every check and changes nothing. The script:

1. Checks the working tree, that the tag is unused and newer than the latest, and that `go.mod` is tidy.
2. Checks the Homebrew tap token by running the `Release preflight` workflow on GitHub. The token is a repository secret (`HOMEBREW_TAP_GITHUB_TOKEN`) and cannot be read locally. An expired token failed the v0.0.8 release after it was already published; this check and the same one at the start of the release workflow exist to stop that.
3. Moves the `[Unreleased]` section of `CHANGELOG.md` under the new version (`scripts/changelog-release`), commits and pushes it.
4. Waits for the Test workflow to pass on that commit.
5. Creates and pushes the annotated tag. That starts `.github/workflows/release.yml`, which runs GoReleaser (`.goreleaser.yaml`): binaries for Linux, macOS and Windows, the GitHub release, and the Homebrew formula in `rubysolo/homebrew-tools` (users install from `rubysolo/tools`).
6. Waits for the release workflow and confirms the release has its archives and the tap points at the new version.

The GitHub release notes are that version's section of `CHANGELOG.md` (`scripts/release-notes`), so write the changelog for readers. Add user-visible changes to `[Unreleased]` in the same change that makes them; the release script refuses to run when it is empty.

Do not re-run a release workflow that failed after publishing: GoReleaser would try to upload archives the release already has. Fix the cause and finish the remaining step by hand, or delete the release and tag and start again.
