# Envisible Development Plan

**Goal:** Create an open-source CLI tool to manage encryption/decryption of sensitive data in configuration files (YAML, JSON, TOML, .env) using explicit `ENC[...]` markers, ensuring values can be safely checked into version control.

## Phase 1: Core Foundation & Crypto [Completed]
- [X] **Project Scaffold**: Initialize Go module and Cobra CLI structure.
- [X] **Crypto Primitives**: Implement `pkg/crypto` using NaCl Sealed Box (Curve25519, XSalsa20, Poly1305).
    - [X] Key generation.
    - [X] Encryption (ephemeral sender, static recipient).
    - [X] Decryption (static recipient).
- [X] **Processing Engine**: Implement `pkg/processor`.
    - [X] Regex-based marker detection (`ENC[...]`). *(Superseded in Phase 3 by the marker scanner.)*
    - [X] Logic to skip already encrypted values (`ENC[v1:...]`).
    - [X] Unit tests for processor logic.

## Phase 2: CLI Workflow Implementation [Completed]
- [X] **Key Management**: Implement `keygen` command.
- [X] **Encryption**: Implement `encrypt` command.
    - [X] File reading/writing.
    - [X] `--inplace` modification support.
- [X] **Decryption**: Implement `decrypt` command.
    - [X] Support for stripping markers for final output.
- [X] **Runtime Injection**: Implement `run` command.
    - [X] Decrypt environment variables in memory.
    - [X] Execute child process with injected secrets.
    - [X] Signal propagation to child process.
- [X] **Editor Integration**: Implement `edit` command.
    - [X] Decrypt to secure temp file.
    - [X] Launch `$EDITOR`.
    - [X] Re-encrypt and save on exit.

## Phase 3: Future & Polish [In Progress]
- [X] **UX/UI Overhaul**:
    - [X] **Styling Library**: Integrate a library (e.g., `lipgloss` or `fatih/color`) for consistent, rich terminal output.
    - [X] **Visual Feedback**: Standardize log messages with colors and icons (e.g., ✔ Success, ✖ Error, ℹ Info).
    - [X] **Command Polish**:
        - `check`: Summary table/list of files and statuses.
        - `keygen`: Visual confirmation of key creation.
        - `encrypt`/`decrypt`: Clearer status indicators for processing.
        - `run`: Visual confirmation that the proper environment is being configured before executing the given command
- [X] **Git Integration**: Investigate `git diff` drivers to show plaintext diffs locally (if keys are present).
- [X] **Cloud Key Providers**: KMS-backed v2 envelope format with GCP KMS / AWS KMS / Azure Key Vault. `envisible kms init` / `kms create` / `kms rotate`. v1 (local NaCl) and v2 (KMS) coexist side-by-side; mixed-marker files supported via composite decryptor.
- [X] **Marker Grammar & Scanner** ([plan 01](docs/plans/01-marker-scanner.md), [ADR 0001](docs/adr/0001-enc-marker-grammar.md)): replaced the line-scoped `ENC\[(.*?)\]` regex with a single hand-written scanner used by every command.
    - [X] Bracket-balanced plaintext bodies, `\[` / `\]` / `\\` escapes, multi-line plaintext; ciphertext still single-line and byte-identical to the old parse.
    - [X] Defects (`unterminated`, `malformed ciphertext`) reported with `file:line:col` — an error on `encrypt`/`edit`/`check`, a warning on `decrypt`/`run`/`kms rotate`.
    - [X] Heuristic warnings for the two ambiguous-but-legal shapes: an unmatched trailing `]`, and a plaintext marker that spans lines.
    - [X] Comment regions resolved against marker spans, which also gave `kms rotate` the comment skipping it was missing.
    - [X] Known limitation (an unbalanced unescaped `]` in a hand-written marker) documented in README + ADR rather than silently guessed at.
- [X] **Byte-exact env values** ([plan 02](docs/plans/02-env-value-fidelity.md)): `ExtractEnv` parses structure against the still-encrypted file and decrypts afterwards, so `run` delivers the exact plaintext bytes.
    - [X] No trimming or unquoting of decrypted values; dotenv quoting applies to file text only (exactly one surrounding quote pair).
    - [X] `export ` prefixes, inline `# comments` and CRLF handled; non-assignment lines skipped with a warning instead of in silence.
    - [X] Secret content can no longer add, remove or alter another variable in the child environment.
- [X] **stdin/stdout piping** ([plan 03](docs/plans/03-stdin-stdout.md)): `-` as the target for `encrypt`, `decrypt` and `check`, with a TTY refusal, an `--inplace` rejection, and `<stdin>` in messages. `edit -` and `run -f -` rejected with a pointer at the right command.
- [X] **Private key by value** ([plan 04](docs/plans/04-key-material-by-value.md)): `ENVISIBLE_KEY` carries the key material alongside the path-valued `ENVISIBLE_KEY_PATH`; resolution order is explicit `--key` > `ENVISIBLE_KEY` > `ENVISIBLE_KEY_PATH` > `envisible.key`, resolved in `PersistentPreRunE`. `keygen --print-key` emits the key on stdout (refused on a TTY) and writes no key file; a group/world-readable key file warns.
- [X] **`envisible set`** ([plan 05](docs/plans/05-envisible-set.md)): stdin-only writer that encrypts in memory and splices ciphertext into a .env-shaped file, so the plaintext never enters the file, the disk, or argv. Works with `envisible.pub` alone. Layout, comments and file mode preserved; atomic write; `--from-json` / `--from-env` / `--dry-run` / `--if-changed` / `--raw` / `--allow-empty`; empty stdin and non-dotenv targets refused. Churn (randomized encryption) and the two-sources-of-truth consequence documented, not discovered.
- [ ] **IDE Integration**: VS Code plugin for auto-encrypt on save (Deferred).
- [X] **Pre-commit Hooks**: Helper script to ensure no plaintext `ENC[...]` markers are committed.
- [X] **Release**: Setup GitHub Actions for cross-platform binary builds.
- [X] **Verification**: Command to safely verify that a file is encrypted with the expected key.

Detailed designs for the five changes above live in [`docs/plans/`](docs/plans/); durable decisions with real alternatives are recorded in [`docs/adr/`](docs/adr/).
