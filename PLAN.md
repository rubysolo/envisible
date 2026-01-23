# Envisible Development Plan

**Goal:** Create an open-source CLI tool to manage encryption/decryption of sensitive data in configuration files (YAML, JSON, TOML, .env) using explicit `ENC[...]` markers, ensuring values can be safely checked into version control.

## Phase 1: Core Foundation & Crypto [Completed]
- [x] **Project Scaffold**: Initialize Go module and Cobra CLI structure.
- [x] **Crypto Primitives**: Implement `pkg/crypto` using NaCl Sealed Box (Curve25519, XSalsa20, Poly1305).
    - [x] Key generation.
    - [x] Encryption (ephemeral sender, static recipient).
    - [x] Decryption (static recipient).
- [x] **Processing Engine**: Implement `pkg/processor`.
    - [x] Regex-based marker detection (`ENC[...]`).
    - [x] Logic to skip already encrypted values (`ENC[v1:...]`).
    - [x] Unit tests for processor logic.

## Phase 2: CLI Workflow Implementation [Completed]
- [x] **Key Management**: Implement `keygen` command.
- [x] **Encryption**: Implement `encrypt` command.
    - [x] File reading/writing.
    - [x] `--inplace` modification support.
- [x] **Decryption**: Implement `decrypt` command.
    - [x] Support for stripping markers for final output.
- [x] **Runtime Injection**: Implement `run` command.
    - [x] Decrypt environment variables in memory.
    - [x] Execute child process with injected secrets.
    - [x] Signal propagation to child process.
- [x] **Editor Integration**: Implement `edit` command.
    - [x] Decrypt to secure temp file.
    - [x] Launch `$EDITOR`.
    - [x] Re-encrypt and save on exit.

## Phase 3: Future & Polish [Pending]
- [x] **Git Integration**: Investigate `git diff` drivers to show plaintext diffs locally (if keys are present).
- [ ] **Cloud Key Providers**: Abstract `pkg/crypto` to support AWS KMS / GCP KMS / Vault (Deferred).
- [ ] **IDE Integration**: VS Code plugin for auto-encrypt on save (Deferred).
- [x] **Pre-commit Hooks**: Helper script to ensure no plaintext `ENC[...]` markers are committed.
- [ ] **Release**: Setup GitHub Actions for cross-platform binary builds.
