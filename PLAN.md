# Envisible Development Plan

**Goal:** Create an open-source CLI tool to manage encryption/decryption of sensitive data in configuration files (YAML, JSON, TOML, .env) using explicit `ENC[...]` markers, ensuring values can be safely checked into version control.

## Phase 1: Core Foundation & Crypto [Completed]
- [X] **Project Scaffold**: Initialize Go module and Cobra CLI structure.
- [X] **Crypto Primitives**: Implement `pkg/crypto` using NaCl Sealed Box (Curve25519, XSalsa20, Poly1305).
    - [X] Key generation.
    - [X] Encryption (ephemeral sender, static recipient).
    - [X] Decryption (static recipient).
- [X] **Processing Engine**: Implement `pkg/processor`.
    - [X] Regex-based marker detection (`ENC[...]`).
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
- [X] **Git Integration**: Investigate `git diff` drivers to show plaintext diffs locally (if keys are present).
- [ ] **Cloud Key Providers**: Abstract `pkg/crypto` to support AWS KMS / GCP KMS / Vault (Deferred).
- [ ] **IDE Integration**: VS Code plugin for auto-encrypt on save (Deferred).
- [X] **Pre-commit Hooks**: Helper script to ensure no plaintext `ENC[...]` markers are committed.
- [X] **Release**: Setup GitHub Actions for cross-platform binary builds.
- [ ] **Verification**: Command to safely verify that a file is encrypted with the expected key.
