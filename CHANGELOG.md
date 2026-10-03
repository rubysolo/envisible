# Changelog

All notable changes to envisible are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version is `0.x`,
a release may change behavior; anything that does is listed under **Changed** or
**Removed** and marked **Breaking**.

Dates are the day the release was published on GitHub (UTC).

The two ciphertext formats, `ENC[v1:...]` (local NaCl keypair) and `ENC[v2:...]` (cloud KMS
envelope), have not changed since they were introduced. A file encrypted by any release
decrypts with every later one.

## [Unreleased]

## [0.0.8] - 2026-10-03

### Added

- **`envisible set`** writes a secret into a file from stdin, so the plaintext never exists
  in the file or in a command-line argument. It needs only the public key. Supports single
  values, `--from-env` and `--from-json` payloads, `--dry-run` and `--if-changed`.
- **`ENVISIBLE_KEY`** supplies the private key by value, so it can come straight from a
  secret store with no key file on disk. Order of precedence: an explicit `--key`, then
  `ENVISIBLE_KEY`, then `ENVISIBLE_KEY_PATH`, then `envisible.key`.
- **`keygen --print-key`** writes the new private key to stdout and creates no
  `envisible.key`. It refuses to print to a terminal.
- **`keygen --force`** replaces existing key files.
- **`run --pass-key`** leaves an inherited `ENVISIBLE_KEY` in the command's environment, for
  a command that calls envisible itself.
- **`-` as a file argument** for `encrypt`, `decrypt` and `check` reads from stdin, so a
  value can be piped through without a plaintext temp file. `-f -` works the same way.
- **Escapes inside a plaintext marker**: `\]`, `\[` and `\\`, plus a backslash before a line
  break to continue a value onto the next line. A secret containing `]` or newlines can now
  be written and round-trips exactly.
- A warning when the private key file is readable by group or others.
- Marker problems are reported with file, line and column. `encrypt`, `edit` and `set`
  refuse to write a file with a malformed marker, and `check` fails on one; `decrypt`, `run`
  and `kms rotate` warn and continue.

### Changed

- **Breaking:** `keygen` refuses to run when `envisible.pub` or `envisible.key` already
  exists, and says so. A new keypair cannot decrypt anything encrypted with the old one, and
  `keygen` used to replace both files silently. Pass `--force` to replace them. With
  `--print-key`, only the public key path is checked.
- **Breaking:** `run`, `edit` and the `git` helpers no longer pass `ENVISIBLE_KEY` to the
  programs they start. The child gets the decrypted values, not the key. Use
  `run --pass-key` to opt back in.
- **Breaking:** `run` hands the command exactly the bytes that were encrypted. Previously
  the decrypted file was parsed again as dotenv, which trimmed whitespace and stripped
  quotes from secret values.
- **Breaking:** a plaintext marker ends at the first unescaped newline. A marker with a
  forgotten `]` is now an error instead of silently absorbing the following lines.
- In-place writes (`encrypt -i`, `decrypt -i`, `edit`, `set`, `kms rotate`) are atomic and
  follow symlinks: the link stays a link and its target is updated. A dangling link is an
  error.
- `kms rotate` skips markers inside comments, as `encrypt` and `decrypt` already did, so an
  old ciphertext kept in a comment is never sent to a KMS.
- AWS KMS takes the region from the key's ARN. Decrypt no longer depends on `AWS_REGION`
  matching the key's region, or being set at all. A bare key ID or alias name still uses
  the standard AWS region settings.

### Fixed

- **Security:** part of a secret could stay in the file as plaintext while `check` and the
  pre-commit hook reported it clean. `ENC[ab]cd]` encrypted only `ab` and left `cd]` in the
  clear. A stray `ENC[` in a comment could also hide the real marker below it, so `check`
  passed on a plaintext value and `kms rotate` reported success having rotated nothing.
- **Security:** a decrypted value containing a newline followed by `KEY=value` injected that
  extra variable into the environment of the command started by `run`.
- A value containing `]`, such as a JSON array, was cut at the first bracket and corrupted.
- A multi-line value, such as a PEM key, matched no marker and was written back unencrypted.
- A secret whose text began with `v1:` or `v2:` was misread as ciphertext, and `edit` wrote
  it back in the clear.
- `version` and the `git setup` progress message now respect the output rule: results on
  stdout, informational messages on stderr.
- `run` forwards every `SIGINT` and `SIGTERM` to the command for as long as it runs.
  Previously only the first was forwarded and later ones were swallowed, so a command that
  did not exit on the first signal could only be stopped with `SIGKILL`. A signal arriving
  while the command was starting could also be lost.
- `keygen` writes both key files or neither. Previously it wrote `envisible.pub` first, so a
  failed private-key write (an unwritable `--key` path, a failed `--print-key` write to
  stdout) left a new public key with no matching private key. Run over an existing pair,
  that replaced the public key and kept the old private key, so values encrypted afterwards
  could not be decrypted.
- `keygen` always creates the private key file with mode `0600`, including when it replaces
  an existing key file that had looser permissions.
- `kms rotate` rejects a `v2` value that is too short to decrypt, and aborts. Previously a
  value truncated inside its nonce or payload was re-wrapped and counted as rotated.

## [0.0.7] - 2026-07-10

### Added

- **`-q` / `--quiet`** global flag silences informational output.
- Claude Code plugin and marketplace manifests, so the setup skill installs with
  `/plugin marketplace add rubysolo/envisible`.
- `AGENTS.md`, a project guide for AI coding agents.
- `LICENSE` file (MIT). The README already declared the license.
- README: a "why use envisible" introduction and a comparison with similar tools.

### Changed

- **Breaking:** informational output (banners, progress, KMS summaries) moved from stdout to
  stderr. Stdout now carries only decrypted content, so `$(envisible decrypt ...)` and pipes
  are clean. Scripts that parsed the banner from stdout need updating.

### Fixed

- `run` no longer treats the child command's flags as its own. `envisible run ruby -e ...`
  failed with an unknown-flag error unless `--` was used. envisible's own flags now go
  before the command, and `--` is optional.

## [0.0.6] - 2026-05-25

### Changed

- Markers inside a comment are left alone by `encrypt` and `decrypt`. A `#` starts a comment
  at the start of a line or after whitespace, unless it is inside a marker. An old value
  kept in a comment for reference is no longer re-encrypted.
- Setup skill expanded.

## [0.0.5] - 2026-05-19

### Added

- **Cloud KMS support** for Google Cloud KMS, AWS KMS and Azure Key Vault. The private key
  stays in the cloud; `envisible.pub` holds the public key and a pointer to it.
  - `kms init` registers an existing key.
  - `kms create` provisions a new one.
  - `kms rotate` re-wraps every value for a new key version without re-encrypting the
    payloads.
- **`ENC[v2:...]` envelope format.** Each value is sealed locally with a random data key,
  and the data key is wrapped with the KMS public key (RSA-OAEP-SHA256). Encrypting needs no
  network access.
- Files with both `v1` and `v2` markers decrypt in one pass, so a project can migrate
  gradually.
- `check` detects malformed markers (bad encoding, truncated ciphertext) offline, in addition
  to unencrypted ones.
- An agent skill, `skills/envisible/SKILL.md`, that sets envisible up in another project.

## [0.0.4] - 2026-02-05

### Changed

- **Breaking for download scripts:** release archives are named
  `envisible_<os>_<arch>` with Go's lowercase names, for example
  `envisible_linux_amd64.tar.gz` (previously `envisible_Linux_x86_64`). This matches Docker's
  `TARGETOS` and `TARGETARCH` build arguments. Windows archives are `.zip`.

## [0.0.3] - 2026-01-27

### Added

- **`-f` / `--file`** global flag and the **`ENVISIBLE_FILE`** environment variable select
  the file to operate on, for every command. The default is still `.env`.
- Short forms `-k` for `--key` and `-p` for `--pub`.

### Removed

- **Breaking:** `run -e` / `--env`. Use `-f` / `--file` or `ENVISIBLE_FILE` instead.

## [0.0.2] - 2026-01-24

### Added

- **`check --verify`** (`-v`) decrypts every marker with the private key to confirm each
  value is valid, not just encrypted.
- Homebrew install instructions (`brew tap rubysolo/tools`).
- CI runs the tests on the two most recent Go versions.

### Changed

- Styled, colored terminal output for status, warnings and errors.

## [0.0.1] - 2026-01-23

First release.

### Added

- Inline encryption of `ENC[...]` markers in config and env files with a local NaCl keypair
  (Curve25519, XSalsa20-Poly1305), in the `ENC[v1:...]` format.
- Commands:
  - `keygen` generates `envisible.pub` and `envisible.key`.
  - `encrypt` and `decrypt`, with `-i` to modify the file in place and `decrypt --strip` to
    output plain values without markers.
  - `edit` opens a decrypted copy in `$EDITOR` and re-encrypts it on save.
  - `run` starts a command with the decrypted values in its environment.
  - `check` fails if a file contains an unencrypted marker.
  - `git setup` configures a diff driver that shows decrypted changes, and
    `git install-hook` installs a pre-commit hook that runs `check`.
  - `version`.
- `--key` and `--pub` flags, and the `ENVISIBLE_KEY_PATH` and `ENVISIBLE_PUB_PATH`
  environment variables, to locate the key files.
- Release binaries for Linux, macOS and Windows on amd64 and arm64, and a Homebrew formula.

[Unreleased]: https://github.com/rubysolo/envisible/compare/v0.0.8...HEAD
[0.0.8]: https://github.com/rubysolo/envisible/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/rubysolo/envisible/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/rubysolo/envisible/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/rubysolo/envisible/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/rubysolo/envisible/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/rubysolo/envisible/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/rubysolo/envisible/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/rubysolo/envisible/releases/tag/v0.0.1
