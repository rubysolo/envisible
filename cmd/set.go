package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rubysolo/envisible/pkg/processor"
	"github.com/rubysolo/envisible/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	setFromJSON   bool
	setFromEnv    bool
	setDryRun     bool
	setIfChanged  bool
	setRaw        bool
	setAllowEmpty bool
)

// newFileMode is the mode a `set`-created file gets. It matches what
// `encrypt -i` writes, so a file's permissions do not depend on which command
// happened to create it.
const newFileMode os.FileMode = 0644

// pair is one key and the plaintext destined for it. The value is held for
// exactly as long as it takes to encrypt it, and is never rendered anywhere:
// every message this command prints names keys only.
type pair struct {
	key   string
	value string
}

// outcome is what happened (or would happen) to one key.
type outcome struct {
	key    string
	action processor.Action
}

var setCmd = &cobra.Command{
	Use:   "set [file] KEY -",
	Short: "Encrypt a value from stdin into a file, without the plaintext ever touching it",
	Long: `Read a value from stdin, encrypt it, and splice it into a .env-shaped file.

The plaintext never enters the file, the disk, or argv: it is read from stdin,
encrypted in memory, and only the ciphertext is written. Encryption needs the
public key alone, so a developer with envisible.pub and no decrypt capability
can still add and rotate secrets.

  printf '%s' "$TOKEN" | envisible set .env API_TOKEN -
  secret-store get api-token | envisible set API_TOKEN -
  secret-store export --json | envisible set --from-json -

There is deliberately no --value flag. An argument is visible in ps, in shell
history, and in every process listing on the machine.

Layout is preserved: an existing key keeps its 'export ' prefix, indentation
and trailing comment, and only the value is rewritten. A new key is appended.

Encryption is randomized, so re-running set with an unchanged value produces a
different ciphertext and a diff. set writes only the keys it is given; it is
for adding and rotating a key, not for syncing a whole file. Use --if-changed
(which needs decrypt capability) to skip keys whose value already matches.`,
	Args: cobra.RangeArgs(1, 3),
	RunE: func(cmd *cobra.Command, args []string) error {
		if setFromJSON && setFromEnv {
			return errors.New("--from-json and --from-env are mutually exclusive")
		}

		targetFile, key, err := parseSetArgs(args, setFromJSON || setFromEnv)
		if err != nil {
			return err
		}
		if targetFile == "" {
			targetFile = filePath
		}
		if targetFile == stdinTarget {
			return errors.New("set needs a real file to write: stdin is already carrying the value")
		}
		// Reject a bad key before reading anything, so a typo can never be the
		// reason a file was touched.
		if key != "" && !processor.ValidEnvName(key) {
			return fmt.Errorf("invalid key name %q: must match [A-Za-z_][A-Za-z0-9_]*", key)
		}

		payload, _, err := readTarget(cmd, stdinTarget)
		if err != nil {
			return err
		}

		pairs, err := setPairs(cmd.Context(), key, payload)
		if err != nil {
			return err
		}
		for _, p := range pairs {
			if !processor.ValidEnvName(p.key) {
				return fmt.Errorf("invalid key name %q: must match [A-Za-z_][A-Za-z0-9_]*", p.key)
			}
			if p.value == "" && !setAllowEmpty {
				return fmt.Errorf("refusing to write an empty value for %s: stdin carried no bytes, which is what a dead process upstream in a pipe looks like (pass --allow-empty if you meant it)", p.key)
			}
		}
		if len(pairs) == 0 {
			return errors.New("no keys in the payload: nothing to set")
		}

		content, mode, err := readSetTargetFile(targetFile)
		if err != nil {
			return err
		}
		if !processor.LooksLikeDotenv(content) {
			return fmt.Errorf("%s does not look like a .env file, and appending a KEY=value line to it would corrupt it; use `envisible edit %s` for YAML/JSON/TOML targets", targetFile, targetFile)
		}

		enc, err := loadEncryptor()
		if err != nil {
			return err
		}
		var dec processor.Decryptor
		if setIfChanged {
			// Never degrade into a full rewrite: --if-changed exists precisely
			// to avoid churn, so failing to answer "has it changed?" has to be
			// an error rather than a silent "assume yes".
			dec, err = loadDecryptor(cmd.Context())
			if err != nil {
				return fmt.Errorf("--if-changed needs decrypt capability to compare the current value: %w", err)
			}
		}

		updated, outcomes, err := applySet(cmd.Context(), content, pairs, enc, dec)
		if err != nil {
			return err
		}

		if setDryRun {
			ui.Info("dry run: would set %s in %s", describeOutcomes(outcomes), targetFile)
			return nil
		}
		if changedCount(outcomes) == 0 {
			ui.Success("no change: %s in %s", describeOutcomes(outcomes), targetFile)
			return nil
		}
		if err := writeFileAtomic(targetFile, updated, mode); err != nil {
			return err
		}
		ui.Success("set %s in %s", describeOutcomes(outcomes), targetFile)
		return nil
	},
}

// parseSetArgs splits the positional arguments into a target file and a key.
//
// The trailing "-" is mandatory and load-bearing: it is the only place a value
// may come from, and spelling it out at the call site is what keeps a plausible
// `envisible set KEY hunter2` from ever being a thing that works.
func parseSetArgs(args []string, payloadMode bool) (file, key string, err error) {
	if len(args) == 0 || args[len(args)-1] != stdinTarget {
		return "", "", errors.New("the value is read from stdin: end the command with '-' (there is deliberately no --value flag, since an argument is visible in ps and in shell history)")
	}
	rest := args[:len(args)-1]

	if payloadMode {
		if len(rest) > 1 {
			return "", "", errors.New("usage: envisible set [file] --from-json|--from-env -")
		}
		if len(rest) == 1 {
			file = rest[0]
		}
		return file, "", nil
	}

	switch len(rest) {
	case 1:
		return "", rest[0], nil
	case 2:
		return rest[0], rest[1], nil
	default:
		return "", "", errors.New("usage: envisible set [file] KEY - (or --from-json / --from-env for a payload)")
	}
}

// setPairs turns the stdin payload into the keys and plaintexts to write.
func setPairs(ctx context.Context, key string, payload []byte) ([]pair, error) {
	switch {
	case setFromJSON:
		return jsonPairs(payload)
	case setFromEnv:
		return envPairs(ctx, payload)
	default:
		return []pair{{key: key, value: string(trimOneNewline(payload))}}, nil
	}
}

// trimOneNewline drops exactly one trailing '\n' unless --raw was passed.
//
// Editors, heredocs and `echo` all add one, and a credential stored with a
// stray newline fails at the point of use, far from the command that broke it.
// Exactly one, so a multi-line secret keeps its shape.
func trimOneNewline(b []byte) []byte {
	if setRaw {
		return b
	}
	if len(b) > 0 && b[len(b)-1] == '\n' {
		return b[:len(b)-1]
	}
	return b
}

// jsonPairs reads a JSON object of KEY → string.
//
// Parse errors are reported by offset only. encoding/json's own messages quote
// the byte they choked on, and that byte belongs to a secret.
func jsonPairs(payload []byte) ([]pair, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		var syn *json.SyntaxError
		if errors.As(err, &syn) {
			return nil, fmt.Errorf("--from-json: invalid JSON at byte offset %d", syn.Offset)
		}
		return nil, errors.New("--from-json: stdin is not a JSON object of KEY -> value")
	}

	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]pair, 0, len(keys))
	for _, k := range keys {
		var v string
		if err := json.Unmarshal(raw[k], &v); err != nil {
			return nil, fmt.Errorf("--from-json: the value for %s is not a string", k)
		}
		pairs = append(pairs, pair{key: k, value: v})
	}
	return pairs, nil
}

// envPairs reads a dotenv-shaped payload, using the same parser `run` uses so
// the input grammar and the output grammar cannot drift apart.
func envPairs(ctx context.Context, payload []byte) ([]pair, error) {
	env, defects, err := processor.ExtractEnvWithDefects(ctx, payload, plaintextOnlyDecryptor{})
	if err != nil {
		return nil, fmt.Errorf("--from-env: %w", err)
	}
	if len(defects) > 0 {
		lines := make([]string, 0, len(defects))
		for _, d := range defects {
			lines = append(lines, describeDefect(stdinDisplayName, payload, d))
		}
		return nil, fmt.Errorf("--from-env: %d unreadable line(s) in the payload:\n  %s", len(defects), strings.Join(lines, "\n  "))
	}

	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]pair, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, pair{key: k, value: env[k]})
	}
	return pairs, nil
}

// plaintextOnlyDecryptor refuses every marker version, which makes
// ExtractEnv leave any ENC[...] in the payload as the literal text it is. The
// --from-env payload is plaintext by definition; nothing in it is ours to open.
type plaintextOnlyDecryptor struct{}

func (plaintextOnlyDecryptor) DecryptMarker(context.Context, string) ([]byte, error) {
	return nil, processor.ErrSkip
}

// readSetTargetFile reads the target, treating "does not exist" as empty
// content destined for a new 0644 file.
func readSetTargetFile(path string) ([]byte, os.FileMode, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, newFileMode, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to stat file: %w", err)
	}
	if info.IsDir() {
		return nil, 0, fmt.Errorf("%s is a directory", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read file: %w", err)
	}
	return content, info.Mode().Perm(), nil
}

// applySet encrypts each value and splices it in, returning the new content and
// what happened to each key. Nothing is written here — the caller decides that,
// which is what makes --dry-run exercise the identical code path.
func applySet(ctx context.Context, content []byte, pairs []pair, enc processor.Encryptor, dec processor.Decryptor) ([]byte, []outcome, error) {
	outcomes := make([]outcome, 0, len(pairs))
	for _, p := range pairs {
		if dec != nil {
			current, found, err := processor.LookupValue(ctx, content, p.key, dec)
			if err != nil {
				return nil, nil, fmt.Errorf("--if-changed: failed to decrypt the current value of %s: %w", p.key, err)
			}
			if found && current == p.value {
				outcomes = append(outcomes, outcome{key: p.key, action: processor.Unchanged})
				continue
			}
		}
		inner, err := enc.EncryptValue([]byte(p.value))
		if err != nil {
			// The encryptor's errors are about keys and lengths, never content.
			return nil, nil, fmt.Errorf("failed to encrypt the value for %s: %w", p.key, err)
		}
		var action processor.Action
		content, action = processor.Upsert(content, p.key, processor.WrapMarker(inner))
		outcomes = append(outcomes, outcome{key: p.key, action: action})
	}
	return content, outcomes, nil
}

// changedCount reports how many keys actually produced a rewrite.
func changedCount(outcomes []outcome) int {
	n := 0
	for _, o := range outcomes {
		if o.action != processor.Unchanged {
			n++
		}
	}
	return n
}

// describeOutcomes renders the per-key report: "STRIPE_KEY (updated),
// AWS_REGION (added)". Keys only — a value never reaches stdout or stderr, on
// any path.
func describeOutcomes(outcomes []outcome) string {
	parts := make([]string, 0, len(outcomes))
	for _, o := range outcomes {
		parts = append(parts, fmt.Sprintf("%s (%s)", o.key, o.action))
	}
	return strings.Join(parts, ", ")
}

// writeFileAtomic writes data to path via a temp file in the same directory,
// fsync, and rename.
//
// Same directory because rename is only atomic within a filesystem; fsync
// because a rename that lands before the data does leaves an empty file where a
// secret used to be. The mode is applied to the temp file before the rename, so
// the file at path is never briefly world-readable.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".envisible-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	cleanup := func(err error) error {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(fmt.Errorf("failed to write temp file: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("failed to sync temp file: %w", err))
	}
	if err := tmp.Chmod(mode); err != nil {
		return cleanup(fmt.Errorf("failed to set mode on temp file: %w", err))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace %s: %w", path, err)
	}
	return nil
}

func init() {
	setCmd.Flags().BoolVar(&setFromJSON, "from-json", false, "read a JSON object of KEY -> value from stdin (writes, and therefore churns, every key in it)")
	setCmd.Flags().BoolVar(&setFromEnv, "from-env", false, "read dotenv-shaped KEY=value lines from stdin")
	setCmd.Flags().BoolVar(&setDryRun, "dry-run", false, "report what would change and write nothing")
	setCmd.Flags().BoolVar(&setIfChanged, "if-changed", false, "skip keys whose current value already decrypts to the new one (requires decrypt capability)")
	setCmd.Flags().BoolVar(&setRaw, "raw", false, "keep stdin verbatim instead of trimming exactly one trailing newline")
	setCmd.Flags().BoolVar(&setAllowEmpty, "allow-empty", false, "allow an empty value (by default empty stdin is an error and nothing is written)")
	rootCmd.AddCommand(setCmd)
}
