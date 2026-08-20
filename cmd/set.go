package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
		payloadFlag := ""
		switch {
		case setFromJSON:
			payloadFlag = "--from-json"
		case setFromEnv:
			payloadFlag = "--from-env"
		}

		targetFile, key, err := parseSetArgs(args, payloadFlag)
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

		payload, _, err := readTargetWithRemedy(cmd, stdinTarget, "set reads the value from stdin only, so pipe it in: printf '%s' \"$VALUE\" | envisible set FILE KEY -")
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
				if payloadFlag != "" {
					return fmt.Errorf("refusing to write an empty value for %s: its value in the %s payload is empty (pass --allow-empty if you meant it)", p.key, payloadFlag)
				}
				return fmt.Errorf("refusing to write an empty value for %s: stdin carried no bytes, which is what a dead process upstream in a pipe looks like (pass --allow-empty if you meant it)", p.key)
			}
		}
		if len(pairs) == 0 {
			return errors.New("no keys in the payload: nothing to set")
		}

		content, err := readSetTargetFile(targetFile)
		if err != nil {
			return err
		}
		// `set` is a write path, so it holds to the write path's contract: a
		// target that already carries a malformed marker is pre-existing damage,
		// and splicing into it would hand the user — who may hold only the
		// public key and cannot check their own work — a file the pre-commit
		// hook rejects. Error with file:line:col, write nothing.
		isDotenv, defects := processor.LooksLikeDotenvWithDefects(content)
		if err := defectError(targetFile, content, defects); err != nil {
			return err
		}
		if !isDotenv {
			return fmt.Errorf("%s does not look like a .env file, and appending a KEY=value line to it would corrupt it; use `envisible edit %s` for YAML/JSON/TOML targets", targetFile, targetFile)
		}
		// Parseable but ambiguous shapes. The write goes ahead — both readings
		// are legal grammar — but the author is told which line the next
		// `encrypt` will read differently than they may have meant.
		warnAmbiguousMarkers(targetFile, content)

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

		updated, outcomes, err := applySet(cmd.Context(), targetFile, content, pairs, enc, dec)
		if err != nil {
			return err
		}

		if setDryRun {
			// A gate, shaped like `check`: one machine-readable line per key on
			// stdout, where -q cannot silence it, and a non-zero exit when
			// anything would change. That is what makes it usable as the CI
			// drift check the README points at.
			return reportDryRun(cmd.OutOrStdout(), targetFile, outcomes)
		}
		if changedCount(outcomes) == 0 {
			ui.Success("no change: %s in %s", describeOutcomes(outcomes), targetFile)
			return nil
		}
		if err := writeFileAtomic(targetFile, updated, newFileMode); err != nil {
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
//
// payloadFlag is "--from-json" / "--from-env" when a payload flag was given, or
// "" in single-key mode. In payload mode the one optional positional is a file,
// and a lone argument that looks like a KEY rather than a path is rejected: a
// file named MYKEY full of secrets in the working directory is a far worse
// outcome than an error the user can route around with ./MYKEY.
func parseSetArgs(args []string, payloadFlag string) (file, key string, err error) {
	if len(args) == 0 || args[len(args)-1] != stdinTarget {
		return "", "", errors.New("the value is read from stdin: end the command with '-' (there is deliberately no --value flag, since an argument is visible in ps and in shell history)")
	}
	rest := args[:len(args)-1]

	if payloadFlag != "" {
		if len(rest) > 1 {
			return "", "", errors.New("usage: envisible set [file] --from-json|--from-env -")
		}
		if len(rest) == 1 {
			file = rest[0]
			if looksLikeKeyNotPath(file) {
				return "", "", fmt.Errorf("%s takes a file, not a key: %q looks like a variable name (the keys come from the payload; if %q really is the file, spell it ./%s)", payloadFlag, file, file, file)
			}
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

// looksLikeKeyNotPath reports whether s is more plausibly a variable name than
// a file: it passes ValidEnvName, which already rules out every separator and
// the dot a real file name almost always carries.
func looksLikeKeyNotPath(s string) bool {
	return processor.ValidEnvName(s)
}

// reportDryRun prints one "action\tKEY\tfile" line per key to out and returns
// a non-nil error when any key would change, so the exit code is the answer.
func reportDryRun(out io.Writer, targetFile string, outcomes []outcome) error {
	for _, o := range outcomes {
		fmt.Fprintf(out, "%s\t%s\t%s\n", o.action, o.key, targetFile)
	}
	n := changedCount(outcomes)
	if n == 0 {
		return nil
	}
	return fmt.Errorf("dry run: %d key(s) would change in %s, nothing written", n, targetFile)
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
			lines = append(lines, payloadContext.describe(stdinDisplayName, payload, d))
		}
		return nil, fmt.Errorf("--from-env: %d unusable line(s) in the payload:\n  %s", len(defects), strings.Join(lines, "\n  "))
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
// content destined for a new file. The mode is the writer's concern: it keeps
// an existing file's and uses newFileMode otherwise.
func readSetTargetFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return content, nil
}

// applySet encrypts each value and splices it in, returning the new content and
// what happened to each key. Nothing is written here — the caller decides that,
// which is what makes --dry-run exercise the identical code path.
//
// The target was already checked for defects before this is called; the
// defect-aware processor calls here are the belt to that suspender, so a future
// caller that skips the pre-flight still cannot write into a damaged file.
func applySet(ctx context.Context, targetFile string, content []byte, pairs []pair, enc processor.Encryptor, dec processor.Decryptor) ([]byte, []outcome, error) {
	outcomes := make([]outcome, 0, len(pairs))
	for _, p := range pairs {
		if dec != nil {
			current, found, defects, err := processor.LookupValueWithDefects(ctx, content, p.key, dec)
			if err := defectError(targetFile, content, defects); err != nil {
				return nil, nil, err
			}
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
		var (
			action  processor.Action
			defects []processor.Defect
		)
		content, action, defects = processor.UpsertWithDefects(content, p.key, processor.WrapMarker(inner))
		if err := defectError(targetFile, content, defects); err != nil {
			return nil, nil, err
		}
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

func init() {
	setCmd.Flags().BoolVar(&setFromJSON, "from-json", false, "read a JSON object of KEY -> value from stdin (writes, and therefore churns, every key in it)")
	setCmd.Flags().BoolVar(&setFromEnv, "from-env", false, "read dotenv-shaped KEY=value lines from stdin")
	setCmd.Flags().BoolVar(&setDryRun, "dry-run", false, "write nothing; print one action<TAB>KEY<TAB>file line per key on stdout and exit non-zero if anything would change")
	setCmd.Flags().BoolVar(&setIfChanged, "if-changed", false, "skip keys whose current value already decrypts to the new one (requires decrypt capability)")
	setCmd.Flags().BoolVar(&setRaw, "raw", false, "keep stdin verbatim instead of trimming exactly one trailing newline")
	setCmd.Flags().BoolVar(&setAllowEmpty, "allow-empty", false, "allow an empty value (by default empty stdin is an error and nothing is written)")
	rootCmd.AddCommand(setCmd)
}
