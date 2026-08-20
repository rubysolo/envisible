package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// stdinTarget is the conventional Unix spelling for "read from stdin" as a
// file argument. A real file named "-" is reachable as "./-".
const stdinTarget = "-"

// stdinDisplayName is how stdin is rendered in messages that would otherwise
// interpolate a file path.
const stdinDisplayName = "<stdin>"

// isTerminal reports whether f is attached to a character device (a terminal).
//
// It is a package variable rather than a direct os.Stdin.Stat() call deep in
// the read path so tests can drive the refusal branch without allocating a
// pty: the TTY refusal is a safety behavior, and a safety behavior that cannot
// be tested in CI is not a behavior anyone can rely on.
var isTerminal = func(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// targetName renders a target for human-facing messages: a path as itself, and
// stdin as "<stdin>".
func targetName(target string) string {
	if target == stdinTarget {
		return stdinDisplayName
	}
	return target
}

// readTarget returns the bytes to operate on and whether they came from stdin.
// A target of "-" reads cmd.InOrStdin() to EOF; anything else is a file path.
//
// Two failures are refused up front rather than half-honored:
//
//   - stdin attached to a terminal. Waiting on a TTY looks like a hang, and the
//     user's recovery is either Ctrl-C or typing a secret into a terminal that
//     keeps it in scrollback.
//   - --inplace together with "-". There is no file to rewrite; silently
//     ignoring the flag would let a script believe it wrote something.
//
// Empty stdin is *not* an error: an empty file is a legitimate thing to
// encrypt, decrypt or check.
func readTarget(cmd *cobra.Command, target string) (content []byte, isStdin bool, err error) {
	return readTargetWithRemedy(cmd, target, "pipe input or pass a file path")
}

// readTargetWithRemedy is readTarget with the caller choosing what to tell a
// user whose stdin is a terminal. "Pass a file path" is right for encrypt,
// decrypt and check, and impossible for set, whose value can only ever come
// from stdin.
func readTargetWithRemedy(cmd *cobra.Command, target, ttyRemedy string) (content []byte, isStdin bool, err error) {
	if target != stdinTarget {
		content, err = os.ReadFile(target)
		if err != nil {
			return nil, false, fmt.Errorf("failed to read file: %w", err)
		}
		return content, false, nil
	}

	if f := cmd.Flags().Lookup("inplace"); f != nil && f.Value.String() == "true" {
		return nil, true, errors.New("--inplace has no meaning when reading stdin")
	}

	in := cmd.InOrStdin()
	if f, ok := in.(*os.File); ok && isTerminal(f) {
		return nil, true, fmt.Errorf("refusing to read from a terminal; %s", ttyRemedy)
	}

	content, err = io.ReadAll(in)
	if err != nil {
		return nil, true, fmt.Errorf("failed to read stdin: %w", err)
	}
	return content, true, nil
}
