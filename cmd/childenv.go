package cmd

import (
	"os"
	"runtime"
	"strings"
)

// privateKeyEnvVar carries the v1 private key by value (see resolveKeySources).
const privateKeyEnvVar = "ENVISIBLE_KEY"

// childEnviron returns the environment to hand to a process envisible spawns:
// this process's environment minus the private key.
//
// ENVISIBLE_KEY exists so envisible can decrypt. The programs it launches (the
// command under `run`, $EDITOR under `edit`, git) are given the decrypted
// values, or nothing, and have no use for the key that produced them. Passing
// it along would hand every child, and everything that child spawns, the
// ability to decrypt every secret in the repository rather than the handful it
// was given, and would undo the scoping a caller sets up with
// `<store> exec --as ENVISIBLE_KEY -- envisible run -- app`.
//
// ENVISIBLE_KEY_PATH and the other ENVISIBLE_* variables are paths, not
// secrets, and pass through.
func childEnviron() []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if isPrivateKeyEnvVar(name) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// isPrivateKeyEnvVar matches the way the OS (and so os.Getenv) resolves the
// name: case-insensitively on Windows, exactly everywhere else.
func isPrivateKeyEnvVar(name string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(name, privateKeyEnvVar)
	}
	return name == privateKeyEnvVar
}
