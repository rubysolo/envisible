package ui

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStderr redirects os.Stderr for the duration of fn and returns whatever
// was written. The ui helpers write directly to os.Stderr, so this is how we
// assert on their output.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

func TestOutputHelpersWriteToStderr(t *testing.T) {
	Quiet = false
	t.Cleanup(func() { Quiet = false })

	out := captureStderr(t, func() {
		Success("ok %d", 1)
		Error("boom %s", "x")
		Info("info here")
		Warn("careful")
		KV("Resource", "the-value")
	})

	for _, want := range []string{"ok 1", "boom x", "info here", "careful", "Resource", "the-value"} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr output missing %q; got:\n%s", want, out)
		}
	}

	// Headline applies an underline style that renders each rune with its own
	// escape sequence, so the text isn't a contiguous substring — just assert it
	// emits something.
	if got := captureStderr(t, func() { Headline("A Title") }); got == "" {
		t.Error("Headline produced no output")
	}
}

func TestQuietSuppressesInfoButNotError(t *testing.T) {
	Quiet = true
	t.Cleanup(func() { Quiet = false })

	out := captureStderr(t, func() {
		Success("suppressed")
		Info("suppressed")
		Warn("suppressed")
		KV("suppressed", "suppressed")
		Headline("suppressed")
		Error("always shown")
	})

	if strings.Contains(out, "suppressed") {
		t.Errorf("Quiet must suppress informational output; got:\n%s", out)
	}
	if !strings.Contains(out, "always shown") {
		t.Errorf("Quiet must never suppress Error; got:\n%s", out)
	}
}
