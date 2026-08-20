package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// newFileMode is the mode a file created by a write path gets. One constant
// for every command, so a file's permissions do not depend on which command
// happened to create it.
const newFileMode os.FileMode = 0644

// resolveWriteTarget follows path through any symlinks to the file a write
// should actually land on.
//
// A rename over a symlink replaces the link, not its target, so an atomic
// writer that does not resolve first silently forks `.env -> .env.local` into
// two files: the one `set` wrote and the one everything else reads. Resolving
// up front gives every write path the same answer `os.WriteFile` would have
// given — the link survives, the target changes.
//
// A path that does not exist resolves through its directory, so a new file is
// created where the (possibly symlinked) directory really lives. A dangling
// symlink is an explicit error: creating a regular file where a link used to
// point is exactly the silent redirect this function exists to prevent.
func resolveWriteTarget(path string) (string, error) {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		dir, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return "", fmt.Errorf("failed to resolve directory of %s: %w", path, err)
		}
		return filepath.Join(dir, filepath.Base(path)), nil
	case err != nil:
		return "", fmt.Errorf("failed to stat %s: %w", path, err)
	case info.Mode()&os.ModeSymlink != 0:
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("%s is a symlink whose target does not exist; refusing to replace the link with a regular file", path)
			}
			return "", fmt.Errorf("failed to resolve symlink %s: %w", path, err)
		}
		return resolved, nil
	default:
		return path, nil
	}
}

// writeFileAtomic replaces the file at path with data: a temp file in the same
// directory, fsync, rename. Symlinks are followed, so the link stays a link and
// its target is what changes.
//
// Same directory because rename is only atomic within a filesystem; fsync
// because a rename that lands before the data does leaves an empty file where a
// secret used to be. An existing file keeps its mode; a new one gets
// createMode. The mode is applied to the temp file before the rename, so the
// file at path is never briefly more readable than it was.
//
// Every in-place write in the CLI goes through here. `os.WriteFile` is
// symlink-correct but truncates before it writes, so an interrupted
// `encrypt -i` on a large file could leave a half-written secret behind.
func writeFileAtomic(path string, data []byte, createMode os.FileMode) error {
	target, err := resolveWriteTarget(path)
	if err != nil {
		return err
	}

	mode := createMode
	if info, err := os.Stat(target); err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
		mode = info.Mode().Perm()
	}

	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".envisible-*")
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
	if err := os.Rename(tmpPath, target); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace %s: %w", path, err)
	}
	return nil
}
