package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// ErrExists means the caller asked to write a file that is already
// there. It is not a failure. `stunmesh-provd init` and `node add`
// (stage 2 items 4 and 5) are meant to run again against a tree that
// already has some files, and a caller tells "did not write it,
// because the operator already owns it" apart from a real error with
// errors.Is(err, ErrExists).
var ErrExists = errors.New("store: already exists")

// WriteFile creates path with data and mode. It never overwrites an
// existing file; see the package doc "Write primitives" section for
// why that guarantee is unconditional and how it holds up under a
// race between two processes.
//
// WriteFile returns ErrExists, wrapping path, if path already exists.
// It reports no other detail about the existing file, and it never
// includes data in an error message.
//
// On any other failure, WriteFile removes the file it started
// writing, so a failed write does not linger on disk and masquerade
// as ErrExists on a later run.
func WriteFile(path string, data []byte, mode fs.FileMode) error {
	// O_EXCL makes the existence check and the creation one atomic
	// kernel operation: two processes racing to create path cannot
	// both win. The loser gets EEXIST, not a chance to truncate or
	// interleave writes with the winner. A separate os.Stat before
	// os.WriteFile cannot give this guarantee, because another
	// process can create path in the gap between the check and the
	// write.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%w: %s", ErrExists, path)
		}
		return fmt.Errorf("store: create %s: %w", path, err)
	}

	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		os.Remove(path)
		if writeErr != nil {
			return fmt.Errorf("store: write %s: %w", path, writeErr)
		}
		return fmt.Errorf("store: close %s: %w", path, closeErr)
	}

	// OpenFile's mode argument is masked by the process umask, so the
	// file on disk can land narrower than requested (or, with an
	// unusual umask that masks an owner bit, even lose a bit the
	// caller needs). Chmod after creation forces the exact requested
	// mode, independent of umask.
	if err := os.Chmod(path, mode); err != nil {
		os.Remove(path)
		return fmt.Errorf("store: chmod %s: %w", path, err)
	}

	return nil
}

// CreateDir creates path with mode, including any missing parents.
// It is idempotent: if path already exists as a directory, CreateDir
// leaves it untouched (mode included) and returns nil. It returns an
// error if path exists and is not a directory.
//
// A directory entry holds no secret by itself; only the files inside
// it do, and WriteFile protects those. CreateDir's job is to make the
// directory available, not to guard against a second caller also
// making it, so it does not need WriteFile's O_EXCL race protection:
// two processes both creating the same directory concurrently reach
// the same, harmless end state.
//
// mode is masked by the process umask like WriteFile's; CreateDir
// calls os.Chmod after creating path (not any parent it had to
// create along the way) to force the exact requested mode regardless
// of umask. A caller that wants a parent and a leaf at different
// modes calls CreateDir once per level, parent first.
func CreateDir(path string, mode fs.FileMode) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("store: create %s: exists and is not a directory", path)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("store: stat %s: %w", path, err)
	}

	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("store: create %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("store: chmod %s: %w", path, err)
	}
	return nil
}
