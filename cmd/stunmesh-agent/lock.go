package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// errLockHeld reports that another instance already holds the lock.
// This is the normal, expected outcome: the daemon and a
// hotplug-driven restart can overlap. The caller logs one line and
// exits 0; it is not a failure.
var errLockHeld = errors.New("locked by another instance")

// lockFile is one held stunmesh-agent lock, returned by acquireLock.
type lockFile struct {
	f *os.File
}

// acquireLock takes the exclusive, non-blocking lock at path.
//
// It uses flock(2) (syscall.Flock), not a PID file. flock ties the
// lock to the file descriptor, so the kernel drops it when the
// process dies.
//
// acquireLock creates path if it does not exist, mode 0644. The file
// holds no secret; it only gives flock(2) something to lock.
// acquireLock never removes the lock file: a delete races a second
// opener.
//
// acquireLock returns an error wrapping errLockHeld when another
// instance already holds the lock. Any other error (the directory
// does not exist, permission denied, and so on) is a genuine failure
// to acquire the lock, and is returned unwrapped by errLockHeld.
func acquireLock(path string) (*lockFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s: %w", path, errLockHeld)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}

	return &lockFile{f: f}, nil
}

// Release unlocks and closes the lock file. Release is safe to call
// from a defer on every exit path, including failure. It is also safe
// to call on a nil *lockFile, so a caller does not need to guard the
// defer behind the acquireLock error check.
func (l *lockFile) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	closeErr := l.f.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
