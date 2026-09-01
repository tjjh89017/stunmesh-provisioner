package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// errLockHeld reports that another instance already holds the lock.
// This is the normal, expected outcome (PLAN.md section 5): cron and
// the WAN hotplug script both start fetch, and they overlap
// routinely. The caller logs one line and exits 0; it is not a
// failure.
var errLockHeld = errors.New("locked by another instance")

// lockFile is one held stunmesh-agent lock, returned by acquireLock.
type lockFile struct {
	f *os.File
}

// acquireLock takes the exclusive, non-blocking lock at path.
//
// It uses flock(2) (syscall.Flock), not a PID file. flock ties the
// lock to the open file descriptor, not to a recorded PID. The
// kernel drops the lock the instant the holding process exits, for
// any reason, including a crash or a kill -9. A PID file needs extra
// code to detect a stale entry and to decide when it is safe to
// remove it; flock needs none, so a lock can never wedge the node.
// This matters here: the node runs fetch from cron every few minutes
// and also from a WAN hotplug event, so two instances starting at
// once, and the risk of one dying mid-run, are routine, not rare.
//
// acquireLock creates path if it does not exist, mode 0644. The file
// holds no secret; it only gives flock(2) something to lock.
// acquireLock never removes path, on success or on Release: deleting
// a lock file races a second process that is about to open and lock
// the same name, which would let two instances hold "the lock" on
// two different inodes at once. An empty file left behind costs
// nothing.
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
// from a defer on every doFetch exit path, including failure. It is
// also safe to call on a nil *lockFile, so a caller does not need to
// guard the defer behind the acquireLock error check.
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
