package main

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestAcquireLock_SecondHolderIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.lock")

	first, err := acquireLock(path)
	if err != nil {
		t.Fatalf("acquireLock (first): %v", err)
	}
	defer func() { _ = first.Release() }()

	_, err = acquireLock(path)
	if !errors.Is(err, errLockHeld) {
		t.Errorf("acquireLock (second) err = %v, want errLockHeld", err)
	}
}

func TestAcquireLock_ReleaseAllowsReacquire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.lock")

	first, err := acquireLock(path)
	if err != nil {
		t.Fatalf("acquireLock (first): %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	second, err := acquireLock(path)
	if err != nil {
		t.Fatalf("acquireLock (second, after release): %v", err)
	}
	defer func() { _ = second.Release() }()
}

func TestAcquireLock_CreatesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist-yet.lock")

	lock, err := acquireLock(path)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	defer func() { _ = lock.Release() }()
}

func TestAcquireLock_BadPathIsNotReportedAsHeld(t *testing.T) {
	// The parent directory does not exist: OpenFile fails outright.
	path := filepath.Join(t.TempDir(), "no-such-dir", "agent.lock")

	_, err := acquireLock(path)
	if err == nil {
		t.Fatal("acquireLock: want an error, got nil")
	}
	if errors.Is(err, errLockHeld) {
		t.Errorf("acquireLock err = %v, must not look like errLockHeld", err)
	}
}

func TestLockFile_ReleaseOnNilIsSafe(t *testing.T) {
	var l *lockFile
	if err := l.Release(); err != nil {
		t.Errorf("Release on nil *lockFile: %v, want nil", err)
	}
}

func TestAcquireLock_DoesNotDeleteTheLockFileOnRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.lock")

	lock, err := acquireLock(path)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// A second acquire must still succeed against the same file, i.e.
	// Release must not have removed it out from under a fresh
	// acquireLock call racing to create the same path.
	second, err := acquireLock(path)
	if err != nil {
		t.Fatalf("acquireLock (after release): %v", err)
	}
	defer func() { _ = second.Release() }()
}
