package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// withUmask sets the process umask to mask for the duration of the
// test and restores the previous umask on cleanup. It skips the test
// on a platform without a Unix umask.
//
// syscall.Umask changes process-global state. Do not add
// t.Parallel() to a test in this package, or to a test in this
// package that calls withUmask, without first serializing every test
// that touches the umask (directly or through withUmask). Two such
// tests running in parallel would race on the umask and produce
// flaky, hard-to-reproduce failures.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no umask on windows")
	}
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) })
}

func TestWriteFile_CreatesFileWithContentAndMode(t *testing.T) {
	withUmask(t, 0o022)
	root := t.TempDir()
	path := filepath.Join(root, "controller.key")

	if err := store.WriteFile(path, []byte("secret-key-bytes"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "secret-key-bytes" {
		t.Errorf("content = %q, want %q", data, "secret-key-bytes")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 0600", perm)
	}
}

func TestWriteFile_Mode0644(t *testing.T) {
	withUmask(t, 0o022)
	root := t.TempDir()
	path := filepath.Join(root, "provd.yaml")

	if err := store.WriteFile(path, []byte("proxies: []\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want 0644", perm)
	}
}

// TestWriteFile_ModeSurvivesRestrictiveUmask pins that a 0600 request
// lands as exactly 0600 even under a umask that would otherwise widen
// or narrow it (0077 already narrows 0644 to 0600; this test uses a
// pathological umask that would additionally strip the owner's write
// bit from a 0600 request if WriteFile relied on OpenFile's mode
// argument alone).
func TestWriteFile_ModeSurvivesRestrictiveUmask(t *testing.T) {
	root := t.TempDir()
	withUmask(t, 0o200)
	path := filepath.Join(root, "controller.key")

	if err := store.WriteFile(path, []byte("k"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 0600 regardless of umask", perm)
	}
}

// TestWriteFile_ModeSurvivesPermissiveUmask pins the other direction:
// a permissive umask (0000) must not widen a 0644 request either.
func TestWriteFile_ModeSurvivesPermissiveUmask(t *testing.T) {
	withUmask(t, 0o000)
	root := t.TempDir()
	path := filepath.Join(root, "provd.yaml")

	if err := store.WriteFile(path, []byte("k"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want 0644 regardless of umask", perm)
	}
}

func TestWriteFile_NeverOverwrites(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "README.md")

	if err := store.WriteFile(path, []byte("first"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := store.WriteFile(path, []byte("second"), 0o644)
	if !errors.Is(err, store.ErrExists) {
		t.Fatalf("err = %v, want ErrExists", err)
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if string(data) != "first" {
		t.Errorf("content = %q, want %q (must not be overwritten)", data, "first")
	}
}

// TestWriteFile_NeverOverwritesOperatorFile pins that WriteFile
// refuses to touch a file the operator created directly (not through
// this package), and does not even change its mode.
func TestWriteFile_NeverOverwritesOperatorFile(t *testing.T) {
	// os.WriteFile's mode argument is masked by the process umask,
	// same as os.OpenFile's. Force the umask to 0 so the fixture
	// lands on disk at exactly 0640, the mode this test asserts
	// below, regardless of the umask the test process inherited.
	withUmask(t, 0o000)
	root := t.TempDir()
	path := filepath.Join(root, "provd.yaml")

	if err := os.WriteFile(path, []byte("operator-edited: true\n"), 0o640); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	err := store.WriteFile(path, []byte("default-content\n"), 0o644)
	if !errors.Is(err, store.ErrExists) {
		t.Fatalf("err = %v, want ErrExists", err)
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if string(data) != "operator-edited: true\n" {
		t.Errorf("content = %q, want operator's own content untouched", data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("mode = %o, want the operator's own 0640 untouched", perm)
	}
}

func TestWriteFile_ErrorNeverContainsData(t *testing.T) {
	const secret = "TopSecretPrivateKeyMaterial"
	root := t.TempDir()
	path := filepath.Join(root, "controller.key")

	if err := store.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := store.WriteFile(path, []byte(secret), 0o600)
	if err == nil {
		t.Fatal("want error on second write")
	}
	if got := err.Error(); len(got) == 0 {
		t.Fatal("want a non-empty error")
	}
	if containsSecret(err.Error(), secret) {
		t.Fatalf("error leaks secret: %v", err)
	}
}

func containsSecret(msg, secret string) bool {
	return len(msg) >= len(secret) && (func() bool {
		for i := 0; i+len(secret) <= len(msg); i++ {
			if msg[i:i+len(secret)] == secret {
				return true
			}
		}
		return false
	})()
}

func TestWriteFile_MissingParentDirIsNotErrExists(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "no-such-dir", "controller.key")

	err := store.WriteFile(path, []byte("k"), 0o600)
	if err == nil {
		t.Fatal("want error when parent directory is missing")
	}
	if errors.Is(err, store.ErrExists) {
		t.Fatalf("err = %v, want a generic error, not ErrExists", err)
	}
}

func TestCreateDir_CreatesWithMode(t *testing.T) {
	withUmask(t, 0o022)
	root := t.TempDir()
	path := filepath.Join(root, "test-ns")

	if err := store.CreateDir(path, 0o700); err != nil {
		t.Fatalf("CreateDir: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("path is not a directory")
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("mode = %o, want 0700", perm)
	}
}

func TestCreateDir_CreatesMissingParents(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "test-ns", "nodes", "alpha")

	if err := store.CreateDir(path, 0o755); err != nil {
		t.Fatalf("CreateDir: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("path is not a directory")
	}
}

func TestCreateDir_IdempotentOnExistingDir(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "test-ns")

	if err := store.CreateDir(path, 0o700); err != nil {
		t.Fatalf("first CreateDir: %v", err)
	}
	// Simulate the operator (or a prior run) having changed the mode.
	if err := os.Chmod(path, 0o750); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if err := store.CreateDir(path, 0o700); err != nil {
		t.Fatalf("second CreateDir: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o750 {
		t.Errorf("mode = %o, want the existing 0750 left untouched", perm)
	}
}

func TestCreateDir_ErrorWhenPathIsAFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "test-ns")

	if err := os.WriteFile(path, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := store.CreateDir(path, 0o700); err == nil {
		t.Fatal("want error when path already exists as a file")
	}
}

func TestCreateDir_ModeSurvivesRestrictiveUmask(t *testing.T) {
	withUmask(t, 0o077)
	root := t.TempDir()
	path := filepath.Join(root, "test-ns")

	if err := store.CreateDir(path, 0o755); err != nil {
		t.Fatalf("CreateDir: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Errorf("mode = %o, want 0755 regardless of umask", perm)
	}
}
