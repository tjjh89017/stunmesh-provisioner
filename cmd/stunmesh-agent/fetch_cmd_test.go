package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunFetch_MissingFlagsReportsExitError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), nil)
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "--namespace") {
		t.Errorf("stderr = %q, want it to name the missing settings", stderr.String())
	}
}

func TestRunFetch_ValidFlagsReachTheStubSeam(t *testing.T) {
	var stdout, stderr bytes.Buffer
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	args := []string{
		"--namespace", "ns",
		"--node-id", "n1",
		"--controller-pubkey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"--identity-key", "/tmp/id.key",
		"--lock", lockPath,
	}
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), args)
	// Validation must pass with these flags (proving the flags and
	// defaults resolved correctly); doFetch is an unimplemented stub
	// in this item, so it reports failure -- that is the seam later
	// items replace.
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "not implemented") {
		t.Errorf("stderr = %q, want it to reach the doFetch stub, not a validation error", stderr.String())
	}
}

func TestRunFetch_BadControllerPubkeyNeverEchoed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"--namespace", "ns",
		"--node-id", "n1",
		"--controller-pubkey", "not-a-real-key-super-secret-looking",
		"--identity-key", "/tmp/id.key",
	}
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), args)
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if strings.Contains(stderr.String(), "not-a-real-key-super-secret-looking") {
		t.Errorf("stderr leaks the bad pubkey value: %q", stderr.String())
	}
}

func TestRunFetch_ConfigFilePrecedenceEndToEnd(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.conf")
	lockPath := filepath.Join(dir, "agent.lock")
	content := "namespace=from-file\nnode_id=from-file\ncontroller_pubkey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nidentity_key=/tmp/id.key\nlock=" + lockPath + "\n"
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{
		"--namespace", "from-flag",
		"--config", configPath,
	}
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), args)
	// The flag-supplied namespace must win, leaving node_id and the
	// rest to come from the file; the whole thing then reaches
	// doFetch's stub, so the failure here is "not implemented", not a
	// validation error -- proving both the merge and the precedence
	// worked end to end through runFetch.
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "not implemented") {
		t.Errorf("stderr = %q, want the config-merged flags to pass validation", stderr.String())
	}
}

func TestRunFetch_UnexpectedPositionalArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"extra"})
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), `"extra"`) {
		t.Errorf("stderr = %q, want it to name the unexpected argument", stderr.String())
	}
}

func TestRunFetch_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"-h"})
	if code != ExitOK {
		t.Errorf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout.String(), "Usage: stunmesh-agent") {
		t.Errorf("stdout = %q, want usage", stdout.String())
	}
}

func validFetchConfig(lockPath string) *Config {
	return &Config{
		Namespace:          "ns",
		NodeID:             "n1",
		ControllerPubkey:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Proxies:            []string{"https://dhtproxy.example"},
		IdentityKeyPath:    "/tmp/id.key",
		LastPath:           "/tmp/last.json",
		LockPath:           lockPath,
		StunmeshConfigPath: "/tmp/stunmesh.yaml",
	}
}

func TestDoFetch_SecondConcurrentHolderExitsOKWithOneLogLine(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")

	held, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("acquireLock (first holder): %v", err)
	}
	defer held.Release()

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := doFetch(env, validFetchConfig(lockPath))

	if code != ExitOK {
		t.Errorf("code = %d, want %d (a held lock is normal, not a failure)", code, ExitOK)
	}
	lines := strings.Split(strings.TrimRight(stderr.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("stderr = %q, want exactly one log line", stderr.String())
	}
	if !strings.Contains(stderr.String(), lockPath) {
		t.Errorf("stderr = %q, want it to name the lock path", stderr.String())
	}
	if strings.Contains(stderr.String(), "not implemented") {
		t.Errorf("stderr = %q, doFetch must not fall through to the stub when the lock is held", stderr.String())
	}
}

func TestDoFetch_AcquiresLockThenFallsThroughToStub(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := doFetch(env, validFetchConfig(lockPath))

	if code != ExitError {
		t.Errorf("code = %d, want %d (stub still reports failure)", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "not implemented") {
		t.Errorf("stderr = %q, want it to reach the doFetch stub", stderr.String())
	}

	// The lock must be released: a second call must be able to take it
	// too, not report it as held.
	var stdout2, stderr2 bytes.Buffer
	env2 := newEnv(strings.NewReader(""), &stdout2, &stderr2)
	code2 := doFetch(env2, validFetchConfig(lockPath))
	if code2 != ExitError || !strings.Contains(stderr2.String(), "not implemented") {
		t.Errorf("second doFetch = code %d, stderr %q, want the lock to have been released", code2, stderr2.String())
	}
}

func TestDoFetch_BadLockPathIsExitError(t *testing.T) {
	// The parent directory does not exist, so opening the lock file
	// fails for a reason other than it being held.
	lockPath := filepath.Join(t.TempDir(), "no-such-dir", "agent.lock")

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := doFetch(env, validFetchConfig(lockPath))

	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if strings.Contains(stderr.String(), "already locked") {
		t.Errorf("stderr = %q, a bad path must not be reported as an ordinary held lock", stderr.String())
	}
}
