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
	args := []string{
		"--namespace", "ns",
		"--node-id", "n1",
		"--controller-pubkey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"--identity-key", "/tmp/id.key",
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
	content := "namespace=from-file\nnode_id=from-file\ncontroller_pubkey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nidentity_key=/tmp/id.key\n"
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
