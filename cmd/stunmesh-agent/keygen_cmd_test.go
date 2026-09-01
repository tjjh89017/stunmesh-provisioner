package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
)

func TestRunKeygen_WritesNewKeyAndPrintsPubkey(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)

	code := runKeygen(env, []string{"--config-dir", dir})
	if code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}

	keyPath := filepath.Join(dir, "identity.key")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read identity.key: %v", err)
	}
	priv, err := crypto.ParseKey(string(data))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	if got := crypto.Public(priv).String(); strings.TrimSpace(stdout.String()) != got {
		t.Errorf("stdout = %q, want the public key %q", stdout.String(), got)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != identityKeyMode {
		t.Errorf("mode = %v, want %v", info.Mode().Perm(), identityKeyMode)
	}
}

func TestRunKeygen_ReusesExistingKey(t *testing.T) {
	dir := t.TempDir()
	var stdout1, stderr1 bytes.Buffer
	env1 := newEnv(strings.NewReader(""), &stdout1, &stderr1)
	if code := runKeygen(env1, []string{"--config-dir", dir}); code != ExitOK {
		t.Fatalf("first run: code = %d; stderr=%q", code, stderr1.String())
	}

	var stdout2, stderr2 bytes.Buffer
	env2 := newEnv(strings.NewReader(""), &stdout2, &stderr2)
	if code := runKeygen(env2, []string{"--config-dir", dir}); code != ExitOK {
		t.Fatalf("second run: code = %d; stderr=%q", code, stderr2.String())
	}

	if stdout1.String() != stdout2.String() {
		t.Errorf("public key changed across runs: %q vs %q", stdout1.String(), stdout2.String())
	}
}

func TestRunKeygen_UnknownFlagIsExitError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"--this-flag-does-not-exist"})
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
}

func TestRunKeygen_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"-h"})
	if code != ExitOK {
		t.Errorf("code = %d, want %d", code, ExitOK)
	}
	if stdout.Len() == 0 {
		t.Error("stdout is empty, want usage text")
	}
}

func TestRunKeygen_UnexpectedPositionalArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"bogus"})
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
}

func TestDoKeygen_ExistingNonKeyFileRefusesToReplace(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write bogus file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := doKeygen(env, keyPath)
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "not a key" {
		t.Errorf("file content changed, want it left untouched")
	}
}

func TestDoKeygen_NeverLogsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := doKeygen(env, filepath.Join(dir, "identity.key"))
	if code != ExitOK {
		t.Fatalf("code = %d; stderr=%q", code, stderr.String())
	}

	data, err := os.ReadFile(filepath.Join(dir, "identity.key"))
	if err != nil {
		t.Fatalf("read identity.key: %v", err)
	}
	priv := strings.TrimSpace(string(data))
	if strings.Contains(stdout.String(), priv) || strings.Contains(stderr.String(), priv) {
		t.Errorf("private key leaked into stdout/stderr")
	}
}
