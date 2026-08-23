package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
)

func TestRunKeygen_MissingIdentityKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), nil)
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "--identity-key") {
		t.Errorf("stderr = %q, want it to name the missing setting", stderr.String())
	}
}

func TestRunKeygen_DoesNotRequireFetchOnlySettings(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id.key")

	var stdout, stderr bytes.Buffer
	// Deliberately no --namespace, --node-id, --controller-pubkey, or
	// --proxy: keygen must not require any of them.
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"--identity-key", keyPath})
	if code != ExitOK {
		t.Errorf("code = %d, want %d; stderr = %q", code, ExitOK, stderr.String())
	}
	if stderr.String() != "" {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("identity key file not written: %v", err)
	}
}

func TestRunKeygen_IdentityKeyFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id.key")
	configPath := filepath.Join(dir, "agent.conf")
	writeFile(t, configPath, "identity_key="+keyPath+"\n")

	var stdout, stderr bytes.Buffer
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"--config", configPath})
	if code != ExitOK {
		t.Errorf("code = %d, want %d; stderr = %q", code, ExitOK, stderr.String())
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("identity key file not written: %v", err)
	}
}

func TestRunKeygen_UnexpectedPositionalArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"extra"})
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
}

// --- doKeygen ---

func TestDoKeygen_GeneratesAndWritesKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")
	cfg := &Config{IdentityKeyPath: keyPath}

	var stdout, stderr bytes.Buffer
	code := doKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), cfg)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr = %q", code, ExitOK, stderr.String())
	}

	if stderr.String() != "" {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Stat(%s): %v", keyPath, err)
	}
	if got := info.Mode().Perm(); got != identityKeyMode {
		t.Errorf("mode = %o, want %o", got, identityKeyMode)
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	priv, err := crypto.ParseKey(string(data))
	if err != nil {
		t.Fatalf("written file is not a valid key: %v", err)
	}

	wantPub := crypto.Public(priv).String()
	gotStdout := strings.TrimRight(stdout.String(), "\n")
	if gotStdout != wantPub {
		t.Errorf("stdout = %q, want %q", gotStdout, wantPub)
	}
	if strings.Count(stdout.String(), "\n") != 1 {
		t.Errorf("stdout = %q, want exactly one line", stdout.String())
	}

	// The private key must never appear in stdout or stderr.
	privStr := priv.String()
	if strings.Contains(stdout.String(), privStr) {
		t.Errorf("stdout contains the private key")
	}
	if strings.Contains(stderr.String(), privStr) {
		t.Errorf("stderr contains the private key")
	}
}

func TestDoKeygen_NoStrayTempFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")
	cfg := &Config{IdentityKeyPath: keyPath}

	var stdout, stderr bytes.Buffer
	if code := doKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), cfg); code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr = %q", code, ExitOK, stderr.String())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "identity.key" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("dir entries = %v, want only [identity.key]", names)
	}
}

func TestDoKeygen_ReusesExistingKeyAndTightensMode(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")

	priv, _, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("crypto.Keygen: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(priv.String()+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := &Config{IdentityKeyPath: keyPath}
	var stdout, stderr bytes.Buffer
	code := doKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), cfg)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr = %q", code, ExitOK, stderr.String())
	}

	wantPub := crypto.Public(priv).String()
	gotStdout := strings.TrimRight(stdout.String(), "\n")
	if gotStdout != wantPub {
		t.Errorf("stdout = %q, want %q (existing key's public key, unchanged)", gotStdout, wantPub)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != identityKeyMode {
		t.Errorf("mode = %o, want %o (loose mode must be tightened)", got, identityKeyMode)
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.TrimSpace(string(data)) != priv.String() {
		t.Errorf("file content changed; keygen must not replace an existing valid key")
	}
}

func TestDoKeygen_RejectsUnparsableExistingFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")
	if err := os.WriteFile(keyPath, []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := &Config{IdentityKeyPath: keyPath}
	var stdout, stderr bytes.Buffer
	code := doKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), cfg)
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), keyPath) {
		t.Errorf("stderr = %q, want it to name the path", stderr.String())
	}
	if strings.Contains(stderr.String(), "not a key") {
		t.Errorf("stderr = %q, must not echo the file's content", stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("stdout = %q, want empty on failure", stdout.String())
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "not a key\n" {
		t.Errorf("file content changed on a rejected file, want it left untouched")
	}
}

func TestDoKeygen_FailsCleanlyWhenDirectoryMissing(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "no-such-dir", "identity.key")
	cfg := &Config{IdentityKeyPath: keyPath}

	var stdout, stderr bytes.Buffer
	code := doKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), cfg)
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if stdout.String() != "" {
		t.Errorf("stdout = %q, want empty on failure", stdout.String())
	}
}
