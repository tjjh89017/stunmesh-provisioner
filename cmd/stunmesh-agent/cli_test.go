package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_VersionFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr, "1.2.3")
	if code != ExitOK {
		t.Errorf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "1.2.3") {
		t.Errorf("stdout = %q, want it to contain the version", stdout.String())
	}
}

func TestRun_HelpFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-h"}, strings.NewReader(""), &stdout, &stderr, "dev")
	if code != ExitOK {
		t.Errorf("code = %d, want %d", code, ExitOK)
	}
	if stdout.Len() == 0 {
		t.Error("stdout is empty, want usage text")
	}
}

func TestRun_UnknownFlagIsExitError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--this-flag-does-not-exist"}, strings.NewReader(""), &stdout, &stderr, "dev")
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
}

func TestRun_NoConfigYamlIsExitError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--config-dir", t.TempDir()}, strings.NewReader(""), &stdout, &stderr, "dev")
	if code != ExitError {
		t.Errorf("code = %d, want %d (not provisioned yet)", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "not provisioned") {
		t.Errorf("stderr = %q, want it to say not provisioned yet", stderr.String())
	}
}

func TestRun_MalformedConfigIsExitError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("namespace: ns\n"), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"--config-dir", dir, "--oneshot"}, strings.NewReader(""), &stdout, &stderr, "dev")
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
}

func TestRun_KeygenDispatch(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"keygen", "--config-dir", dir}, strings.NewReader(""), &stdout, &stderr, "dev")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.key")); err != nil {
		t.Errorf("identity.key not written: %v", err)
	}
	if stdout.Len() == 0 {
		t.Error("stdout is empty, want the public key")
	}
}

func TestRun_UnexpectedPositionalArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--config-dir", t.TempDir(), "bogus"}, strings.NewReader(""), &stdout, &stderr, "dev")
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
}
