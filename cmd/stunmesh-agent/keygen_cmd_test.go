package main

import (
	"bytes"
	"strings"
	"testing"
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
	var stdout, stderr bytes.Buffer
	// Deliberately no --namespace, --node-id, --controller-pubkey, or
	// --proxy: keygen must not require any of them.
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"--identity-key", "/tmp/id.key"})
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "not implemented") {
		t.Errorf("stderr = %q, want validation to pass and reach the doKeygen stub", stderr.String())
	}
}

func TestRunKeygen_IdentityKeyFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/agent.conf"
	writeFile(t, configPath, "identity_key=/tmp/id.key\n")

	var stdout, stderr bytes.Buffer
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"--config", configPath})
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "not implemented") {
		t.Errorf("stderr = %q, want the config file's identity_key to satisfy validation", stderr.String())
	}
}

func TestRunKeygen_UnexpectedPositionalArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"extra"})
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
}
