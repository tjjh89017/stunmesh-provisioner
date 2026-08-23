package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_NoArgsPrintsUsageAndErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(nil, strings.NewReader(""), &stdout, &stderr, "dev")
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "Usage: stunmesh-agent") {
		t.Errorf("stderr = %q, want it to contain usage", stderr.String())
	}
}

func TestRun_Help(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		var stdout, stderr bytes.Buffer
		code := Run([]string{flag}, strings.NewReader(""), &stdout, &stderr, "dev")
		if code != ExitOK {
			t.Errorf("%s: code = %d, want %d", flag, code, ExitOK)
		}
		if !strings.Contains(stdout.String(), "Usage: stunmesh-agent") {
			t.Errorf("%s: stdout = %q, want it to contain usage", flag, stdout.String())
		}
	}
}

func TestRun_Version(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr, "1.2.3")
	if code != ExitOK {
		t.Errorf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout.String(), "1.2.3") {
		t.Errorf("stdout = %q, want it to contain the version", stdout.String())
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"bogus"}, strings.NewReader(""), &stdout, &stderr, "dev")
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), `unknown command "bogus"`) {
		t.Errorf("stderr = %q, want it to name the unknown command", stderr.String())
	}
}

func TestRun_DispatchesToFetchAndKeygen(t *testing.T) {
	for _, name := range []string{"fetch", "keygen"} {
		var stdout, stderr bytes.Buffer
		// No flags at all: each subcommand must fail its own
		// validation, proving Run actually dispatched into it rather
		// than silently doing nothing.
		code := Run([]string{name}, strings.NewReader(""), &stdout, &stderr, "dev")
		if code != ExitError {
			t.Errorf("%s: code = %d, want %d", name, code, ExitError)
		}
		if !strings.Contains(stderr.String(), name+":") {
			t.Errorf("%s: stderr = %q, want it to be labeled by the subcommand", name, stderr.String())
		}
	}
}
