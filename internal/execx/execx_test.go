package execx_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/execx"
)

func TestExec_Run_Success(t *testing.T) {
	var e execx.Exec

	stdout, err := e.Run("echo", "hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stdout != "hello\n" {
		t.Errorf("stdout = %q, want %q", stdout, "hello\n")
	}
}

func TestExec_Run_CommandNotFound(t *testing.T) {
	var e execx.Exec

	const secretArg = "private_key=SUPERSECRETVALUE"
	_, err := e.Run("definitely-not-a-real-command-xyz", secretArg)
	if err == nil {
		t.Fatal("Run: want error, got nil")
	}
	if !errors.Is(err, execx.ErrRunFailed) {
		t.Errorf("errors.Is(err, ErrRunFailed) = false, want true; err = %v", err)
	}
	if strings.Contains(err.Error(), secretArg) {
		t.Errorf("error message contains the secret argument: %v", err)
	}
}

func TestExec_Run_NonZeroExit(t *testing.T) {
	var e execx.Exec

	_, err := e.Run("sh", "-c", "exit 7")
	if err == nil {
		t.Fatal("Run: want error, got nil")
	}
	if !errors.Is(err, execx.ErrRunFailed) {
		t.Errorf("errors.Is(err, ErrRunFailed) = false, want true; err = %v", err)
	}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("error message = %q, want it to mention the exit code 7", err.Error())
	}
}

func TestExec_Run_ErrorDoesNotLeakStderr(t *testing.T) {
	var e execx.Exec

	const secretStderr = "leaked-secret-on-stderr"
	_, err := e.Run("sh", "-c", "echo "+secretStderr+" >&2; exit 1")
	if err == nil {
		t.Fatal("Run: want error, got nil")
	}
	if strings.Contains(err.Error(), secretStderr) {
		t.Errorf("error message leaks stderr content: %v", err)
	}
}

func TestExec_Run_ErrorDoesNotLeakArgs(t *testing.T) {
	var e execx.Exec

	const secretArg = "preshared_key=ANOTHERSECRET"
	_, err := e.Run("sh", "-c", "exit 1", secretArg)
	if err == nil {
		t.Fatal("Run: want error, got nil")
	}
	if strings.Contains(err.Error(), secretArg) {
		t.Errorf("error message leaks an argument: %v", err)
	}
}

// Exec must implement Runner.
var _ execx.Runner = execx.Exec{}
