package main

import (
	"bytes"
	"strings"
	"testing"
)

// run is a small test helper. It calls Run with fresh buffers and
// returns the exit code, stdout, and stderr as strings.
func run(args ...string) (code int, stdout, stderr string) {
	var outBuf, errBuf bytes.Buffer
	code = Run(args, strings.NewReader(""), &outBuf, &errBuf, "1.2.3")
	return code, outBuf.String(), errBuf.String()
}

func TestRun_Version(t *testing.T) {
	code, stdout, _ := run("--version")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "stunmesh-provd 1.2.3") {
		t.Errorf("stdout = %q, want it to contain the version", stdout)
	}
}

func TestRun_HelpFlag(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		code, stdout, _ := run(flag)
		if code != ExitOK {
			t.Errorf("%s: code = %d, want %d", flag, code, ExitOK)
		}
		if !strings.Contains(stdout, "Usage:") {
			t.Errorf("%s: stdout = %q, want it to contain usage", flag, stdout)
		}
	}
}

func TestRun_NoArgs(t *testing.T) {
	code, _, stderr := run()
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr = %q, want it to contain usage", stderr)
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	code, _, stderr := run("frobnicate")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "frobnicate") {
		t.Errorf("stderr = %q, want it to name the unknown command", stderr)
	}
}

func TestRun_UnknownFlag(t *testing.T) {
	code, _, _ := run("--bogus")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

func TestRun_InitDirOverride(t *testing.T) {
	root := t.TempDir() + "/custom-root"
	code, stdout, stderr := run("--dir", root, "init")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %q, want %d", code, stderr, ExitOK)
	}
	if !strings.Contains(stdout, root) {
		t.Errorf("stdout = %q, want it to contain the overridden dir", stdout)
	}
}

func TestRun_InitWithNamespace(t *testing.T) {
	root := t.TempDir()
	code, stdout, stderr := run("--dir", root, "init", "myns")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %q, want %d", code, stderr, ExitOK)
	}
	if !strings.Contains(stdout, "myns") {
		t.Errorf("stdout = %q, want it to contain the namespace", stdout)
	}
}

func TestRun_InitTooManyArgs(t *testing.T) {
	code, _, _ := run("init", "a", "b")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

func TestRun_NodeAdd(t *testing.T) {
	code, _, stderr := run("node", "add", "ns1", "node1")
	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr, "ns1") || !strings.Contains(stderr, "node1") {
		t.Errorf("stderr = %q, want it to contain namespace and node id", stderr)
	}
}

func TestRun_NodeAddWrongArity(t *testing.T) {
	code, _, _ := run("node", "add", "ns1")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

func TestRun_NodeNoSubcommand(t *testing.T) {
	code, _, _ := run("node")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

func TestRun_NodeUnknownSubcommand(t *testing.T) {
	code, _, stderr := run("node", "remove", "ns1", "node1")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "remove") {
		t.Errorf("stderr = %q, want it to name the unknown subcommand", stderr)
	}
}

func TestRun_Publish(t *testing.T) {
	// The default --dir (/etc/stunmesh/provd) does not exist in the
	// test environment, so naming a namespace under it is a clear,
	// reported error rather than a silent no-op.
	code, _, stderr := run("publish", "--namespace", "ns1", "--once")
	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr, "ns1") {
		t.Errorf("stderr = %q, want it to contain the namespace", stderr)
	}
}

func TestRun_PublishDefaults(t *testing.T) {
	// The republish loop (stage 2 item 8) is not implemented yet:
	// omitting --once is a usage error, not a silent no-op.
	code, _, stderr := run("publish")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "--once") {
		t.Errorf("stderr = %q, want it to mention --once", stderr)
	}
}

func TestRun_PublishExtraArgs(t *testing.T) {
	code, _, _ := run("publish", "extra")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

func TestRun_PublishUnknownFlag(t *testing.T) {
	code, _, _ := run("publish", "--bogus")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

func TestRun_PublishHelp(t *testing.T) {
	code, stdout, stderr := run("publish", "-h")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "publish") && !strings.Contains(stderr, "publish") {
		t.Errorf("expected usage output to mention publish, stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestExitCodesAreDistinct(t *testing.T) {
	if ExitOK == ExitError || ExitOK == ExitUsage || ExitError == ExitUsage {
		t.Fatalf("exit codes must be distinct: OK=%d Error=%d Usage=%d", ExitOK, ExitError, ExitUsage)
	}
}
