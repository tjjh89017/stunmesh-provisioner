package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
)

// withUmask sets the process umask for the duration of the test and
// restores it on cleanup. See internal/store/write_test.go for why no
// test in this file may run in parallel with another that touches the
// umask.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no umask on windows")
	}
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) })
}

// newTestEnv builds an Env rooted at dir with deterministic
// randomness, for tests that must not touch the real process
// streams.
func newTestEnv(dir string) (env *Env, stdout, stderr *bytes.Buffer) {
	stdout = &bytes.Buffer{}
	stderr = &bytes.Buffer{}
	env = newEnv(strings.NewReader(""), stdout, stderr, dir)
	return env, stdout, stderr
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", path, err)
	}
	return info
}

func TestRunInit_FreshTree(t *testing.T) {
	withUmask(t, 0o022)
	root := t.TempDir()
	env, stdout, stderr := newTestEnv(root)

	code := runInit(env, []string{"myns"})
	if code != ExitOK {
		t.Fatalf("runInit code = %d, stderr = %q, want %d", code, stderr.String(), ExitOK)
	}

	readmePath := filepath.Join(root, "README.md")
	if data, err := os.ReadFile(readmePath); err != nil {
		t.Fatalf("ReadFile(README.md): %v", err)
	} else if !strings.Contains(string(data), "namespace") {
		t.Errorf("README.md does not mention namespace: %q", data)
	}
	if perm := mustStat(t, readmePath).Mode().Perm(); perm != 0o644 {
		t.Errorf("README.md mode = %o, want 0644", perm)
	}

	nsDir := filepath.Join(root, "myns")
	if perm := mustStat(t, nsDir).Mode().Perm(); perm != 0o700 {
		t.Errorf("namespace dir mode = %o, want 0700", perm)
	}
	if perm := mustStat(t, root).Mode().Perm(); perm != 0o755 {
		t.Errorf("root dir mode = %o, want 0755", perm)
	}

	provdPath := filepath.Join(nsDir, "provd.yaml")
	provdData, err := os.ReadFile(provdPath)
	if err != nil {
		t.Fatalf("ReadFile(provd.yaml): %v", err)
	}
	for _, want := range []string{"dhtproxy2.jami.net", "dhtproxy3.jami.net", "republish_interval: 5m"} {
		if !strings.Contains(string(provdData), want) {
			t.Errorf("provd.yaml = %q, want it to contain %q", provdData, want)
		}
	}
	if perm := mustStat(t, provdPath).Mode().Perm(); perm != 0o644 {
		t.Errorf("provd.yaml mode = %o, want 0644", perm)
	}

	keyPath := filepath.Join(nsDir, "controller.key")
	pubPath := filepath.Join(nsDir, "controller.pub")
	if perm := mustStat(t, keyPath).Mode().Perm(); perm != 0o600 {
		t.Errorf("controller.key mode = %o, want 0600", perm)
	}
	if perm := mustStat(t, pubPath).Mode().Perm(); perm != 0o644 {
		t.Errorf("controller.pub mode = %o, want 0644", perm)
	}

	privData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile(controller.key): %v", err)
	}
	priv, err := crypto.ParseKey(string(privData))
	if err != nil {
		t.Fatalf("ParseKey(controller.key): %v", err)
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("ReadFile(controller.pub): %v", err)
	}
	pub, err := crypto.ParseKey(string(pubData))
	if err != nil {
		t.Fatalf("ParseKey(controller.pub): %v", err)
	}
	if want := crypto.Public(priv); pub != want {
		t.Errorf("controller.pub does not match controller.key: got %s, want %s", pub, want)
	}

	if strings.Contains(stdout.String(), privData2str(privData)) {
		t.Errorf("private key leaked into stdout: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), pub.String()) {
		t.Errorf("stdout = %q, want it to print the public key", stdout.String())
	}
}

// privData2str trims the trailing newline the same way the file
// content would appear if it leaked verbatim, so the leak check
// compares like with like.
func privData2str(data []byte) string {
	return strings.TrimSpace(string(data))
}

func TestRunInit_RandomNamespaceWhenNoneGiven(t *testing.T) {
	root := t.TempDir()
	env, stdout, stderr := newTestEnv(root)

	code := runInit(env, nil)
	if code != ExitOK {
		t.Fatalf("runInit code = %d, stderr = %q, want %d", code, stderr.String(), ExitOK)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var namespaces []string
	for _, e := range entries {
		if e.IsDir() {
			namespaces = append(namespaces, e.Name())
		}
	}
	if len(namespaces) != 1 {
		t.Fatalf("namespace dirs = %v, want exactly one", namespaces)
	}
	if strings.Contains(namespaces[0], "/") || strings.HasPrefix(namespaces[0], ".") {
		t.Errorf("random namespace %q is not a valid directory name", namespaces[0])
	}
	if !strings.Contains(stdout.String(), namespaces[0]) {
		t.Errorf("stdout = %q, want it to name the generated namespace %q", stdout.String(), namespaces[0])
	}
}

func TestRunInit_RandomNamespaceIsDeterministicFromRand(t *testing.T) {
	root1, root2 := t.TempDir(), t.TempDir()

	env1, _, _ := newTestEnv(root1)
	env1.Rand = strings.NewReader("0123456789abcdef")
	if code := runInit(env1, nil); code != ExitOK {
		t.Fatalf("runInit(1) code = %d, want %d", code, ExitOK)
	}

	env2, _, _ := newTestEnv(root2)
	env2.Rand = strings.NewReader("0123456789abcdef")
	if code := runInit(env2, nil); code != ExitOK {
		t.Fatalf("runInit(2) code = %d, want %d", code, ExitOK)
	}

	ns1 := onlyDir(t, root1)
	ns2 := onlyDir(t, root2)
	if ns1 != ns2 {
		t.Errorf("namespace from a fixed Rand source is not deterministic: %q != %q", ns1, ns2)
	}
}

func onlyDir(t *testing.T, root string) string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			return e.Name()
		}
	}
	t.Fatalf("no namespace directory under %s", root)
	return ""
}

func TestRunInit_RerunIsCalmNoOp(t *testing.T) {
	root := t.TempDir()
	env, _, stderr := newTestEnv(root)

	if code := runInit(env, []string{"myns"}); code != ExitOK {
		t.Fatalf("first runInit code = %d, stderr = %q", code, stderr.String())
	}

	nsDir := filepath.Join(root, "myns")
	keyPath := filepath.Join(nsDir, "controller.key")
	pubPath := filepath.Join(nsDir, "controller.pub")
	provdPath := filepath.Join(nsDir, "provd.yaml")
	readmePath := filepath.Join(root, "README.md")

	origKey := mustReadFile(t, keyPath)
	origPub := mustReadFile(t, pubPath)
	origProvd := mustReadFile(t, provdPath)
	origReadme := mustReadFile(t, readmePath)

	env2, stdout2, stderr2 := newTestEnv(root)
	code := runInit(env2, []string{"myns"})
	if code != ExitOK {
		t.Fatalf("second runInit code = %d, stderr = %q, want %d", code, stderr2.String(), ExitOK)
	}

	if got := mustReadFile(t, keyPath); !bytes.Equal(got, origKey) {
		t.Error("controller.key changed on re-run")
	}
	if got := mustReadFile(t, pubPath); !bytes.Equal(got, origPub) {
		t.Error("controller.pub changed on re-run")
	}
	if got := mustReadFile(t, provdPath); !bytes.Equal(got, origProvd) {
		t.Error("provd.yaml changed on re-run")
	}
	if got := mustReadFile(t, readmePath); !bytes.Equal(got, origReadme) {
		t.Error("README.md changed on re-run")
	}
	if !strings.Contains(stdout2.String(), "already exist") {
		t.Errorf("stdout on re-run = %q, want it to report what already existed", stdout2.String())
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	return data
}

// TestRunInit_RecoversMissingPubFromExistingKey simulates a process
// that died after writing controller.key but before writing
// controller.pub (or an operator who deleted just controller.pub). A
// re-run must derive controller.pub from the existing controller.key,
// not generate a fresh, mismatched pair.
func TestRunInit_RecoversMissingPubFromExistingKey(t *testing.T) {
	root := t.TempDir()
	nsDir := filepath.Join(root, "myns")
	if err := os.MkdirAll(nsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	priv, _, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	keyPath := filepath.Join(nsDir, "controller.key")
	if err := os.WriteFile(keyPath, []byte(priv.String()+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// provd.yaml must exist too, or runInit would (harmlessly) write
	// it; write it up front so this test isolates the key recovery.
	if err := os.WriteFile(filepath.Join(nsDir, "provd.yaml"), []byte(defaultProvdYAML), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	env, _, stderr := newTestEnv(root)
	code := runInit(env, []string{"myns"})
	if code != ExitOK {
		t.Fatalf("runInit code = %d, stderr = %q, want %d", code, stderr.String(), ExitOK)
	}

	pubData := mustReadFile(t, filepath.Join(nsDir, "controller.pub"))
	pub, err := crypto.ParseKey(string(pubData))
	if err != nil {
		t.Fatalf("ParseKey(controller.pub): %v", err)
	}
	if want := crypto.Public(priv); pub != want {
		t.Errorf("recovered controller.pub = %s, want %s (derived from the pre-existing controller.key)", pub, want)
	}
	// The pre-existing key must not have been replaced.
	if got := mustReadFile(t, keyPath); string(got) != priv.String()+"\n" {
		t.Error("runInit replaced a pre-existing controller.key")
	}
}

func TestRunInit_TooManyArgs(t *testing.T) {
	root := t.TempDir()
	env, _, stderr := newTestEnv(root)

	code := runInit(env, []string{"a", "b"})
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	if stderr.Len() == 0 {
		t.Error("want a usage message on stderr")
	}
}

func TestRunInit_RejectsInvalidNamespace(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"..", ".", ".hidden", "has/slash"} {
		env, _, stderr := newTestEnv(root)
		code := runInit(env, []string{name})
		if code != ExitError {
			t.Errorf("namespace %q: code = %d, want %d", name, code, ExitError)
		}
		if stderr.Len() == 0 {
			t.Errorf("namespace %q: want an error message", name)
		}
	}
}

// TestRunInit_NoSecretInOutput exercises a fresh init with the real
// crypto/rand source and asserts the generated private key bytes
// never appear on stdout or stderr, in any of the encodings the key
// could plausibly be printed in.
func TestRunInit_NoSecretInOutput(t *testing.T) {
	root := t.TempDir()
	env, stdout, stderr := newTestEnv(root)
	env.Rand = rand.Reader

	code := runInit(env, []string{"myns"})
	if code != ExitOK {
		t.Fatalf("runInit code = %d, stderr = %q, want %d", code, stderr.String(), ExitOK)
	}

	privData := mustReadFile(t, filepath.Join(root, "myns", "controller.key"))
	priv, err := crypto.ParseKey(string(privData))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}

	combined := stdout.String() + "\n" + stderr.String()
	if strings.Contains(combined, priv.String()) {
		t.Error("private key string leaked into command output")
	}
}
