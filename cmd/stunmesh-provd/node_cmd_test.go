package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtkey"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// initTestNamespace runs runInit against root for namespace and fails
// the test on error. It returns the namespace directory.
func initTestNamespace(t *testing.T, root, namespace string) string {
	t.Helper()
	env, _, stderr := newTestEnv(root)
	if code := runInit(env, []string{namespace}); code != ExitOK {
		t.Fatalf("runInit(%q) code = %d, stderr = %q", namespace, code, stderr.String())
	}
	return filepath.Join(root, namespace)
}

func TestRunNodeAdd_WithKeyArgument(t *testing.T) {
	root := t.TempDir()
	initTestNamespace(t, root, "myns")

	_, pub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	env, stdout, stderr := newTestEnv(root)
	code := runNodeAdd(env, []string{"myns", "alpha", pub.String()})
	if code != ExitOK {
		t.Fatalf("runNodeAdd code = %d, stderr = %q, want %d", code, stderr.String(), ExitOK)
	}

	nodeDir := filepath.Join(root, "myns", "nodes", "alpha")

	identityData, err := os.ReadFile(filepath.Join(nodeDir, "identity.pub"))
	if err != nil {
		t.Fatalf("ReadFile(identity.pub): %v", err)
	}
	got, err := crypto.ParseKey(string(identityData))
	if err != nil {
		t.Fatalf("ParseKey(identity.pub): %v", err)
	}
	if got != pub {
		t.Errorf("identity.pub = %s, want %s", got, pub)
	}

	if _, err := os.Stat(filepath.Join(nodeDir, "wg.yaml")); err != nil {
		t.Errorf("wg.yaml missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(nodeDir, "stunmesh.yaml")); err != nil {
		t.Errorf("stunmesh.yaml missing: %v", err)
	}

	if !strings.Contains(stdout.String(), "NAMESPACE=myns") {
		t.Errorf("stdout = %q, want NAMESPACE=myns", stdout.String())
	}
	if !strings.Contains(stdout.String(), "NODE_ID=alpha") {
		t.Errorf("stdout = %q, want NODE_ID=alpha", stdout.String())
	}
}

func TestRunNodeAdd_FromStdin(t *testing.T) {
	root := t.TempDir()
	initTestNamespace(t, root, "myns")

	_, pub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	env, _, stderr := newTestEnv(root)
	env.Stdin = strings.NewReader(pub.String() + "\n")
	code := runNodeAdd(env, []string{"myns", "beta"})
	if code != ExitOK {
		t.Fatalf("runNodeAdd code = %d, stderr = %q, want %d", code, stderr.String(), ExitOK)
	}

	identityData, err := os.ReadFile(filepath.Join(root, "myns", "nodes", "beta", "identity.pub"))
	if err != nil {
		t.Fatalf("ReadFile(identity.pub): %v", err)
	}
	got, err := crypto.ParseKey(string(identityData))
	if err != nil {
		t.Fatalf("ParseKey(identity.pub): %v", err)
	}
	if got != pub {
		t.Errorf("identity.pub = %s, want %s", got, pub)
	}
}

func TestRunNodeAdd_PrintsNodeConstants(t *testing.T) {
	root := t.TempDir()
	initTestNamespace(t, root, "myns")

	pubData, err := os.ReadFile(filepath.Join(root, "myns", "controller.pub"))
	if err != nil {
		t.Fatalf("ReadFile(controller.pub): %v", err)
	}
	controllerPub, err := crypto.ParseKey(string(pubData))
	if err != nil {
		t.Fatalf("ParseKey(controller.pub): %v", err)
	}

	_, identityPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	env, stdout, stderr := newTestEnv(root)
	code := runNodeAdd(env, []string{"myns", "alpha", identityPub.String()})
	if code != ExitOK {
		t.Fatalf("runNodeAdd code = %d, stderr = %q, want %d", code, stderr.String(), ExitOK)
	}

	out := stdout.String()
	for _, want := range []string{
		"NAMESPACE=myns",
		"NODE_ID=alpha",
		"CONTROLLER_PUBKEY=" + controllerPub.String(),
		"DHT_PROXY=https://dhtproxy2.jami.net",
		"DHT_PROXY=https://dhtproxy3.jami.net",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want it to contain %q", out, want)
		}
	}
}

func TestRunNodeAdd_FileModes(t *testing.T) {
	withUmask(t, 0o022)
	root := t.TempDir()
	initTestNamespace(t, root, "myns")

	_, pub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	env, _, stderr := newTestEnv(root)
	code := runNodeAdd(env, []string{"myns", "alpha", pub.String()})
	if code != ExitOK {
		t.Fatalf("runNodeAdd code = %d, stderr = %q, want %d", code, stderr.String(), ExitOK)
	}

	nodeDir := filepath.Join(root, "myns", "nodes", "alpha")

	if perm := mustStat(t, nodeDir).Mode().Perm(); perm != 0o700 {
		t.Errorf("node dir mode = %o, want 0700", perm)
	}
	if perm := mustStat(t, filepath.Join(root, "myns", "nodes")).Mode().Perm(); perm != 0o755 {
		t.Errorf("nodes dir mode = %o, want 0755", perm)
	}
	if perm := mustStat(t, filepath.Join(nodeDir, "identity.pub")).Mode().Perm(); perm != 0o644 {
		t.Errorf("identity.pub mode = %o, want 0644", perm)
	}
	if perm := mustStat(t, filepath.Join(nodeDir, "wg.yaml")).Mode().Perm(); perm != 0o600 {
		t.Errorf("wg.yaml mode = %o, want 0600", perm)
	}
	if perm := mustStat(t, filepath.Join(nodeDir, "stunmesh.yaml")).Mode().Perm(); perm != 0o644 {
		t.Errorf("stunmesh.yaml mode = %o, want 0644", perm)
	}
}

func TestRunNodeAdd_RerunDoesNotClobberEditedFiles(t *testing.T) {
	root := t.TempDir()
	initTestNamespace(t, root, "myns")

	_, pub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	env, _, stderr := newTestEnv(root)
	if code := runNodeAdd(env, []string{"myns", "alpha", pub.String()}); code != ExitOK {
		t.Fatalf("first runNodeAdd code = %d, stderr = %q", code, stderr.String())
	}

	nodeDir := filepath.Join(root, "myns", "nodes", "alpha")
	wgPath := filepath.Join(nodeDir, "wg.yaml")
	edited := []byte("wg0:\n  private_key: edited-by-operator\n  addresses: [10.0.0.1/24]\n  peers: {}\n")
	if err := os.WriteFile(wgPath, edited, 0o600); err != nil {
		t.Fatalf("WriteFile(wg.yaml edit): %v", err)
	}
	origIdentity := mustReadFile(t, filepath.Join(nodeDir, "identity.pub"))

	_, otherPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	env2, stdout2, stderr2 := newTestEnv(root)
	code := runNodeAdd(env2, []string{"myns", "alpha", otherPub.String()})
	if code != ExitOK {
		t.Fatalf("second runNodeAdd code = %d, stderr = %q, want %d", code, stderr2.String(), ExitOK)
	}

	if got := mustReadFile(t, wgPath); !bytes.Equal(got, edited) {
		t.Errorf("wg.yaml changed on re-run: got %q, want %q", got, edited)
	}
	if got := mustReadFile(t, filepath.Join(nodeDir, "identity.pub")); !bytes.Equal(got, origIdentity) {
		t.Errorf("identity.pub changed on re-run to a different key: got %q, want %q", got, origIdentity)
	}
	if !strings.Contains(stdout2.String(), "already exists") {
		t.Errorf("stdout on re-run = %q, want it to report what already existed", stdout2.String())
	}
}

func TestRunNodeAdd_NamespaceNotInitialized(t *testing.T) {
	root := t.TempDir()
	env, _, stderr := newTestEnv(root)

	code := runNodeAdd(env, []string{"missing-ns", "alpha", strings.Repeat("A", 43) + "="})
	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "init") {
		t.Errorf("stderr = %q, want it to mention running init", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "missing-ns")); err == nil {
		t.Error("runNodeAdd created a namespace directory for an uninitialized namespace")
	}
}

func TestRunNodeAdd_RejectsInvalidNodeID(t *testing.T) {
	root := t.TempDir()
	initTestNamespace(t, root, "myns")

	_, pub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	for _, nodeID := range []string{"..", ".", ".hidden", "has/slash", ""} {
		env, _, stderr := newTestEnv(root)
		args := []string{"myns", nodeID, pub.String()}
		if nodeID == "" {
			// A bare empty positional argument is still two args
			// syntactically; runNodeAdd must still reject it as an
			// invalid node_id, not merely a usage error.
			args = []string{"myns", "", pub.String()}
		}
		code := runNodeAdd(env, args)
		if code != ExitError && code != ExitUsage {
			t.Errorf("node_id %q: code = %d, want an error", nodeID, code)
		}
		if stderr.Len() == 0 {
			t.Errorf("node_id %q: want an error message", nodeID)
		}
	}
}

func TestRunNodeAdd_RejectsInvalidKeyArgument(t *testing.T) {
	root := t.TempDir()
	initTestNamespace(t, root, "myns")

	env, _, stderr := newTestEnv(root)
	code := runNodeAdd(env, []string{"myns", "alpha", "not-a-valid-key"})
	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	if strings.Contains(stderr.String(), "not-a-valid-key") {
		t.Errorf("error echoes the rejected key material: %q", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "myns", "nodes", "alpha", "identity.pub")); err == nil {
		t.Error("runNodeAdd wrote identity.pub from an invalid key")
	}
}

func TestRunNodeAdd_RejectsInvalidKeyFromStdin(t *testing.T) {
	root := t.TempDir()
	initTestNamespace(t, root, "myns")

	env, _, stderr := newTestEnv(root)
	env.Stdin = strings.NewReader("garbage\n")
	code := runNodeAdd(env, []string{"myns", "alpha"})
	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	if strings.Contains(stderr.String(), "garbage") {
		t.Errorf("error echoes the rejected key material: %q", stderr.String())
	}
}

func TestRunNodeAdd_TooFewOrTooManyArgs(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{
		{"onlyns"},
		{"ns", "id", "key", "extra"},
		nil,
	} {
		env, _, stderr := newTestEnv(root)
		code := runNodeAdd(env, args)
		if code != ExitUsage {
			t.Errorf("args %v: code = %d, want %d", args, code, ExitUsage)
		}
		if stderr.Len() == 0 {
			t.Errorf("args %v: want a usage message", args)
		}
	}
}

// TestRunNodeAdd_NoSecretInOutput exercises a full run and asserts
// nothing that looks like private key material appears in the
// command's output. The only "secret" this command ever handles is
// the node identity key it is given, which is public by definition;
// this test guards against a future change accidentally logging a
// path's file content or similar.
func TestRunNodeAdd_NoSecretInOutput(t *testing.T) {
	root := t.TempDir()
	initTestNamespace(t, root, "myns")

	priv, pub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	env, stdout, stderr := newTestEnv(root)
	code := runNodeAdd(env, []string{"myns", "alpha", pub.String()})
	if code != ExitOK {
		t.Fatalf("runNodeAdd code = %d, stderr = %q, want %d", code, stderr.String(), ExitOK)
	}

	combined := stdout.String() + "\n" + stderr.String()
	if strings.Contains(combined, priv.String()) {
		t.Error("a private key string appeared in command output")
	}

	controllerKeyData := mustReadFile(t, filepath.Join(root, "myns", "controller.key"))
	controllerPriv, err := crypto.ParseKey(string(controllerKeyData))
	if err != nil {
		t.Fatalf("ParseKey(controller.key): %v", err)
	}
	if strings.Contains(combined, controllerPriv.String()) {
		t.Error("the controller private key appeared in command output")
	}
}

// TestNodeIDAcceptedByResolveNameIsAddressableByDHTKey asserts that
// every node_id store.ResolveName accepts is also one dhtkey.Key
// accepts for the same namespace, and that every node_id
// store.ResolveName rejects for path-escape reasons is one dhtkey.Key
// rejects too. A node_id that `node add` could create but that
// dhtkey.Key later refuses would be a node that can never be
// published to (PLAN.md 7.4 traps).
func TestNodeIDAcceptedByResolveNameIsAddressableByDHTKey(t *testing.T) {
	root := t.TempDir()
	const namespace = "myns"

	for _, nodeID := range []string{"alpha", "node-1", "a.b", "UPPER"} {
		if _, err := store.ResolveName(filepath.Join(root, namespace, "nodes"), nodeID); err != nil {
			t.Fatalf("ResolveName(%q) rejected a node_id expected to be valid: %v", nodeID, err)
		}
		if _, err := dhtkey.Key(namespace, nodeID); err != nil {
			t.Errorf("node_id %q is accepted by ResolveName but rejected by dhtkey.Key: %v", nodeID, err)
		}
	}

	for _, nodeID := range []string{"", ".", "..", ".hidden", "has/slash"} {
		if _, err := store.ResolveName(filepath.Join(root, namespace, "nodes"), nodeID); err == nil {
			t.Fatalf("ResolveName(%q) unexpectedly succeeded", nodeID)
		}
	}
}
