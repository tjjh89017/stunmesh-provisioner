package store_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// b64Key returns a syntactically valid base64-encoded 32-byte key, so
// tests that only care about file plumbing (not key cryptography) do
// not have to run Keygen.
func b64Key(fill byte) string {
	var raw [32]byte
	for i := range raw {
		raw[i] = fill
	}
	return base64.StdEncoding.EncodeToString(raw[:])
}

// writeFile writes data to path, creating parent directories as needed.
func writeFile(t *testing.T, path string, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// setupNamespace builds a minimal, valid namespace directory under
// root and returns its path.
func setupNamespace(t *testing.T, root, namespace string) string {
	t.Helper()
	nsDir := filepath.Join(root, namespace)
	writeFile(t, filepath.Join(nsDir, "provd.yaml"), "proxies:\n  - https://dhtproxy2.jami.net\n  - https://dhtproxy3.jami.net\nrepublish_interval: 5m\n")
	writeFile(t, filepath.Join(nsDir, "controller.key"), b64Key(0x01)+"\n")
	writeFile(t, filepath.Join(nsDir, "controller.pub"), b64Key(0x02)+"\n")
	return nsDir
}

// setupNode builds a minimal, valid node directory under
// <root>/<namespace>/nodes/<nodeID> and returns its path.
func setupNode(t *testing.T, root, namespace, nodeID, wgYAML, stunmeshText string) string {
	t.Helper()
	nodeDir := filepath.Join(root, namespace, "nodes", nodeID)
	writeFile(t, filepath.Join(nodeDir, "identity.pub"), b64Key(0x03)+"\n")
	writeFile(t, filepath.Join(nodeDir, "wg.yaml"), wgYAML)
	writeFile(t, filepath.Join(nodeDir, "stunmesh.yaml"), stunmeshText)
	return nodeDir
}

func TestReadDeployment(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")

	dep, err := store.ReadDeployment(root, "test-ns")
	if err != nil {
		t.Fatalf("ReadDeployment: %v", err)
	}

	if dep.Namespace != "test-ns" {
		t.Errorf("Namespace = %q, want test-ns", dep.Namespace)
	}
	wantProxies := []string{"https://dhtproxy2.jami.net", "https://dhtproxy3.jami.net"}
	if len(dep.Proxies) != len(wantProxies) {
		t.Fatalf("Proxies = %v, want %v", dep.Proxies, wantProxies)
	}
	for i, p := range wantProxies {
		if dep.Proxies[i] != p {
			t.Errorf("Proxies[%d] = %q, want %q", i, dep.Proxies[i], p)
		}
	}
	if dep.RepublishInterval != 5*time.Minute {
		t.Errorf("RepublishInterval = %v, want 5m", dep.RepublishInterval)
	}

	wantPriv, _ := crypto.ParseKey(b64Key(0x01))
	wantPub, _ := crypto.ParseKey(b64Key(0x02))
	if dep.ControllerPrivateKey != wantPriv {
		t.Errorf("ControllerPrivateKey mismatch")
	}
	if dep.ControllerPublicKey != wantPub {
		t.Errorf("ControllerPublicKey mismatch")
	}
}

func TestReadDeployment_MissingProvdYAML(t *testing.T) {
	root := t.TempDir()
	nsDir := filepath.Join(root, "test-ns")
	writeFile(t, filepath.Join(nsDir, "controller.key"), b64Key(0x01))
	writeFile(t, filepath.Join(nsDir, "controller.pub"), b64Key(0x02))

	_, err := store.ReadDeployment(root, "test-ns")
	if !errors.Is(err, store.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestReadDeployment_MissingNamespaceDir(t *testing.T) {
	root := t.TempDir()

	_, err := store.ReadDeployment(root, "no-such-ns")
	if !errors.Is(err, store.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestReadDeployment_MalformedProvdYAML(t *testing.T) {
	root := t.TempDir()
	nsDir := setupNamespace(t, root, "test-ns")
	writeFile(t, filepath.Join(nsDir, "provd.yaml"), "proxies: [this is not valid yaml\n")

	_, err := store.ReadDeployment(root, "test-ns")
	if !errors.Is(err, store.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestReadDeployment_BadRepublishInterval(t *testing.T) {
	root := t.TempDir()
	nsDir := setupNamespace(t, root, "test-ns")
	writeFile(t, filepath.Join(nsDir, "provd.yaml"), "proxies:\n  - https://dhtproxy2.jami.net\nrepublish_interval: not-a-duration\n")

	_, err := store.ReadDeployment(root, "test-ns")
	if !errors.Is(err, store.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestReadDeployment_NonPositiveRepublishIntervalIsRejected(t *testing.T) {
	for _, interval := range []string{"0s", "-1m", "0"} {
		root := t.TempDir()
		nsDir := setupNamespace(t, root, "test-ns")
		writeFile(t, filepath.Join(nsDir, "provd.yaml"), "proxies:\n  - https://dhtproxy2.jami.net\nrepublish_interval: "+interval+"\n")

		_, err := store.ReadDeployment(root, "test-ns")
		if !errors.Is(err, store.ErrMalformed) {
			t.Fatalf("interval %q: err = %v, want ErrMalformed", interval, err)
		}
		if !strings.Contains(err.Error(), "provd.yaml") || !strings.Contains(err.Error(), "republish_interval") {
			t.Errorf("interval %q: err = %q, want it to name provd.yaml and republish_interval", interval, err)
		}
	}
}

func TestReadDeployment_BadControllerKey(t *testing.T) {
	root := t.TempDir()
	nsDir := setupNamespace(t, root, "test-ns")
	writeFile(t, filepath.Join(nsDir, "controller.key"), "not base64 at all !!!\n")

	_, err := store.ReadDeployment(root, "test-ns")
	if !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
}

func TestReadDeployment_MissingControllerKey(t *testing.T) {
	root := t.TempDir()
	nsDir := filepath.Join(root, "test-ns")
	writeFile(t, filepath.Join(nsDir, "provd.yaml"), "proxies: []\nrepublish_interval: 5m\n")
	writeFile(t, filepath.Join(nsDir, "controller.pub"), b64Key(0x02))

	_, err := store.ReadDeployment(root, "test-ns")
	if !errors.Is(err, store.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestReadDeployment_RejectsInvalidNamespaceName(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")

	cases := []string{"", ".", "..", "../test-ns", ".hidden", "a/b"}
	for _, name := range cases {
		if _, err := store.ReadDeployment(root, name); err == nil {
			t.Errorf("ReadDeployment(%q): want error, got nil", name)
		}
	}
}

func TestReadNode(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")
	wgYAML := "wg0:\n  private_key: " + b64Key(0x10) + "\n  addresses:\n    - 10.0.0.1/24\n  options: {}\n  routes: []\n  peers:\n    bravo:\n      public_key: " + b64Key(0x11) + "\n      allowed_ips:\n        - 10.0.0.2/32\n"
	setupNode(t, root, "test-ns", "alpha", wgYAML, "plugins:\n  cf: {}\n")

	node, err := store.ReadNode(root, "test-ns", "alpha")
	if err != nil {
		t.Fatalf("ReadNode: %v", err)
	}

	if node.NodeID != "alpha" {
		t.Errorf("NodeID = %q, want alpha", node.NodeID)
	}
	wantIdentity, _ := crypto.ParseKey(b64Key(0x03))
	if node.IdentityPublicKey != wantIdentity {
		t.Errorf("IdentityPublicKey mismatch")
	}
	if node.Stunmesh != "plugins:\n  cf: {}\n" {
		t.Errorf("Stunmesh = %q", node.Stunmesh)
	}

	// The WG field must be the wg.yaml content translated to JSON,
	// preserving explicit-empty containers: "options: {}" and
	// "routes: []" in the YAML must survive as "{}" and "[]" in the
	// JSON, not vanish.
	wgJSON := string(node.WG)
	for _, want := range []string{`"options":{}`, `"routes":[]`, `"private_key"`, `"peers"`} {
		if !strings.Contains(wgJSON, want) {
			t.Errorf("WG JSON = %s, want substring %q", wgJSON, want)
		}
	}
}

func TestReadNode_PresenceSurvivesYAMLToJSON(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")

	// wg0 has no "options" key at all, wg1 has an explicit empty one.
	// The two interfaces must end up distinguishable in the resulting
	// JSON: one must not have "options" at all, the other must have
	// "options":{}.
	wgYAML := "wg0:\n" +
		"  private_key: " + b64Key(0x10) + "\n" +
		"  addresses: [10.0.0.1/24]\n" +
		"  peers: {}\n" +
		"wg1:\n" +
		"  private_key: " + b64Key(0x11) + "\n" +
		"  addresses: [10.0.0.2/24]\n" +
		"  options: {}\n" +
		"  peers: {}\n"
	setupNode(t, root, "test-ns", "alpha", wgYAML, "")

	node, err := store.ReadNode(root, "test-ns", "alpha")
	if err != nil {
		t.Fatalf("ReadNode: %v", err)
	}

	var m map[string]map[string]any
	if err := json.Unmarshal(node.WG, &m); err != nil {
		t.Fatalf("unmarshal WG: %v", err)
	}
	if _, ok := m["wg0"]["options"]; ok {
		t.Errorf("wg0 must not have an options key, got %v", m["wg0"])
	}
	if _, ok := m["wg1"]["options"]; !ok {
		t.Errorf("wg1 must have an explicit options key, got %v", m["wg1"])
	}
}

func TestReadNode_EmptyStunmeshIsLegitimate(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")
	setupNode(t, root, "test-ns", "alpha", "wg0:\n  private_key: x\n  addresses: [a]\n  peers: {}\n", "")

	node, err := store.ReadNode(root, "test-ns", "alpha")
	if err != nil {
		t.Fatalf("ReadNode: %v", err)
	}
	if node.Stunmesh != "" {
		t.Errorf("Stunmesh = %q, want empty", node.Stunmesh)
	}
}

func TestReadNode_MissingStunmeshFile(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")
	nodeDir := filepath.Join(root, "test-ns", "nodes", "alpha")
	writeFile(t, filepath.Join(nodeDir, "identity.pub"), b64Key(0x03))
	writeFile(t, filepath.Join(nodeDir, "wg.yaml"), "wg0:\n  private_key: x\n  addresses: [a]\n  peers: {}\n")

	_, err := store.ReadNode(root, "test-ns", "alpha")
	if !errors.Is(err, store.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestReadNode_MissingWGFile(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")
	nodeDir := filepath.Join(root, "test-ns", "nodes", "alpha")
	writeFile(t, filepath.Join(nodeDir, "identity.pub"), b64Key(0x03))
	writeFile(t, filepath.Join(nodeDir, "stunmesh.yaml"), "")

	_, err := store.ReadNode(root, "test-ns", "alpha")
	if !errors.Is(err, store.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestReadNode_MissingIdentityPub(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")
	nodeDir := filepath.Join(root, "test-ns", "nodes", "alpha")
	writeFile(t, filepath.Join(nodeDir, "wg.yaml"), "wg0:\n  private_key: x\n  addresses: [a]\n  peers: {}\n")
	writeFile(t, filepath.Join(nodeDir, "stunmesh.yaml"), "")

	_, err := store.ReadNode(root, "test-ns", "alpha")
	if !errors.Is(err, store.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestReadNode_BadIdentityKey(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")
	nodeDir := filepath.Join(root, "test-ns", "nodes", "alpha")
	writeFile(t, filepath.Join(nodeDir, "identity.pub"), "not valid base64 !!!")
	writeFile(t, filepath.Join(nodeDir, "wg.yaml"), "wg0:\n  private_key: x\n  addresses: [a]\n  peers: {}\n")
	writeFile(t, filepath.Join(nodeDir, "stunmesh.yaml"), "")

	_, err := store.ReadNode(root, "test-ns", "alpha")
	if !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
}

func TestReadNode_MalformedWGYAML(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")
	setupNode(t, root, "test-ns", "alpha", "wg0: [this is not, valid: yaml\n", "")

	_, err := store.ReadNode(root, "test-ns", "alpha")
	if !errors.Is(err, store.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestReadNode_RejectsInvalidNodeIDName(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")
	setupNode(t, root, "test-ns", "alpha", "wg0:\n  private_key: x\n  addresses: [a]\n  peers: {}\n", "")

	cases := []string{"", ".", "..", "../alpha", ".hidden", "a/b"}
	for _, name := range cases {
		if _, err := store.ReadNode(root, "test-ns", name); err == nil {
			t.Errorf("ReadNode(%q): want error, got nil", name)
		}
	}
}

func TestNamespaces(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "ns-a")
	setupNamespace(t, root, "ns-b")
	writeFile(t, filepath.Join(root, "README.md"), "explains the layout\n")
	if err := os.Mkdir(filepath.Join(root, ".hidden"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	got, err := store.Namespaces(root)
	if err != nil {
		t.Fatalf("Namespaces: %v", err)
	}

	want := []string{"ns-a", "ns-b"}
	if len(got) != len(want) {
		t.Fatalf("Namespaces = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("Namespaces[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestNamespaces_MissingRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := store.Namespaces(root)
	if !errors.Is(err, store.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestNodes(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")
	setupNode(t, root, "test-ns", "alpha", "wg0:\n  private_key: x\n  addresses: [a]\n  peers: {}\n", "")
	setupNode(t, root, "test-ns", "bravo", "wg0:\n  private_key: x\n  addresses: [a]\n  peers: {}\n", "")
	// A stray regular file inside nodes/ must be skipped, not treated
	// as a node.
	writeFile(t, filepath.Join(root, "test-ns", "nodes", "notes.txt"), "not a node\n")

	got, err := store.Nodes(root, "test-ns")
	if err != nil {
		t.Fatalf("Nodes: %v", err)
	}

	want := []string{"alpha", "bravo"}
	if len(got) != len(want) {
		t.Fatalf("Nodes = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("Nodes[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestNodes_InvalidNamespaceName(t *testing.T) {
	root := t.TempDir()

	if _, err := store.Nodes(root, ".."); err == nil {
		t.Fatal("want error for invalid namespace name")
	}
}

func TestReadDeployment_ProvdYAMLIsADirectory(t *testing.T) {
	root := t.TempDir()
	nsDir := setupNamespace(t, root, "test-ns")
	provdPath := filepath.Join(nsDir, "provd.yaml")
	if err := os.Remove(provdPath); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.Mkdir(provdPath, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	_, err := store.ReadDeployment(root, "test-ns")
	if err == nil {
		t.Fatal("want error when provd.yaml is a directory")
	}
	if errors.Is(err, store.ErrNotExist) {
		t.Fatalf("err = %v, want a generic read error, not ErrNotExist", err)
	}
}

func TestNodes_MissingNodesDir(t *testing.T) {
	root := t.TempDir()
	setupNamespace(t, root, "test-ns")

	_, err := store.Nodes(root, "test-ns")
	if !errors.Is(err, store.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

// TestNoSecretInErrorMessages checks that a bad key file and a
// malformed wg.yaml (both of which may contain private key material)
// never surface their content in an error message.
func TestNoSecretInErrorMessages(t *testing.T) {
	const secret = "TopSecretPrivateKeyMaterial12345"

	root := t.TempDir()
	nsDir := setupNamespace(t, root, "test-ns")
	writeFile(t, filepath.Join(nsDir, "controller.key"), secret)

	_, err := store.ReadDeployment(root, "test-ns")
	if err == nil {
		t.Fatal("want error for bad controller.key")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks secret: %v", err)
	}

	nodeDir := filepath.Join(root, "test-ns", "nodes", "alpha")
	writeFile(t, filepath.Join(nodeDir, "identity.pub"), secret)
	writeFile(t, filepath.Join(nodeDir, "wg.yaml"), "wg0:\n  private_key: "+secret+"\n  addresses: [this is not, valid: yaml\n")
	writeFile(t, filepath.Join(nodeDir, "stunmesh.yaml"), "")

	_, err = store.ReadNode(root, "test-ns", "alpha")
	if err == nil {
		t.Fatal("want error for bad identity.pub / malformed wg.yaml")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks secret: %v", err)
	}
}
