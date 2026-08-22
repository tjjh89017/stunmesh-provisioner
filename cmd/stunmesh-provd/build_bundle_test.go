package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// filledWGYAML is a minimal but complete wg.yaml body: one interface,
// one peer, nothing optional. It is valid input to buildBundle.
const filledWGYAML = `wg0:
  private_key: cGxhY2Vob2xkZXItcHJpdmF0ZS1rZXktMzItYnl0ZXMh
  addresses:
    - 10.0.0.1/24
  peers:
    bravo:
      public_key: cGxhY2Vob2xkZXItcHVibGljLWtleS0zMi1ieXRlcyE=
      allowed_ips:
        - 10.0.0.2/32
`

func fixedNow() time.Time {
	return time.Date(2025, 8, 21, 12, 0, 0, 0, time.UTC)
}

// testNode builds a *store.Node from a wg.yaml body and a stunmesh.yaml
// body, without touching the file system. It mirrors what
// store.ReadNode returns.
func testNode(t *testing.T, nodeID, wgYAML, stunmesh string) *store.Node {
	t.Helper()
	root := t.TempDir()
	initTestNamespace(t, root, "myns")

	_, pub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	env, _, stderr := newTestEnv(root)
	if code := runNodeAdd(env, []string{"myns", nodeID, pub.String()}); code != ExitOK {
		t.Fatalf("runNodeAdd code = %d, stderr = %q", code, stderr.String())
	}
	nodeDir := filepath.Join(root, "myns", "nodes", nodeID)
	mustWriteFile(t, filepath.Join(nodeDir, "wg.yaml"), wgYAML)
	mustWriteFile(t, filepath.Join(nodeDir, "stunmesh.yaml"), stunmesh)

	node, err := store.ReadNode(root, "myns", nodeID)
	if err != nil {
		t.Fatalf("ReadNode: %v", err)
	}
	return node
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func TestBuildBundle_UneditedTemplateIsRejectedWithActionableError(t *testing.T) {
	node := testNode(t, "alpha", wgYAMLTemplate, stunmeshYAMLTemplate)

	_, err := buildBundle("myns", node, fixedNow())
	if err == nil {
		t.Fatal("buildBundle succeeded, want an error for the unedited template")
	}
	if errors.Is(err, bundle.ErrNull) {
		t.Fatalf("error is bare bundle.ErrNull, want an operator-facing wrapper: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "alpha") {
		t.Errorf("error %q does not name the node", msg)
	}
	if !strings.Contains(msg, "wg.yaml") {
		t.Errorf("error %q does not name wg.yaml", msg)
	}
	if !strings.Contains(msg, "template") && !strings.Contains(msg, "unedited") {
		t.Errorf("error %q does not explain that the file needs filling in: %v", msg, err)
	}
}

func TestBuildBundle_GenuineNestedNullStillReportsErrNull(t *testing.T) {
	// A filled-in file that still smuggles a nested null must not be
	// mistaken for the unedited-template case: the top-level wg.yaml
	// document is an object here, not the literal `null` document.
	wg := `wg0:
  private_key: cGxhY2Vob2xkZXItcHJpdmF0ZS1rZXktMzItYnl0ZXMh
  addresses:
    - 10.0.0.1/24
  mtu: null
  peers:
    bravo:
      public_key: cGxhY2Vob2xkZXItcHVibGljLWtleS0zMi1ieXRlcyE=
      allowed_ips:
        - 10.0.0.2/32
`
	node := testNode(t, "alpha", wg, "")

	_, err := buildBundle("myns", node, fixedNow())
	if err == nil {
		t.Fatal("buildBundle succeeded, want an error for a nested null")
	}
	if !errors.Is(err, bundle.ErrNull) {
		t.Fatalf("error = %v, want it to wrap bundle.ErrNull", err)
	}
}

func TestBuildBundle_ValidNodeProducesValidatedBundle(t *testing.T) {
	node := testNode(t, "alpha", filledWGYAML, "interfaces: {}\n")

	b, err := buildBundle("myns", node, fixedNow())
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	if b.Namespace != "myns" || b.NodeID != "alpha" {
		t.Fatalf("bundle namespace/node_id = %q/%q, want myns/alpha", b.Namespace, b.NodeID)
	}
	if b.Timestamp != fixedNow().Unix() {
		t.Fatalf("bundle timestamp = %d, want %d", b.Timestamp, fixedNow().Unix())
	}
	if err := b.Validate("myns", "alpha"); err != nil {
		t.Fatalf("returned bundle does not validate: %v", err)
	}
}

func TestBuildBundle_ExplicitEmptyWGIsAccepted(t *testing.T) {
	// "{}" is a real, deliberate document: it means "remove every
	// interface" and must not be confused with the unedited-template
	// "null" document.
	node := testNode(t, "alpha", "{}\n", "")

	b, err := buildBundle("myns", node, fixedNow())
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	if len(b.WG) != 0 {
		t.Fatalf("WG = %v, want empty map", b.WG)
	}
}

func TestBuildBundle_TimestampExcludedFromCanonicalStaysStableAcrossBuilds(t *testing.T) {
	node := testNode(t, "alpha", filledWGYAML, "interfaces: {}\n")

	b1, err := buildBundle("myns", node, fixedNow())
	if err != nil {
		t.Fatalf("buildBundle #1: %v", err)
	}
	b2, err := buildBundle("myns", node, fixedNow().Add(time.Hour))
	if err != nil {
		t.Fatalf("buildBundle #2: %v", err)
	}
	if b1.Timestamp == b2.Timestamp {
		t.Fatalf("timestamps unexpectedly equal, test is not exercising the property")
	}

	c1, err := b1.Canonical()
	if err != nil {
		t.Fatalf("Canonical #1: %v", err)
	}
	c2, err := b2.Canonical()
	if err != nil {
		t.Fatalf("Canonical #2: %v", err)
	}
	if string(c1) != string(c2) {
		t.Fatalf("canonical bytes differ across builds with different timestamps:\n%s\n%s", c1, c2)
	}
}

func TestBuildBundle_OversizedBundleIsRejected(t *testing.T) {
	// A single, absurdly long address list pushes the inner JSON past
	// maxInnerBundleSize without needing a real 56 KiB fixture file.
	var b strings.Builder
	b.WriteString("wg0:\n  private_key: cGxhY2Vob2xkZXItcHJpdmF0ZS1rZXktMzItYnl0ZXMh\n  addresses:\n")
	for i := 0; i < 6000; i++ {
		b.WriteString("    - 10.0.0.1/24\n")
	}
	b.WriteString("  peers:\n    bravo:\n      public_key: cGxhY2Vob2xkZXItcHVibGljLWtleS0zMi1ieXRlcyE=\n      allowed_ips:\n        - 10.0.0.2/32\n")

	node := testNode(t, "alpha", b.String(), "")

	_, err := buildBundle("myns", node, fixedNow())
	if err == nil {
		t.Fatal("buildBundle succeeded, want an error for an oversized bundle")
	}
	if !strings.Contains(err.Error(), "alpha") {
		t.Errorf("error %q does not name the node", err.Error())
	}
}
