package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
)

// sealTestBundle builds a minimal, well-formed bundle JSON with the
// given timestamp, namespace "ns" and node_id "n1" (the values every
// test in this file uses for the receiving node), and seals it from
// senderPriv to recipientPub, as stunmesh-provd publish_cmd.go does
// (controller is the sender, node identity is the recipient).
func sealTestBundle(t *testing.T, timestamp int64, senderPriv, recipientPub crypto.Key) []byte {
	t.Helper()
	return sealTestBundleFor(t, "ns", "n1", timestamp, senderPriv, recipientPub)
}

// sealTestBundleFor is sealTestBundle with an explicit namespace and
// node_id, for tests that need a bundle addressed to a different node
// than the receiving one under test.
func sealTestBundleFor(t *testing.T, namespace, nodeID string, timestamp int64, senderPriv, recipientPub crypto.Key) []byte {
	t.Helper()
	plain := []byte(fmt.Sprintf(`{"version":1,"namespace":%q,"node_id":%q,"timestamp":%d,"wg":{},"stunmesh":""}`, namespace, nodeID, timestamp))
	sealed, err := crypto.Seal(plain, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed
}

// sealTestBundleInvalidField builds a bundle JSON that parses (phase 1
// passes) but fails a phase 2 check: listen_port out of range
// (docs/format.md 6, check 13).
func sealTestBundleInvalidField(t *testing.T, timestamp int64, senderPriv, recipientPub crypto.Key) []byte {
	t.Helper()
	plain := []byte(fmt.Sprintf(`{"version":1,"namespace":"ns","node_id":"n1","timestamp":%d,"wg":{"wg0":{"private_key":"x","addresses":["10.0.0.1/24"],"listen_port":70000,"peers":{}}},"stunmesh":""}`, timestamp))
	sealed, err := crypto.Seal(plain, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed
}

func TestDecryptAndSelect_KeepsNewestAmongMultiple(t *testing.T) {
	senderPriv, _, _ := crypto.Keygen()
	recipientPriv, recipientPub, _ := crypto.Keygen()
	senderPub := crypto.Public(senderPriv)

	values := [][]byte{
		sealTestBundle(t, 100, senderPriv, recipientPub),
		sealTestBundle(t, 300, senderPriv, recipientPub),
		sealTestBundle(t, 200, senderPriv, recipientPub),
	}

	best, stats := decryptAndSelect(values, senderPub, recipientPriv, "ns", "n1")
	if best == nil {
		t.Fatalf("decryptAndSelect returned nil, want the value with timestamp 300")
	}
	if best.Timestamp != 300 {
		t.Errorf("best.Timestamp = %d, want 300", best.Timestamp)
	}
	if stats.Undecrypted != 0 || stats.Unparsed != 0 {
		t.Errorf("stats = %+v, want all values to decrypt and parse", stats)
	}
}

func TestDecryptAndSelect_SkipsValuesThatFailToDecrypt(t *testing.T) {
	senderPriv, _, _ := crypto.Keygen()
	recipientPriv, recipientPub, _ := crypto.Keygen()
	senderPub := crypto.Public(senderPriv)

	otherPriv, _, _ := crypto.Keygen()
	otherPub := crypto.Public(otherPriv)

	values := [][]byte{
		// Sealed for a different recipient: this node cannot open it.
		sealTestBundle(t, 999, senderPriv, otherPub),
		// Third-party junk: not even a valid sealed value.
		[]byte("not a sealed value at all"),
		sealTestBundle(t, 150, senderPriv, recipientPub),
	}

	best, stats := decryptAndSelect(values, senderPub, recipientPriv, "ns", "n1")
	if best == nil {
		t.Fatalf("decryptAndSelect returned nil, want the one value sealed for this node")
	}
	if best.Timestamp != 150 {
		t.Errorf("best.Timestamp = %d, want 150", best.Timestamp)
	}
	if stats.Undecrypted != 2 {
		t.Errorf("stats.Undecrypted = %d, want 2", stats.Undecrypted)
	}
}

func TestDecryptAndSelect_SkipsValuesThatDecryptButDoNotParse(t *testing.T) {
	senderPriv, _, _ := crypto.Keygen()
	recipientPriv, recipientPub, _ := crypto.Keygen()
	senderPub := crypto.Public(senderPriv)

	garbled, err := crypto.Seal([]byte("not json at all"), recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	values := [][]byte{
		garbled,
		sealTestBundle(t, 50, senderPriv, recipientPub),
	}

	best, stats := decryptAndSelect(values, senderPub, recipientPriv, "ns", "n1")
	if best == nil {
		t.Fatalf("decryptAndSelect returned nil, want the one parseable value")
	}
	if best.Timestamp != 50 {
		t.Errorf("best.Timestamp = %d, want 50", best.Timestamp)
	}
	if stats.Unparsed != 1 {
		t.Errorf("stats.Unparsed = %d, want 1", stats.Unparsed)
	}
}

func TestDecryptAndSelect_TieKeepsFirstEncountered(t *testing.T) {
	senderPriv, _, _ := crypto.Keygen()
	recipientPriv, recipientPub, _ := crypto.Keygen()
	senderPub := crypto.Public(senderPriv)

	first := sealTestBundle(t, 100, senderPriv, recipientPub)
	second := sealTestBundle(t, 100, senderPriv, recipientPub)

	best, _ := decryptAndSelect([][]byte{first, second}, senderPub, recipientPriv, "ns", "n1")
	if best == nil {
		t.Fatalf("decryptAndSelect returned nil")
	}
	// Both decrypt to equal-timestamp bundles; the rule (documented on
	// decryptAndSelect) is that the first one encountered wins. There
	// is no observable difference in this case since the content is
	// identical, but the rule itself is what's under test here: a
	// later exact tie must not silently replace the earlier pick.
	if best.Timestamp != 100 {
		t.Errorf("best.Timestamp = %d, want 100", best.Timestamp)
	}
}

func TestDecryptAndSelect_NoValuesReturnsNil(t *testing.T) {
	recipientPriv, _, _ := crypto.Keygen()
	senderPriv, _, _ := crypto.Keygen()
	senderPub := crypto.Public(senderPriv)

	best, stats := decryptAndSelect(nil, senderPub, recipientPriv, "ns", "n1")
	if best != nil {
		t.Errorf("best = %+v, want nil", best)
	}
	if stats.Undecrypted != 0 || stats.Unparsed != 0 {
		t.Errorf("stats = %+v, want zero", stats)
	}
}

func TestDecryptAndSelect_NoValueDecryptsReturnsNil(t *testing.T) {
	recipientPriv, recipientPub, _ := crypto.Keygen()
	senderPriv, _, _ := crypto.Keygen()
	senderPub := crypto.Public(senderPriv)

	otherPriv, _, _ := crypto.Keygen()
	otherPub := crypto.Public(otherPriv)

	values := [][]byte{
		sealTestBundle(t, 100, senderPriv, otherPub),
	}
	_ = recipientPub

	best, stats := decryptAndSelect(values, senderPub, recipientPriv, "ns", "n1")
	if best != nil {
		t.Errorf("best = %+v, want nil", best)
	}
	if stats.Undecrypted != 1 {
		t.Errorf("stats.Undecrypted = %d, want 1", stats.Undecrypted)
	}
}

func TestDecryptAndSelect_RejectsValueForAnotherNamespace(t *testing.T) {
	senderPriv, _, _ := crypto.Keygen()
	recipientPriv, recipientPub, _ := crypto.Keygen()
	senderPub := crypto.Public(senderPriv)

	values := [][]byte{
		// Decrypts (sealed for this node's key) but the namespace does
		// not match: phase 2 check 8 (docs/format.md 6) must reject it.
		sealTestBundleFor(t, "other-ns", "n1", 999, senderPriv, recipientPub),
	}

	best, stats := decryptAndSelect(values, senderPub, recipientPriv, "ns", "n1")
	if best != nil {
		t.Errorf("best = %+v, want nil (wrong namespace must be rejected)", best)
	}
	if stats.Rejected != 1 {
		t.Errorf("stats.Rejected = %d, want 1", stats.Rejected)
	}
}

func TestDecryptAndSelect_RejectsValueThatFailsAFieldRule(t *testing.T) {
	senderPriv, _, _ := crypto.Keygen()
	recipientPriv, recipientPub, _ := crypto.Keygen()
	senderPub := crypto.Public(senderPriv)

	values := [][]byte{
		// Parses (phase 1 passes) but listen_port is out of range:
		// phase 2 check 13 must reject it.
		sealTestBundleInvalidField(t, 500, senderPriv, recipientPub),
	}

	best, stats := decryptAndSelect(values, senderPub, recipientPriv, "ns", "n1")
	if best != nil {
		t.Errorf("best = %+v, want nil (an out-of-range field must be rejected)", best)
	}
	if stats.Rejected != 1 {
		t.Errorf("stats.Rejected = %d, want 1", stats.Rejected)
	}
}

// TestDecryptAndSelect_OlderValidBeatsNewerInvalid pins the key
// decision of this item (see decryptAndSelect's doc comment): a newer
// value that fails a PLAN.md 4.4 check must never be selected over an
// older value that passes every check, even though PLAN.md 4.6 says
// "keep the largest timestamp" in isolation.
func TestDecryptAndSelect_OlderValidBeatsNewerInvalid(t *testing.T) {
	senderPriv, _, _ := crypto.Keygen()
	recipientPriv, recipientPub, _ := crypto.Keygen()
	senderPub := crypto.Public(senderPriv)

	values := [][]byte{
		sealTestBundle(t, 100, senderPriv, recipientPub), // older, valid
		// newer, but wrong namespace: must be rejected, not selected.
		sealTestBundleFor(t, "other-ns", "n1", 900, senderPriv, recipientPub),
	}

	best, stats := decryptAndSelect(values, senderPub, recipientPriv, "ns", "n1")
	if best == nil {
		t.Fatalf("decryptAndSelect returned nil, want the older valid value")
	}
	if best.Timestamp != 100 {
		t.Errorf("best.Timestamp = %d, want 100 (the older, valid value)", best.Timestamp)
	}
	if stats.Rejected != 1 {
		t.Errorf("stats.Rejected = %d, want 1", stats.Rejected)
	}
}

func TestLoadIdentityKey_MissingFile(t *testing.T) {
	_, err := loadIdentityKey(filepath.Join(t.TempDir(), "no-such-file"))
	if err == nil {
		t.Fatal("loadIdentityKey: want an error for a missing file")
	}
}

func TestLoadIdentityKey_MalformedFileNeverEchoesContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	secretLooking := "super-secret-not-a-real-key-value"
	if err := os.WriteFile(path, []byte(secretLooking), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := loadIdentityKey(path)
	if err == nil {
		t.Fatal("loadIdentityKey: want an error for a malformed key file")
	}
	if strings.Contains(err.Error(), secretLooking) {
		t.Errorf("error leaks file content: %v", err)
	}
}

func TestLoadIdentityKey_ValidFile(t *testing.T) {
	priv, _, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	path := filepath.Join(t.TempDir(), "identity.key")
	if err := os.WriteFile(path, []byte(priv.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := loadIdentityKey(path)
	if err != nil {
		t.Fatalf("loadIdentityKey: %v", err)
	}
	if got != priv {
		t.Errorf("loadIdentityKey returned a different key than written")
	}
}
