package main

// This file pins three acceptance criteria for the controller:
//
//	(a) `publish --once` against a fake proxy produces a value that
//	    internal/crypto.Open decrypts to the expected bundle.
//	(b) the republish loop re-puts identical bytes across rounds
//	    within one running process, as long as canonical bundle
//	    content and identity.pub are unchanged.
//	(c) the tool never modifies wg.yaml, stunmesh.yaml, or provd.yaml.
//
// Every test here builds its tree with the real runInit and
// runNodeAdd command functions, and reaches the DHT only through an
// httptest fake proxy (see capturingProxy in publish_cmd_test.go), so
// each test exercises the same path an operator would drive by hand.
//
// crypto.Seal draws a fresh random nonce on every call, so two
// separate `publish --once` process invocations seal the same
// plaintext bundle to different ciphertext, even when every file on
// disk is byte-for-byte unchanged between them.
// TestAcceptance_TwoSeparatePublishOnceInvocationsProduceDifferentBytes
// pins that. TestAcceptance_LoopPutsIdenticalBytesAcrossRoundsWhenUnchanged
// pins the narrower guarantee that actually holds: unchanged content
// re-puts identical bytes only within one running republish loop.
//
// The republish loop's own reseal-on-change behavior (a content edit,
// or an identity.pub change, forces a fresh seal even inside one
// running loop) is already pinned by
// TestRunRepublishLoop_ContentChangeReseals and
// TestRunRepublishLoop_IdentityKeyChangeReseals in
// republish_loop_test.go; this file does not repeat them.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtkey"
)

// decryptedBundle is the subset of the inner bundle JSON this file's
// tests check field-by-field. It mirrors the bundle's shape closely
// enough to compare wg.yaml/stunmesh.yaml content end to end, without
// pulling in internal/bundle's full validation-oriented type.
type decryptedBundle struct {
	Version   int    `json:"version"`
	Namespace string `json:"namespace"`
	NodeID    string `json:"node_id"`
	WG        map[string]struct {
		PrivateKey string   `json:"private_key"`
		Addresses  []string `json:"addresses"`
		Peers      map[string]struct {
			PublicKey  string   `json:"public_key"`
			AllowedIPs []string `json:"allowed_ips"`
		} `json:"peers"`
	} `json:"wg"`
	Stunmesh string `json:"stunmesh"`
}

// TestAcceptance_PublishOnceDecryptsToExpectedBundle pins criterion
// (a). It builds a namespace and a node through runInit/runNodeAdd,
// writes a wg.yaml and stunmesh.yaml with known content, runs
// `publish --once` against an httptest fake proxy, decrypts the
// captured value with crypto.Open using the node's own identity
// private key, and checks the decrypted fields against the exact
// input content -- not merely that decryption succeeded.
func TestAcceptance_PublishOnceDecryptsToExpectedBundle(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, controllerPub := setupPublishTestNamespace(t, []string{srv.URL})

	identityPriv, identityPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	if code := runNodeAdd(env, []string{namespace, "alpha", identityPub.String()}); code != ExitOK {
		t.Fatalf("runNodeAdd: code=%d", code)
	}

	const wgYAML = `wg0:
  private_key: cGxhY2Vob2xkZXItcHJpdmF0ZS1rZXktMzItYnl0ZXMh
  addresses:
    - 10.0.0.42/24
  peers:
    bravo:
      public_key: cGxhY2Vob2xkZXItcHVibGljLWtleS0zMi1ieXRlcyE=
      allowed_ips:
        - 10.0.0.2/32
`
	const stunmeshYAML = "listen_port: 12345\n"

	nodeDir := filepath.Join(env.Dir, namespace, "nodes", "alpha")
	mustWriteFile(t, filepath.Join(nodeDir, "wg.yaml"), wgYAML)
	mustWriteFile(t, filepath.Join(nodeDir, "stunmesh.yaml"), stunmeshYAML)

	if code := runPublish(env, []string{"--once"}); code != ExitOK {
		t.Fatalf("runPublish --once: code=%d stderr=%q", code, env.Stderr.(interface{ String() string }).String())
	}

	key, err := dhtkey.Key(namespace, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}
	fields := proxy.dataFieldsFor(key)
	if len(fields) != 1 {
		t.Fatalf("proxy received %d puts for key %s, want 1", len(fields), key)
	}

	sealed, err := base64.StdEncoding.DecodeString(fields[0])
	if err != nil {
		t.Fatalf("captured data field is not valid base64: %v", err)
	}

	plain, err := crypto.Open(sealed, controllerPub, identityPriv)
	if err != nil {
		t.Fatalf("crypto.Open(captured value): %v", err)
	}

	var got decryptedBundle
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatalf("decrypted plaintext is not valid JSON: %v", err)
	}

	if got.Version != 1 {
		t.Errorf("version = %d, want 1", got.Version)
	}
	if got.Namespace != namespace {
		t.Errorf("namespace = %q, want %q", got.Namespace, namespace)
	}
	if got.NodeID != "alpha" {
		t.Errorf("node_id = %q, want %q", got.NodeID, "alpha")
	}

	wg0, ok := got.WG["wg0"]
	if !ok {
		t.Fatalf("decrypted wg has no wg0 interface: %+v", got.WG)
	}
	if wg0.PrivateKey != "cGxhY2Vob2xkZXItcHJpdmF0ZS1rZXktMzItYnl0ZXMh" {
		t.Errorf("wg0.private_key = %q, want the value from wg.yaml", wg0.PrivateKey)
	}
	if len(wg0.Addresses) != 1 || wg0.Addresses[0] != "10.0.0.42/24" {
		t.Errorf("wg0.addresses = %v, want [10.0.0.42/24] from wg.yaml", wg0.Addresses)
	}
	bravo, ok := wg0.Peers["bravo"]
	if !ok {
		t.Fatalf("wg0 has no bravo peer: %+v", wg0.Peers)
	}
	if bravo.PublicKey != "cGxhY2Vob2xkZXItcHVibGljLWtleS0zMi1ieXRlcyE=" {
		t.Errorf("bravo.public_key = %q, want the value from wg.yaml", bravo.PublicKey)
	}
	if len(bravo.AllowedIPs) != 1 || bravo.AllowedIPs[0] != "10.0.0.2/32" {
		t.Errorf("bravo.allowed_ips = %v, want [10.0.0.2/32] from wg.yaml", bravo.AllowedIPs)
	}
	if got.Stunmesh != stunmeshYAML {
		t.Errorf("stunmesh = %q, want the exact content of stunmesh.yaml %q", got.Stunmesh, stunmeshYAML)
	}
}

// TestAcceptance_TwoSeparatePublishOnceInvocationsProduceDifferentBytes
// documents, in code, the actual behavior of two separate `publish
// --once` process invocations over unchanged files: they put
// different bytes, because crypto.Seal draws a fresh random nonce on
// every call and there is no state file to persist sealed bytes
// between process invocations.
func TestAcceptance_TwoSeparatePublishOnceInvocationsProduceDifferentBytes(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	addPublishTestNode(t, env, namespace, "alpha")

	key, err := dhtkey.Key(namespace, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}

	if code := runPublish(env, []string{"--once"}); code != ExitOK {
		t.Fatalf("runPublish --once (1st invocation): code=%d", code)
	}
	if code := runPublish(env, []string{"--once"}); code != ExitOK {
		t.Fatalf("runPublish --once (2nd invocation): code=%d", code)
	}

	fields := proxy.dataFieldsFor(key)
	if len(fields) != 2 {
		t.Fatalf("proxy received %d puts, want 2", len(fields))
	}
	if fields[0] == fields[1] {
		t.Fatal("two separate `publish --once` invocations over unchanged files put identical bytes; " +
			"this contradicts crypto.Seal's random nonce")
	}
}

// TestAcceptance_LoopPutsIdenticalBytesAcrossRoundsWhenUnchanged pins
// the behavior specified for criterion (b): the republish loop
// re-puts the identical, cached sealed bytes on a second round within
// the same running process, as long as the canonical bundle content
// and identity.pub have not changed.
//
// This overlaps with
// TestRunRepublishLoop_UnchangedContentPutsIdenticalBytesAcrossRounds
// in republish_loop_test.go; this test is kept short and named for
// the Acceptance criterion so a reviewer can find the criterion's pin
// without cross-referencing another file.
func TestAcceptance_LoopPutsIdenticalBytesAcrossRoundsWhenUnchanged(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	setRepublishInterval(t, env, namespace, "1ns")
	addPublishTestNode(t, env, namespace, "alpha")

	key, err := dhtkey.Key(namespace, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}

	runLoopRounds(t, env, "", 2, nil)

	fields := proxy.dataFieldsFor(key)
	if len(fields) != 2 {
		t.Fatalf("proxy received %d puts, want 2", len(fields))
	}
	if fields[0] != fields[1] {
		t.Fatal("two consecutive rounds of the republish loop over unchanged files put different bytes")
	}
}

// TestAcceptance_PublishNeverModifiesOperatorFiles pins criterion (c).
// It snapshots the content and modification time of provd.yaml,
// wg.yaml, and stunmesh.yaml, runs `publish --once` twice and then a
// few rounds of the republish loop -- every code path that reads
// these files -- and checks nothing about them changed.
//
// Content equality is the primary check here (a byte-for-byte
// os.ReadFile comparison). The modification time is compared too,
// and a change fails the test with t.Errorf: on this test's tree,
// nothing but the code under test touches these files between the
// snapshots, so an mtime that moved means a real write happened --
// even one that rewrote identical bytes and would slip past the
// content check -- and failing on it is deterministic, not flaky.
// The asymmetry runs the other way: a filesystem with second-level
// (or coarser) mtime resolution could in principle mask a real write
// that landed on the same tick, so an unchanged mtime is never taken
// as proof of no write -- content equality must still hold.
func TestAcceptance_PublishNeverModifiesOperatorFiles(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	addPublishTestNode(t, env, namespace, "alpha")
	// Set the republish interval to its smallest value now, as a
	// simulated operator edit, before the "before" snapshot below: so
	// the loop rounds below fire immediately. This test's own setup
	// writes provd.yaml, so it must not be mistaken for a write made by
	// publish or the loop.
	setRepublishInterval(t, env, namespace, "1ns")

	provdPath := filepath.Join(env.Dir, namespace, "provd.yaml")
	wgPath := filepath.Join(env.Dir, namespace, "nodes", "alpha", "wg.yaml")
	stunmeshPath := filepath.Join(env.Dir, namespace, "nodes", "alpha", "stunmesh.yaml")
	paths := []string{provdPath, wgPath, stunmeshPath}

	type snapshot struct {
		content []byte
		modTime time.Time
	}
	snap := func(path string) snapshot {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", path, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%s): %v", path, err)
		}
		return snapshot{content: data, modTime: info.ModTime()}
	}

	before := make(map[string]snapshot, len(paths))
	for _, p := range paths {
		before[p] = snap(p)
	}

	// Exercise every code path that reads these files: two separate
	// --once rounds, then a few rounds of the republish loop.
	if code := runPublish(env, []string{"--once"}); code != ExitOK {
		t.Fatalf("runPublish --once (1st): code=%d", code)
	}
	if code := runPublish(env, []string{"--once"}); code != ExitOK {
		t.Fatalf("runPublish --once (2nd): code=%d", code)
	}
	runLoopRounds(t, env, "", 3, nil)

	// Guard against a vacuous pass. Every check below is "nothing
	// changed", which is trivially true if the rounds above published
	// nothing at all: if node discovery ever regressed to finding zero
	// nodes, runPublish would still return ExitOK ("nothing to
	// publish") and the loop rounds would be no-ops, so the file
	// comparison would stay green while proving nothing about criterion
	// (c). Pin that the rounds really did reach the DHT: 2 `--once`
	// invocations + 3 loop rounds against the single node alpha.
	key, err := dhtkey.Key(namespace, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}
	if got, want := len(proxy.dataFieldsFor(key)), 5; got != want {
		t.Fatalf("proxy received %d puts for key %s, want %d (2 `publish --once` invocations + 3 republish loop rounds); "+
			"without this the checks below would be vacuous -- a run that published nothing "+
			"also modifies no operator files and would pass criterion (c) for the wrong reason", got, key, want)
	}

	for _, p := range paths {
		after := snap(p)
		if !bytes.Equal(before[p].content, after.content) {
			t.Errorf("%s content changed: stunmesh-provd must never edit operator files", p)
		}
		if !after.modTime.Equal(before[p].modTime) {
			t.Errorf("%s modification time changed from %v to %v: stunmesh-provd must never write this file", p, before[p].modTime, after.modTime)
		}
	}
}
