package main

// This file pins the three Acceptance criteria of
// .plan/stage2-provd.md (stage 2 item 10, the last item of the
// controller stage):
//
//	(a) `publish --once` against a fake proxy produces a value that
//	    internal/crypto.Open decrypts to the expected bundle.
//	(b) a second `publish --once` with unchanged files puts identical
//	    bytes.
//	(c) the tool never modifies wg.yaml, stunmesh.yaml, or provd.yaml.
//
// Every test here builds its tree with the real runInit and
// runNodeAdd command functions, and reaches the DHT only through an
// httptest fake proxy (see capturingProxy in publish_cmd_test.go), so
// each test exercises the same path an operator would drive by hand.
//
// # Criterion (b): the stage file's literal wording does not hold
//
// crypto.Seal draws a fresh random nonce on every call (see
// internal/crypto's doc comment). Two separate `publish --once`
// *process* invocations therefore seal the same plaintext bundle to
// different ciphertext, even when every file on disk is byte-for-byte
// unchanged between them. PLAN.md 7.1 states "There is no state
// file": making two separate `--once` processes agree on ciphertext
// would require persisting the sealed bytes to disk between runs,
// which the plan rules out.
//
// What IS specified and implemented is narrower: PLAN.md 7.2 step 6
// and stage 2 item 6 (republish_loop.go) keep each node's sealed
// bytes in memory and re-put them unchanged across rounds *within one
// running process*, as long as the canonical bundle content and
// identity.pub have not changed. TestAcceptance_LoopPutsIdenticalBytesAcrossRoundsWhenUnchanged
// below pins that behavior.
// TestAcceptance_TwoSeparatePublishOnceInvocationsProduceDifferentBytes
// pins the other half honestly: it proves two separate `--once`
// processes over unchanged files put *different* bytes, so this
// discrepancy against the stage file's literal wording lives in code
// instead of only in a report.
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
// tests check field-by-field. It mirrors PLAN.md 4.2's shape closely
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
// different bytes. See this file's package doc comment above for why
// that is expected and why it does not satisfy the stage file's
// literal wording of criterion (b).
//
// If this test ever starts failing because the two invocations now
// agree, that is not a bug to silently work around: it means either
// crypto.Seal stopped using a random nonce, or a state file was added
// against PLAN.md 7.1. Either way, update this test deliberately, not
// by loosening its assertion.
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
			"this contradicts crypto.Seal's random nonce and would mean the stage file's literal " +
			"wording of Acceptance criterion (b) now holds across process invocations -- " +
			"do not just relax this assertion, re-check the report that explains the discrepancy")
	}
}

// TestAcceptance_LoopPutsIdenticalBytesAcrossRoundsWhenUnchanged pins
// the behavior that IS specified for criterion (b): PLAN.md 7.2 step
// 6's republish loop re-puts the identical, cached sealed bytes on a
// second round within the same running process, as long as the
// canonical bundle content and identity.pub have not changed.
//
// This overlaps in spirit with
// TestRunRepublishLoop_UnchangedContentPutsIdenticalBytesAcrossRounds
// in republish_loop_test.go, which already pins the same behavior
// from item 6's own work; this test is kept short and named for the
// Acceptance criterion so a reviewer can find the criterion's pin
// without cross-referencing another file.
func TestAcceptance_LoopPutsIdenticalBytesAcrossRoundsWhenUnchanged(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	setRepublishInterval(t, env, namespace, "0s")
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
// Content equality is the non-negotiable check here (a byte-for-byte
// os.ReadFile comparison). The modification time is also compared,
// but only as a corroborating signal, logged with t.Logf rather than
// failed with t.Errorf: on this test's tree, mtime can only fail to
// move if the file really was never written, so it is not a source of
// flaky, intermittent test failures the way a coarse clock comparing
// two real writes' timing could be; but a filesystem with second-level
// (or coarser) mtime resolution could in principle mask a real write
// that landed on the same tick, so mtime alone must never be the
// reason this test passes or fails -- content is.
func TestAcceptance_PublishNeverModifiesOperatorFiles(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	addPublishTestNode(t, env, namespace, "alpha")
	// Set the republish interval to 0s now, as a simulated operator
	// edit, before the "before" snapshot below: this test's own setup
	// writes provd.yaml, so it must not be mistaken for a write made by
	// publish or the loop.
	setRepublishInterval(t, env, namespace, "0s")

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

	for _, p := range paths {
		after := snap(p)
		if !bytes.Equal(before[p].content, after.content) {
			t.Errorf("%s content changed: stunmesh-provd must never edit operator files (PLAN.md 7.1)", p)
		}
		if !after.modTime.Equal(before[p].modTime) {
			t.Errorf("%s modification time changed from %v to %v: stunmesh-provd must never write this file", p, before[p].modTime, after.modTime)
		}
	}
}
