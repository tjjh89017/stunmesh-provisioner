package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/execx"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
	"github.com/tjjh89017/stunmesh-provisioner/internal/uci"
)

// This file is stage 3 item 12, the stage's acceptance criterion: an
// end-to-end integration test that drives the real doFetch, through a
// real httptest DHT proxy serving really-sealed bundles, against a
// fake exec runner and a real temporary last.json, covering all five
// scenarios PLAN.md 2.6 and 6 describe.
//
// # Why one chained run, not five independent ones
//
// Scenario 2 ("same bundle exits 3") only means something once
// scenario 1 has actually written last.json: exit 3 against a missing
// last.json would prove nothing (an empty last.json never equals a
// non-empty bundle). Scenario 4 ("removed interface deletes its
// sections") needs an interface that scenario 1 (or 3) actually
// created and recorded, with its real section names, not a
// hand-built last.State a test fabricated to look plausible.
// Scenario 5 needs a stunmesh config file that a real apply actually
// wrote, so deleting it means something.
//
// So this test drives one identity key pair, one controller key
// pair, one namespace/node_id, and one on-disk last.json/stunmesh
// config path through five sequential doFetch calls, each building on
// the on-disk state the previous call left behind -- the same way a
// real node's cron job would call fetch five times as the controller
// republishes a changing bundle. Each run gets its own fresh *Env
// (fresh stdout/stderr buffers, fresh *execx.Fake) so command
// sequence assertions never leak calls from an earlier run.
//
// # Two interfaces, to prove isolation
//
// Every run's bundle carries two interfaces, wg0 and wg1, until
// scenario 4 removes wg1 and scenario 5 removes wg0. Scenario 3
// changes only a field inside wg0's "alpha" peer; wg1's content is
// byte-for-byte identical to the previous run. If applyDiff ever
// touched an unchanged interface, that would show up as an
// unexpected "wg1" command in scenario 3's asserted sequence -- the
// exact-sequence assertion catches it, not just a "wg1 uncounted"
// spot check.
//
// wg0 also carries three peers (alpha, bravo, charlie) with peer
// options on one of them, so the expected command sequence exercises
// internal/uci's map-derived orderings (peer name, option key) the
// same way a real bundle would. bundle.Interface stores Peers and
// Options as Go maps, whose iteration order is randomized per
// process; if internal/uci's sort were ever lost, this test would
// fail intermittently across repeated runs (see the implementation
// report's "go test -count" and "-race" results) rather than reading
// as a fluke and getting re-run away.
func wg0Alpha(publicKey string) string {
	return `"alpha":{"public_key":"` + publicKey + `","preshared_key":"alpha-psk",` +
		`"allowed_ips":["10.0.1.2/32"],"options":{"b_opt":"2","a_opt":"1"}}`
}

const (
	wg0Bravo   = `"bravo":{"public_key":"bravo-pub","allowed_ips":["10.0.1.3/32"],"endpoint":"bravo.example.com:51820"}`
	wg0Charlie = `"charlie":{"public_key":"charlie-pub","allowed_ips":["10.0.1.4/32"]}`
	wg1Delta   = `"delta":{"public_key":"delta-pub","allowed_ips":["10.0.2.2/32"]}`
)

// wg0JSON builds the `wg0` interface fragment (the bundle's `wg.wg0`
// value) with alpha's public key set to alphaPublicKey, so scenario 3
// can change exactly one field of one peer.
func wg0JSON(alphaPublicKey string) string {
	return `{"private_key":"wg0-priv-v1","addresses":["10.0.1.1/24"],"peers":{` +
		wg0Alpha(alphaPublicKey) + "," + wg0Bravo + "," + wg0Charlie + `}}`
}

const wg1JSON = `{"private_key":"wg1-priv-v1","addresses":["10.0.2.1/24"],"peers":{` + wg1Delta + `}}`

const stunmeshV1 = "stunmesh-config-v1"

// wg0Sections and wg1Sections are the UCI section names writeUCI
// creates for wg0JSON and wg1JSON, computed independently of
// sectionsFor (fetch_apply.go) by sorting the peer names by hand, so
// this test does not just check the production code against itself.
var (
	wg0Sections = last.Sections{Interface: "wg0", Peers: []string{"wg0_p_alpha", "wg0_p_bravo", "wg0_p_charlie"}}
	wg1Sections = last.Sections{Interface: "wg1", Peers: []string{"wg1_p_delta"}}
)

// integrationBundleJSON builds one complete plaintext bundle (PLAN.md
// 4.2) for this test's namespace/node_id, with wg and stunmesh as
// given. wg is the literal JSON object body for the bundle's `wg`
// key, e.g. `"wg0":...,"wg1":...` or "" for an empty bundle.
func integrationBundleJSON(namespace, nodeID string, timestamp int64, wg, stunmesh string) []byte {
	return []byte(fmt.Sprintf(
		`{"version":1,"namespace":%q,"node_id":%q,"timestamp":%d,"wg":{%s},"stunmesh":%q}`,
		namespace, nodeID, timestamp, wg, stunmesh))
}

// uciCalls converts a uci.Batch (the same type writeUCI drives
// through runner.Run("uci", cmd.Args...)) into the []execx.Call form
// fake.Calls() returns, so this test can build its expected command
// sequence out of internal/uci's own exported batch builders
// (BuildInterface, BuildDelete) instead of hand-transcribing dozens
// of "uci set network...." strings. internal/uci's own golden-file
// tests already pin BuildInterface/BuildDelete's output; reusing them
// here keeps this test's value where the item asks for it -- proving
// writeUCI/applyDiff stitch per-interface batches, commit, reload,
// the stunmesh config, and init.d together in the right order -- and
// not in re-deriving uci layout by hand, which is where a transcribed
// expectation would drift from the real one.
func uciCalls(batch uci.Batch) []execx.Call {
	calls := make([]execx.Call, len(batch))
	for i, cmd := range batch {
		calls[i] = execx.Call{Name: "uci", Args: cmd.Args}
	}
	return calls
}

// uciDeleteCalls builds the exact command sequence writeUCI's
// deleteSections (fetch_apply.go) runs for sections: a "uci get"
// check immediately before each "uci delete", in the same
// peers-then-routes-then-interface order uci.BuildDelete uses. See
// applyDiff's doc comment "Retrying a delete after a successful
// commit" for why deleteSections checks first instead of just
// deleting.
func uciDeleteCalls(sections last.Sections) []execx.Call {
	var calls []execx.Call
	add := func(name string) {
		calls = append(calls,
			execx.Call{Name: "uci", Args: []string{"get", "network." + name}},
			execx.Call{Name: "uci", Args: []string{"delete", "network." + name}},
		)
	}
	for _, peer := range sections.Peers {
		add(peer)
	}
	for _, route := range sections.Routes {
		add(route)
	}
	if sections.Interface != "" {
		add(sections.Interface)
	}
	return calls
}

// uciClearListCalls builds the exact command sequence writeUCI's
// clearListOptions (fetch_apply.go) runs for options: a "uci get"
// check immediately before each "uci delete", one pair per
// "<section>.<option>" path, in the order uci.ListOptions returns
// them. See applyDiff's doc comment "Retrying a create after a
// successful commit" for why clearListOptions checks first instead of
// deleting unconditionally.
func uciClearListCalls(options []string) []execx.Call {
	var calls []execx.Call
	for _, option := range options {
		calls = append(calls,
			execx.Call{Name: "uci", Args: []string{"get", "network." + option}},
			execx.Call{Name: "uci", Args: []string{"delete", "network." + option}},
		)
	}
	return calls
}

var (
	commitCall = execx.Call{Name: "uci", Args: []string{"commit", "network"}}
	reloadCall = execx.Call{Name: "ubus", Args: []string{"call", "network", "reload"}}
	// firewallProbeCall is manageFirewall's "uci get firewall.stunmesh"
	// (PLAN.md 6 "Firewall zone"), staged whenever anyInterfaceChanged
	// is true and at least one remaining interface is not yet a
	// recorded zone member. It is left unscripted in every fake here,
	// so it defaults to success ("the zone already exists"); since
	// none of these scenarios ever record the zone as agent-owned,
	// manageFirewall reads that as a conflicting, operator-owned zone
	// and stages nothing else (see manageFirewall's doc comment
	// "Ownership") -- one extra call, no "uci commit firewall", no
	// firewall reload. The firewall zone's own create/add/remove/
	// delete behavior is covered directly by
	// TestApplyDiff_NewInterface and the other tests in
	// fetch_apply_test.go, not by this chain.
	firewallProbeCall = execx.Call{Name: "uci", Args: []string{"get", "firewall.stunmesh"}}
)

// ifupCall builds the "ifup <iface>" call ifupChangedInterfaces
// (fetch_apply.go) issues for a new or changed interface, after
// reloadCall and before the stunmesh call. A removed interface gets
// none (see ifupChangedInterfaces's doc comment).
func ifupCall(iface string) execx.Call {
	return execx.Call{Name: "ifup", Args: []string{iface}}
}

// switchableProxy is a real httptest.Server whose response body can
// be changed between doFetch calls: each of the five scenarios below
// serves a different sealed DHT value, without needing five separate
// servers. set stores the exact bytes doFetch's next GET receives
// (already rendered as one dhtLine); the handler never calls a *T
// method, since it may run on a goroutine other than the test's own.
type switchableProxy struct {
	srv  *httptest.Server
	mu   sync.Mutex
	line []byte
}

func newSwitchableProxy() *switchableProxy {
	p := &switchableProxy{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		line := p.line
		p.mu.Unlock()
		w.Write(line)
	}))
	return p
}

func (p *switchableProxy) set(t *testing.T, sealed []byte) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.line = dhtLine(t, sealed)
}

// TestFetch_FiveScenariosChained is stage 3 item 12: the acceptance
// criterion. See this file's package doc comment for why the five
// scenarios run as one chain against one on-disk state, rather than
// five independent setups.
func TestFetch_FiveScenariosChained(t *testing.T) {
	identityPriv, identityPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen (identity): %v", err)
	}
	controllerPriv, controllerPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen (controller): %v", err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")
	if err := os.WriteFile(keyPath, []byte(identityPriv.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write identity key: %v", err)
	}

	proxy := newSwitchableProxy()
	defer proxy.srv.Close()

	const namespace, nodeID = "chain-ns", "chain-node"
	cfg := &Config{
		Namespace:        namespace,
		NodeID:           nodeID,
		ControllerPubkey: controllerPub.String(),
		Backend:          "dhtproxy",
		Proxies:          []string{proxy.srv.URL},
		IdentityKeyPath:  keyPath,
		LastPath:         filepath.Join(dir, "last.json"),
		LockPath:         filepath.Join(dir, "agent.lock"),
		Stunmesh:         StunmeshConfig{WritePath: filepath.Join(dir, "stunmesh.yaml")},
	}

	// run publishes plain as the next value the proxy serves (sealed
	// for real, with real crypto), then drives one full doFetch
	// against a fresh Env and a fresh *execx.Fake, and returns the
	// exit code, the fake's recorded calls, and the captured stderr
	// (for failure diagnostics only; no scenario below asserts on its
	// text).
	run := func(t *testing.T, plain []byte) (code int, calls []execx.Call, stderr string) {
		t.Helper()
		sealed, err := crypto.Seal(plain, identityPub, controllerPriv)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		proxy.set(t, sealed)

		var stdout, stderrBuf bytes.Buffer
		env := newEnv(strings.NewReader(""), &stdout, &stderrBuf)
		env.HTTPClient = proxy.srv.Client()
		fake := execx.NewFake()
		env.Runner = fake

		code = runFetchApplyForTest(env, cfg, false)
		return code, fake.Calls(), stderrBuf.String()
	}

	// --- Scenario 1: first run creates. -------------------------------
	//
	// No last.json exists yet, so both wg0 and wg1 are InterfaceNew: the
	// apply step creates every section for both, in interface-name
	// order (computeDiff's doc comment: sorted lexicographically),
	// wg0 before wg1.
	t.Run("1_FirstRunCreates", func(t *testing.T) {
		plain := integrationBundleJSON(namespace, nodeID, 100,
			`"wg0":`+wg0JSON("alpha-pub")+`,"wg1":`+wg1JSON, stunmeshV1)

		code, calls, stderr := run(t, plain)
		if code != ExitOK {
			t.Fatalf("code = %d, want %d (ExitOK); stderr=%q", code, ExitOK, stderr)
		}

		wg0Iface := testInterface(t, wg0JSON("alpha-pub"))
		wg1Iface := testInterface(t, wg1JSON)
		want := uciClearListCalls(uci.ListOptions("wg0", wg0Iface))
		want = append(want, uciCalls(uci.BuildInterface("wg0", wg0Iface))...)
		want = append(want, uciClearListCalls(uci.ListOptions("wg1", wg1Iface))...)
		want = append(want, uciCalls(uci.BuildInterface("wg1", wg1Iface))...)
		// Both wg0 and wg1 are InterfaceNew: ifupChangedInterfaces gives
		// each an explicit "ifup", in diff.Interfaces order, after the
		// reload.
		want = append(want, firewallProbeCall, commitCall, reloadCall, ifupCall("wg0"), ifupCall("wg1"))
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("Calls() =\n%+v\nwant\n%+v", calls, want)
		}

		st, err := last.Read(cfg.LastPath)
		if err != nil {
			t.Fatalf("last.Read: %v", err)
		}
		if st.Stunmesh != stunmeshV1 {
			t.Errorf("last.json Stunmesh = %q, want %q", st.Stunmesh, stunmeshV1)
		}
		wg0, ok := st.WG["wg0"]
		if !ok {
			t.Fatalf("last.json has no wg0 entry: %+v", st.WG)
		}
		if !reflect.DeepEqual(wg0.Sections, wg0Sections) {
			t.Errorf("wg0 Sections = %+v, want %+v", wg0.Sections, wg0Sections)
		}
		wg1, ok := st.WG["wg1"]
		if !ok {
			t.Fatalf("last.json has no wg1 entry: %+v", st.WG)
		}
		if !reflect.DeepEqual(wg1.Sections, wg1Sections) {
			t.Errorf("wg1 Sections = %+v, want %+v", wg1.Sections, wg1Sections)
		}

		info, err := os.Stat(cfg.LastPath)
		if err != nil {
			t.Fatalf("stat last.json: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("last.json mode = %o, want 0600", info.Mode().Perm())
		}

		info, err = os.Stat(cfg.Stunmesh.WritePath)
		if err != nil {
			t.Fatalf("stat stunmesh config: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("stunmesh config mode = %o, want 0600", info.Mode().Perm())
		}
	})

	// --- Scenario 2: same bundle exits 3. ------------------------------
	//
	// This must run after scenario 1: it re-publishes byte-identical
	// content and proves nothing was applied a second time. The mtime
	// check, not just a content comparison, proves last.json was
	// genuinely never rewritten, not merely rewritten with the same
	// bytes.
	t.Run("2_SameBundleExitsNoChange", func(t *testing.T) {
		before, err := os.Stat(cfg.LastPath)
		if err != nil {
			t.Fatalf("stat last.json before: %v", err)
		}
		// Give the filesystem's mtime resolution a margin: if applyDiff
		// wrongly rewrote last.json, a rewrite this soon after
		// scenario 1 must still show a changed mtime.
		time.Sleep(2 * time.Millisecond)

		plain := integrationBundleJSON(namespace, nodeID, 100,
			`"wg0":`+wg0JSON("alpha-pub")+`,"wg1":`+wg1JSON, stunmeshV1)

		code, calls, stderr := run(t, plain)
		if code != ExitOK {
			t.Fatalf("code = %d, want %d (ExitOK; \"no change\" is not a separate exit code any more, see cli.go)", code, ExitOK)
		}
		if len(calls) != 0 {
			t.Errorf("Calls() = %+v, want no commands run", calls)
		}
		if !strings.Contains(stderr, "no change") {
			t.Errorf("stderr = %q, want it to say nothing changed (proves the run reached the compare step, not an unrelated early exit)", stderr)
		}

		after, err := os.Stat(cfg.LastPath)
		if err != nil {
			t.Fatalf("stat last.json after: %v", err)
		}
		if !before.ModTime().Equal(after.ModTime()) {
			t.Errorf("last.json ModTime changed (%v -> %v), want untouched", before.ModTime(), after.ModTime())
		}
	})

	// --- Scenario 3: changed peer rewrites one interface only. --------
	//
	// wg0's alpha peer gets a new public key; wg1 is byte-identical to
	// scenario 1/2. Only wg0's recorded sections are deleted and
	// recreated; wg1 must not appear in the command sequence at all.
	t.Run("3_ChangedPeerTouchesOnlyThatInterface", func(t *testing.T) {
		plain := integrationBundleJSON(namespace, nodeID, 200,
			`"wg0":`+wg0JSON("alpha-pub-v2")+`,"wg1":`+wg1JSON, stunmeshV1)

		before, err := os.Stat(cfg.Stunmesh.WritePath)
		if err != nil {
			t.Fatalf("stat stunmesh config before: %v", err)
		}

		code, calls, stderr := run(t, plain)
		if code != ExitOK {
			t.Fatalf("code = %d, want %d (ExitOK); stderr=%q", code, ExitOK, stderr)
		}

		wg0IfaceV2 := testInterface(t, wg0JSON("alpha-pub-v2"))
		want := uciDeleteCalls(wg0Sections)
		want = append(want, uciClearListCalls(uci.ListOptions("wg0", wg0IfaceV2))...)
		want = append(want, uciCalls(uci.BuildInterface("wg0", wg0IfaceV2))...)
		// stunmesh text is unchanged (still stunmeshV1), but wg0 changed,
		// so step 6 still runs "reload" (PLAN.md 6 step 6 condition:
		// stunmesh changed OR any interface changed). wg0 is
		// InterfaceChanged, so it also gets an explicit "ifup".
		want = append(want, firewallProbeCall, commitCall, reloadCall, ifupCall("wg0"))
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("Calls() =\n%+v\nwant\n%+v", calls, want)
		}
		for _, call := range calls {
			for _, arg := range call.Args {
				if strings.Contains(arg, "wg1") {
					t.Errorf("call %+v touches wg1, want wg1 left alone", call)
				}
			}
		}

		// The stunmesh config file was not touched: prove it by mtime,
		// not just by content, the same reasoning as scenario 2.
		after, err := os.Stat(cfg.Stunmesh.WritePath)
		if err != nil {
			t.Fatalf("stat stunmesh config after: %v", err)
		}
		if !before.ModTime().Equal(after.ModTime()) {
			t.Errorf("stunmesh config ModTime changed (%v -> %v), want untouched (stunmesh unchanged)", before.ModTime(), after.ModTime())
		}

		st, err := last.Read(cfg.LastPath)
		if err != nil {
			t.Fatalf("last.Read: %v", err)
		}
		wg0, ok := st.WG["wg0"]
		if !ok {
			t.Fatalf("last.json lost wg0 after a peer change: %+v", st.WG)
		}
		if wg0.Content.Peers["alpha"].PublicKey != "alpha-pub-v2" {
			t.Errorf("last.json wg0 alpha public key = %q, want alpha-pub-v2", wg0.Content.Peers["alpha"].PublicKey)
		}
		if !reflect.DeepEqual(wg0.Sections, wg0Sections) {
			t.Errorf("wg0 Sections after change = %+v, want %+v (same peer names)", wg0.Sections, wg0Sections)
		}
		wg1, ok := st.WG["wg1"]
		if !ok {
			t.Fatalf("last.json lost wg1, an untouched interface: %+v", st.WG)
		}
		if !reflect.DeepEqual(wg1.Sections, wg1Sections) {
			t.Errorf("wg1 Sections changed even though wg1 was untouched: %+v, want %+v", wg1.Sections, wg1Sections)
		}
	})

	// --- Scenario 4: removed interface deletes its sections. ----------
	//
	// wg1 disappears from the bundle; wg0 (already changed to v2 by
	// scenario 3) stays byte-identical. Only wg1's recorded sections
	// are deleted; wg0 must not appear in the command sequence at all.
	t.Run("4_RemovedInterfaceDeletesItsSections", func(t *testing.T) {
		plain := integrationBundleJSON(namespace, nodeID, 300,
			`"wg0":`+wg0JSON("alpha-pub-v2"), stunmeshV1)

		code, calls, stderr := run(t, plain)
		if code != ExitOK {
			t.Fatalf("code = %d, want %d (ExitOK); stderr=%q", code, ExitOK, stderr)
		}

		want := uciDeleteCalls(wg1Sections)
		want = append(want, firewallProbeCall, commitCall, reloadCall)
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("Calls() =\n%+v\nwant\n%+v", calls, want)
		}
		for _, call := range calls {
			for _, arg := range call.Args {
				if strings.Contains(arg, "wg0") {
					t.Errorf("call %+v touches wg0, want wg0 left alone", call)
				}
			}
		}

		st, err := last.Read(cfg.LastPath)
		if err != nil {
			t.Fatalf("last.Read: %v", err)
		}
		if _, ok := st.WG["wg1"]; ok {
			t.Errorf("last.json still records wg1 after removal: %+v", st.WG)
		}
		wg0, ok := st.WG["wg0"]
		if !ok {
			t.Fatalf("last.json lost wg0, an untouched interface: %+v", st.WG)
		}
		if wg0.Content.Peers["alpha"].PublicKey != "alpha-pub-v2" {
			t.Errorf("last.json wg0 alpha public key = %q, want it to still be the v2 value", wg0.Content.Peers["alpha"].PublicKey)
		}
	})

	// --- Scenario 5: empty wg and empty stunmesh tear everything down. -
	//
	// wg0 is the only interface left; the new bundle carries no
	// interfaces and an empty stunmesh text. Every remaining interface
	// is removed, the stunmesh config file is deleted, and stunmesh is
	// stopped (not reloaded).
	t.Run("5_EmptyBundleTearsDownAndStops", func(t *testing.T) {
		plain := integrationBundleJSON(namespace, nodeID, 400, "", "")

		code, calls, stderr := run(t, plain)
		if code != ExitOK {
			t.Fatalf("code = %d, want %d (ExitOK); stderr=%q", code, ExitOK, stderr)
		}

		want := uciDeleteCalls(wg0Sections)
		want = append(want, commitCall, reloadCall)
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("Calls() =\n%+v\nwant\n%+v", calls, want)
		}

		if _, err := os.Stat(cfg.Stunmesh.WritePath); !os.IsNotExist(err) {
			t.Errorf("stunmesh config file still exists after teardown: err=%v", err)
		}

		st, err := last.Read(cfg.LastPath)
		if err != nil {
			t.Fatalf("last.Read: %v", err)
		}
		if len(st.WG) != 0 {
			t.Errorf("last.json still records interfaces after teardown: %+v", st.WG)
		}
		if st.Stunmesh != "" {
			t.Errorf("last.json Stunmesh = %q, want empty after teardown", st.Stunmesh)
		}

		info, err := os.Stat(cfg.LastPath)
		if err != nil {
			t.Fatalf("stat last.json: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("last.json mode = %o, want 0600", info.Mode().Perm())
		}
	})
}

// TestFetch_TwoInterfaceContentActuallyDiffers guards
// TestFetch_FiveScenariosChained's scenario 3 against a silent typo
// that would make its "wg1 untouched" assertion vacuous by never
// actually changing wg0's content between run 1 and run 3: if
// wg0JSON("alpha-pub") and wg0JSON("alpha-pub-v2") ever produced
// identical bytes, computeDiff would classify wg0 as InterfaceUnchanged
// too, and the "exact sequence" assertion in scenario 3 would degrade
// to asserting an empty non-wg1 sequence -- a fair-looking assertion
// that never actually exercised InterfaceChanged.
func TestFetch_TwoInterfaceContentActuallyDiffers(t *testing.T) {
	if wg0JSON("alpha-pub") == wg0JSON("alpha-pub-v2") {
		t.Fatal("wg0JSON(\"alpha-pub\") == wg0JSON(\"alpha-pub-v2\"), scenario 3 would never see a real change")
	}
	// And wg1JSON must be reused byte-for-byte across every scenario
	// (this file never regenerates it), so parsing it twice yields
	// identical content -- the precondition for the "wg1 never
	// appears in the command sequence" assertions to mean anything.
	a := testInterface(t, wg1JSON)
	b := testInterface(t, wg1JSON)
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if string(aj) != string(bj) {
		t.Fatalf("wg1JSON does not parse identically twice: %s vs %s", aj, bj)
	}
}
