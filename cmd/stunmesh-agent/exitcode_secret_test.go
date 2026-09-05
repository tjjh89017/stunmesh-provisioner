package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtkey"
	"github.com/tjjh89017/stunmesh-provisioner/internal/execx"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// TestDoFetch_RejectedBundleWithSecretsNeverLeaksSecrets pins that the
// "none usable" branch in decryptAndSelect (fetch_select.go) never
// logs the secret material of a bundle it decrypted and parsed but
// then rejected in bundle.Validate, for example a stale republish
// from another namespace. This test uses a bundle that decrypts for
// real and carries sentinel secrets in exactly the fields real
// secrets live in, so a future change that logs the rejected bundle
// is caught here.
func TestDoFetch_RejectedBundleWithSecretsNeverLeaksSecrets(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg, controllerPriv, identityPub := fetchTestConfig(t, lockPath, nil)

	// Decrypts and parses fine (phase 1: crypto.Open then bundle.Parse
	// both succeed), but the namespace does not match this node's
	// configured namespace ("ns", set by fetchTestConfig) -- a phase 2
	// check (bundle.Validate) must reject it. The wg section carries a
	// real-shaped tunnel private key, preshared key, and stunmesh text,
	// all sentinels, so the fully decrypted and parsed *bundle.Bundle
	// that exists in memory on this path carries something worth
	// leaking.
	plain := []byte(`{"version":1,"namespace":"wrong-ns","node_id":"n1","timestamp":100,` +
		`"wg":{"wg0":{"private_key":"sentinel-rejected-privkey-9c2e","addresses":["10.0.0.1/24"],` +
		`"peers":{"bravo":{"public_key":"bravo-pub","preshared_key":"sentinel-rejected-psk-9c2e","allowed_ips":["10.0.0.2/32"]}}}},` +
		`"stunmesh":"sentinel-rejected-stunmesh-9c2e"}`)
	sealed, err := crypto.Seal(plain, identityPub, controllerPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(dhtLine(t, sealed))
	}))
	defer srv.Close()
	cfg.Proxies = []string{srv.URL}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.HTTPClient = srv.Client()

	code := runFetchApplyForTest(env, cfg, false)

	if code != ExitOK {
		t.Errorf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	// Proves the "none usable" / phase-2-reject branch was actually
	// reached, not an earlier one (undecrypted or unparsed).
	if !strings.Contains(stderr.String(), "none usable") || !strings.Contains(stderr.String(), "1 rejected by node checks") {
		t.Errorf("stderr = %q, want the no-valid-value log line to count the phase 2 rejection", stderr.String())
	}
	assertNoSecrets(t, stdout.String()+stderr.String(),
		"sentinel-rejected-privkey-9c2e",
		"sentinel-rejected-psk-9c2e",
		"sentinel-rejected-stunmesh-9c2e",
	)
}

// This file closes two kinds of gap:
//
//   - Exit code pins for terminating paths that fetch_apply_test.go
//     and keygen_cmd_test.go do not already cover: a genuine
//     flag-parse error (as opposed to -h/--help), a bad controller
//     public key or a namespace/node_id that dhtkey.Key rejects, a
//     proxy URL dhtproxy.New rejects, a total DHT outage (every
//     configured proxy fails outright at request time, so
//     dhtproxy.Client.Get returns its plain joined error instead of a
//     *PartialError), and every apply-step failure branch in
//     applyDiff (uci commit, network reload, the stunmesh config
//     file, and last.json).
//
//   - A secret-leak check that is more than eyeballing: every test
//     below plants recognizable sentinel secrets (a tunnel private
//     key, a preshared key, stunmesh config text, and, in the
//     full-pipeline tests, the node identity private key and the
//     full DHT key) in the data actually flowing through the path
//     under test, then asserts none of those sentinels appear
//     anywhere in the captured stdout or stderr.
//
// It does not cover a leak that only shows up in a stdout captured
// verbatim from a real command: execx.Exec never captures stderr and
// this package never logs a successful command's stdout verbatim, so
// there is nothing here to plant a sentinel in, since the fake Runner
// returns exactly what a test scripts it to.
func assertNoSecrets(t *testing.T, captured string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(captured, secret) {
			t.Errorf("captured output leaked secret %q:\n%s", secret, captured)
		}
	}
}

// --- runFetchApply's own crypto/dhtkey/dhtproxy validation, reached
// only when it is driven directly with a Config that buildConfig
// (config.go) would have rejected had it come from a real config.yaml. ---
//
// This helper needs a real identity key, because loadIdentityKey runs
// before the checks under test; validFetchConfig's IdentityKeyPath
// names a file that does not exist, which would exit ExitError there
// instead.

// validFetchConfigWithRealIdentity builds a Config identical to
// validFetchConfig, except IdentityKeyPath names a real key file (a
// freshly generated identity key, written to a temp file) instead of a
// path that never exists. Callers that then set an invalid
// ControllerPubkey, Namespace, or Proxies value are guaranteed to
// reach runFetchApply's validation of that field, not an earlier identity
// key failure.
func validFetchConfigWithRealIdentity(t *testing.T, lockPath string) *Config {
	t.Helper()
	priv, _, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "identity.key")
	if err := os.WriteFile(keyPath, []byte(priv.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write identity key: %v", err)
	}
	cfg := validFetchConfig(lockPath)
	cfg.IdentityKeyPath = keyPath
	return cfg
}

func TestDoFetch_BadControllerPubkeyDirectIsExitErrorNoLeak(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg := validFetchConfigWithRealIdentity(t, lockPath)
	cfg.ControllerPubkey = "sentinel-bad-pubkey-not-base64-at-all!!"

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := runFetchApplyForTest(env, cfg, false)

	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "controller_pubkey") {
		t.Errorf("stderr = %q, want it to name the controller_pubkey branch (proves the branch was reached)", stderr.String())
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), cfg.ControllerPubkey)
}

func TestDoFetch_NamespaceWithSlashIsExitErrorNoLeak(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg := validFetchConfigWithRealIdentity(t, lockPath)
	// dhtkey.Key rejects a namespace containing "/"; an
	// operator-facing sentinel makes sure neither the namespace nor
	// node_id value is echoed, only the field name (dhtkey's own doc
	// comment "validatePart").
	cfg.Namespace = "sentinel-namespace/with-a-slash"

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := runFetchApplyForTest(env, cfg, false)

	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "namespace") {
		t.Errorf("stderr = %q, want it to name the field that failed (proves the branch was reached)", stderr.String())
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), cfg.Namespace)
}

// TestDoFetch_TotalDHTOutageIsExitErrorNoLeak pins runFetchApply's
// handling of dhtproxy.Client.Get's plain, non-*PartialError error:
// every configured proxy fails outright at request time, so Get never
// gets a chance to set its "empty" result and returns a plain error
// joining every per-host failure instead (a *PartialError requires at
// least one base URL to have answered, even emptily). This is a
// different case from TestDoFetch_PartialOutageLogsAndIsTreatedAsNoValues,
// which drives the sibling branch (some proxies fail, at least one
// answers empty, treated as ExitOK "no values"): "the DHT has no
// values" is a non-failure, but a total outage is not that -- it must
// be ExitError, not silently folded into "nothing to do".
func TestDoFetch_TotalDHTOutageIsExitErrorNoLeak(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg := validFetchConfigWithRealIdentity(t, lockPath)
	// Nothing listens on either address: both configured proxies fail
	// outright (connection refused) rather than answering with a 404
	// or an empty 2xx body, so dhtproxy.Client.Get's "empty" result is
	// never set and it returns its plain joined error, not a
	// *PartialError.
	cfg.Proxies = []string{"http://127.0.0.1:1", "http://127.0.0.1:2"}
	dhtKey, err := dhtkey.Key(cfg.Namespace, cfg.NodeID)
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := runFetchApplyForTest(env, cfg, false)

	if code != ExitError {
		t.Errorf("code = %d, want %d (a total DHT outage is a failure, not \"no values\")", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "get:") {
		t.Errorf("stderr = %q, want it to name the get failure branch (proves the branch was reached, not an earlier one)", stderr.String())
	}
	if strings.Contains(stderr.String(), "no value found") || strings.Contains(stderr.String(), "already locked") {
		t.Errorf("stderr = %q, a total outage must not be reported as \"no values\" or an earlier lock/identity/pubkey failure", stderr.String())
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), dhtKey)
}

func TestDoFetch_BadProxyURLIsExitErrorNoLeak(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg := validFetchConfigWithRealIdentity(t, lockPath)
	cfg.Proxies = []string{"://sentinel-not-a-valid-url"}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := runFetchApplyForTest(env, cfg, false)

	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "dht proxy") {
		t.Errorf("stderr = %q, want it to name the dht proxy branch (proves the branch was reached)", stderr.String())
	}
	// The bad URL itself is not a secret: dhtproxy.New's own error
	// names it by design (internal/dhtproxy.New's doc comment), so an
	// operator can see which configured proxy URL is malformed.
	// The secrets this file checks for are key material, the bundle,
	// the stunmesh text, and the full DHT key; this test pins the exit
	// code and confirms the branch actually ran.
}

// --- applyDiff's remaining failure branches: step 1 (writeUCI) is
// already pinned and leak-checked by
// TestApplyDiff_FailurePartwayThroughLeavesLastJSONUnwritten and
// TestApplyDiff_ErrorNeverLeaksSecrets in fetch_apply_test.go. The
// tests below cover uci commit, network reload, the stunmesh config
// file, and last.json. ---

// sentinelDiff builds a Diff carrying one new interface with a
// sentinel tunnel private key and preshared key, plus sentinel
// stunmesh text, so every test below can assert none of the three
// ever reaches stdout or stderr.
func sentinelDiff(t *testing.T) (*Diff, *last.State) {
	t.Helper()
	iface := testInterface(t, `{"private_key":"sentinel-tunnel-privkey-6a1f",`+
		`"addresses":["10.0.0.1/24"],`+
		`"peers":{"bravo":{"public_key":"bravo-pub","preshared_key":"sentinel-psk-6a1f","allowed_ips":["10.0.0.2/32"]}}}`)
	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceNew, Content: &iface},
		},
		Stunmesh:        StunmeshChanged,
		StunmeshContent: "sentinel-stunmesh-text-6a1f",
	}
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}}
	return diff, state
}

func sentinels() []string {
	return []string{"sentinel-tunnel-privkey-6a1f", "sentinel-psk-6a1f", "sentinel-stunmesh-text-6a1f"}
}

// wg0Interface's writeUCI sequence (see sentinelDiff): clearListOptions
// first -- a "uci get" then "uci delete" pair for "wg0.addresses" and
// another for "wg0_p_bravo.allowed_ips" (createInterface, fetch_apply.go)
// -- 4 uci calls. Then BuildInterface's own batch: create, proto,
// private_key, addresses -- 4 uci calls, no peers section here since
// the peer is exercised as part of the same batch below. bravo peer:
// create, description, public_key, preshared_key, allowed_ips,
// route_allowed_ips -- 6 more uci calls. Total 14 uci calls in
// writeUCI, then one "uci get firewall.stunmesh" probe (index 14,
// left unscripted so it reads as an operator-owned zone and stages
// nothing further), "uci commit network" (index 15), "ubus call
// network reload" (index 16), and "ifup wg0" (index 17).
const (
	sentinelCommitIndex = 15
	sentinelReloadIndex = 16
	sentinelIfupIndex   = 17
)

func TestApplyDiff_CommitFailureIsExitErrorNoLeak(t *testing.T) {
	cfg := applyTestConfig(t)
	var stdout, stderr strings.Builder
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	results := make([]execx.Result, sentinelCommitIndex+1)
	results[sentinelCommitIndex] = execx.Result{Err: errors.New("boom")}
	env.Runner = execx.NewFake(results...)

	diff, state := sentinelDiff(t)
	code := applyDiffForTest(env, cfg, diff, state)

	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), sentinels()...)
	if _, err := os.Stat(cfg.LastPath); !os.IsNotExist(err) {
		t.Errorf("last.json was written after a commit failure: err=%v", err)
	}
}

func TestApplyDiff_NetworkReloadFailureIsExitErrorNoLeak(t *testing.T) {
	cfg := applyTestConfig(t)
	var stdout, stderr strings.Builder
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	results := make([]execx.Result, sentinelReloadIndex+1)
	results[sentinelReloadIndex] = execx.Result{Err: errors.New("boom")}
	env.Runner = execx.NewFake(results...)

	diff, state := sentinelDiff(t)
	code := applyDiffForTest(env, cfg, diff, state)

	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), sentinels()...)
	if _, err := os.Stat(cfg.LastPath); !os.IsNotExist(err) {
		t.Errorf("last.json was written after a network reload failure: err=%v", err)
	}
	// No revert after commit succeeded (see applyDiff's doc comment "No
	// revert after uci commit succeeds"): the last call must be the
	// failing reload, not a revert.
	calls := env.Runner.(*execx.Fake).Calls()
	lastCall := calls[len(calls)-1]
	if lastCall.Name != "ubus" {
		t.Errorf("last call = %+v, want the failing ubus call, no revert after commit", lastCall)
	}
}

func TestApplyDiff_StunmeshConfigWriteFailureIsExitErrorNoLeak(t *testing.T) {
	cfg := applyTestConfig(t)
	// A parent directory that does not exist makes os.CreateTemp fail
	// inside writeStunmeshConfigAtomic, without needing to touch the
	// runner at all.
	cfg.Stunmesh.WritePath = filepath.Join(cfg.Stunmesh.WritePath+"-nonexistent-dir", "stunmesh.yaml")

	var stdout, stderr strings.Builder
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.Runner = execx.NewFake() // every uci/ubus call defaults to success

	diff, state := sentinelDiff(t)
	code := applyDiffForTest(env, cfg, diff, state)

	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), sentinels()...)
	if _, err := os.Stat(cfg.LastPath); !os.IsNotExist(err) {
		t.Errorf("last.json was written after a stunmesh config write failure: err=%v", err)
	}
}

func TestApplyDiff_IfupFailureIsExitErrorNoLeak(t *testing.T) {
	cfg := applyTestConfig(t)
	var stdout, stderr strings.Builder
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	results := make([]execx.Result, sentinelIfupIndex+1)
	results[sentinelIfupIndex] = execx.Result{Err: errors.New("boom")}
	env.Runner = execx.NewFake(results...)

	diff, state := sentinelDiff(t)
	code := applyDiffForTest(env, cfg, diff, state)

	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), sentinels()...)
	if _, err := os.Stat(cfg.LastPath); !os.IsNotExist(err) {
		t.Errorf("last.json was written after an ifup failure: err=%v", err)
	}
	// ifup (step 5) runs before the stunmesh config file write
	// (step 7): the file must not exist yet.
	if _, err := os.Stat(cfg.Stunmesh.WritePath); !os.IsNotExist(err) {
		t.Errorf("stunmesh config file was written after an ifup failure: err=%v", err)
	}
	// No revert after commit succeeded: the last call must be the
	// failing ifup, not a revert.
	calls := env.Runner.(*execx.Fake).Calls()
	lastCall := calls[len(calls)-1]
	if lastCall.Name != "ifup" {
		t.Errorf("last call = %+v, want the failing ifup call, no revert after commit", lastCall)
	}
}

func TestApplyDiff_LastJSONWriteFailureIsExitErrorNoLeak(t *testing.T) {
	cfg := applyTestConfig(t)
	// A parent directory that does not exist makes last.Write fail; all
	// runner calls and the stunmesh config write succeed first.
	cfg.LastPath = filepath.Join(t.TempDir(), "nonexistent-dir", "last.json")

	var stdout, stderr strings.Builder
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.Runner = execx.NewFake() // every uci/ubus call defaults to success

	diff, state := sentinelDiff(t)
	code := applyDiffForTest(env, cfg, diff, state)

	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), sentinels()...)
}

// --- Full pipeline, end to end: real crypto, a real httptest DHT
// proxy, a fake exec Runner, five sentinels at once, success and
// failure alike. ---

func TestDoFetch_FullPipelineSuccessNeverLeaksSecrets(t *testing.T) {
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

	namespace, nodeID := "sentinel-ns-6a1f", "sentinel-node-6a1f"
	dhtKey, err := dhtkey.Key(namespace, nodeID)
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}

	plain := []byte(`{"version":1,"namespace":"` + namespace + `","node_id":"` + nodeID + `","timestamp":100,` +
		`"wg":{"wg0":{"private_key":"sentinel-tunnel-privkey-full-6a1f","addresses":["10.0.0.1/24"],` +
		`"peers":{"bravo":{"public_key":"bravo-pub","preshared_key":"sentinel-psk-full-6a1f","allowed_ips":["10.0.0.2/32"]}}}},` +
		`"stunmesh":"sentinel-stunmesh-full-6a1f"}`)
	sealed, err := crypto.Seal(plain, identityPub, controllerPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(dhtLine(t, sealed))
	}))
	defer srv.Close()

	cfg := &Config{
		Namespace:        namespace,
		NodeID:           nodeID,
		ControllerPubkey: controllerPub.String(),
		Backend:          "dhtproxy",
		Proxies:          []string{srv.URL},
		IdentityKeyPath:  keyPath,
		LastPath:         filepath.Join(dir, "last.json"),
		LockPath:         filepath.Join(dir, "agent.lock"),
		Stunmesh:         StunmeshConfig{WritePath: filepath.Join(dir, "stunmesh.yaml")},
	}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.HTTPClient = srv.Client()
	env.Runner = execx.NewFake()

	code := runFetchApplyForTest(env, cfg, false)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}

	assertNoSecrets(t, stdout.String()+stderr.String(),
		identityPriv.String(),
		controllerPriv.String(),
		"sentinel-tunnel-privkey-full-6a1f",
		"sentinel-psk-full-6a1f",
		"sentinel-stunmesh-full-6a1f",
		dhtKey,
	)
}

func TestDoFetch_FullPipelineApplyFailureNeverLeaksSecrets(t *testing.T) {
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

	namespace, nodeID := "sentinel-ns-fail-6a1f", "sentinel-node-fail-6a1f"
	dhtKey, err := dhtkey.Key(namespace, nodeID)
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}

	plain := []byte(`{"version":1,"namespace":"` + namespace + `","node_id":"` + nodeID + `","timestamp":100,` +
		`"wg":{"wg0":{"private_key":"sentinel-tunnel-privkey-fail-6a1f","addresses":["10.0.0.1/24"],"peers":{}}},` +
		`"stunmesh":""}`)
	sealed, err := crypto.Seal(plain, identityPub, controllerPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(dhtLine(t, sealed))
	}))
	defer srv.Close()

	cfg := &Config{
		Namespace:        namespace,
		NodeID:           nodeID,
		ControllerPubkey: controllerPub.String(),
		Backend:          "dhtproxy",
		Proxies:          []string{srv.URL},
		IdentityKeyPath:  keyPath,
		LastPath:         filepath.Join(dir, "last.json"),
		LockPath:         filepath.Join(dir, "agent.lock"),
		Stunmesh:         StunmeshConfig{WritePath: filepath.Join(dir, "stunmesh.yaml")},
	}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.HTTPClient = srv.Client()
	// The very first uci call ("uci get network.wg0.addresses",
	// clearListOptions checking whether the list needs clearing) must
	// succeed so the path is treated as present; the second call (the
	// "uci delete" that follows) then fails, so the apply step still
	// fails immediately, on the first call clearListOptions does not
	// tolerate.
	env.Runner = execx.NewFake(execx.Result{}, execx.Result{Err: errors.New("boom")})

	code := runFetchApplyForTest(env, cfg, false)
	if code != ExitError {
		t.Fatalf("code = %d, want %d; stderr=%q", code, ExitError, stderr.String())
	}

	assertNoSecrets(t, stdout.String()+stderr.String(),
		identityPriv.String(),
		controllerPriv.String(),
		"sentinel-tunnel-privkey-fail-6a1f",
		dhtKey,
	)
}

// TestSentinelDiff_ActuallyCarriesTheSentinels guards sentinelDiff
// against a silent typo that would make every "sentinel never leaks"
// check above vacuous by never actually putting the sentinel where it
// is claimed to be.
func TestSentinelDiff_ActuallyCarriesTheSentinels(t *testing.T) {
	diff, _ := sentinelDiff(t)
	iface := diff.Interfaces[0]
	if iface.Content.PrivateKey != "sentinel-tunnel-privkey-6a1f" {
		t.Errorf("PrivateKey = %q, want the sentinel", iface.Content.PrivateKey)
	}
	if iface.Content.Peers["bravo"].PresharedKey == nil || *iface.Content.Peers["bravo"].PresharedKey != "sentinel-psk-6a1f" {
		t.Errorf("PresharedKey = %v, want the sentinel", iface.Content.Peers["bravo"].PresharedKey)
	}
	if diff.StunmeshContent != "sentinel-stunmesh-text-6a1f" {
		t.Errorf("StunmeshContent = %q, want the sentinel", diff.StunmeshContent)
	}
}
