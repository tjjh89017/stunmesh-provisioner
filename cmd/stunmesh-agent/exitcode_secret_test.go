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

// This file closes two kinds of gap stage 3 item 10 asks for:
//
//   - Exit code pins for terminating paths that fetch_cmd_test.go,
//     fetch_apply_test.go, and keygen_cmd_test.go do not already
//     cover (see this file's implementation report for the full
//     enumeration): a genuine flag-parse error (as opposed to
//     -h/--help), a bad controller public key or a namespace/node_id
//     that dhtkey.Key rejects when doFetch is driven directly (the
//     way many existing tests already do, bypassing
//     Config.ValidateFetch), a proxy URL dhtproxy.New rejects, and
//     every apply-step-2-through-6 failure branch in applyDiff (uci
//     commit, network reload, the stunmesh config file, /etc/init.d/
//     stunmesh, and last.json).
//
//   - A secret-leak check that is more than eyeballing: every test
//     below plants recognizable sentinel secrets (a tunnel private
//     key, a preshared key, stunmesh config text, and, in the
//     full-pipeline tests, the node identity private key and the
//     full DHT key) in the data actually flowing through the path
//     under test, then asserts none of those sentinels appear
//     anywhere in the captured stdout or stderr. This catches a
//     leak introduced by a future change to any of these paths, not
//     just the leaks already known about today; see this function's
//     use across the file for what it does and does not cover.
//
// # Coverage and blind spots of the sentinel approach
//
// What it covers: every error-reporting line on every path exercised
// below, across both a success run and a failure at each numbered
// apply step, using values that look exactly like the real secrets
// (same shape, embedded in the same struct fields) but are unique
// enough that an accidental substring match is not plausible.
//
// What it does not cover: a path this file does not drive (a
// hand-audit of internal/execx, internal/bundle, internal/last,
// internal/crypto, and internal/dhtkey's own error text already
// covers those, see the implementation report); a leak that only
// shows up in the log for a stdout captured verbatim from a real
// command (execx.Exec never captures stderr and this package never
// logs a successful command's stdout verbatim, see internal/execx's
// package doc "Secret policy" -- there is nothing here to plant a
// sentinel in, since the fake Runner returns exactly what a test
// scripts it to); and a value the operator's own shell history or
// process list exposes outside this program's control (out of
// scope: PLAN.md 2.4/README.md's "no secrets in logs or error
// messages" is about this program's own output).
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

// --- Flag-parse error paths (runFetch, runKeygen): a genuine parse
// error (an unrecognized flag), not the -h/--help case already
// covered by TestRunFetch_Help and TestRun_Help. ---

func TestRunFetch_UnknownFlagIsExitError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"--this-flag-does-not-exist"})
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "Usage: stunmesh-agent") {
		t.Errorf("stderr = %q, want the usage text on a genuine parse error", stderr.String())
	}
}

// TestRunKeygen_Help pins runKeygen's own flag.ErrHelp branch
// (fetch_cmd.go's twin branch is already pinned by
// TestRunFetch_Help in fetch_cmd_test.go; the top-level "-h" Run()
// intercepts before ever reaching a subcommand is pinned by
// TestRun_Help in cli_test.go). "keygen -h" reaches runKeygen's own
// fs.Parse, not Run()'s.
func TestRunKeygen_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"-h"})
	if code != ExitOK {
		t.Errorf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout.String(), "Usage: stunmesh-agent") {
		t.Errorf("stdout = %q, want usage", stdout.String())
	}
}

func TestRunKeygen_UnknownFlagIsExitError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runKeygen(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"--this-flag-does-not-exist"})
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "Usage: stunmesh-agent") {
		t.Errorf("stderr = %q, want the usage text on a genuine parse error", stderr.String())
	}
}

// --- doFetch's own crypto/dhtkey/dhtproxy validation, reached only
// when doFetch is driven directly with a Config that
// Config.ValidateFetch would have rejected (the same pattern
// validFetchConfig-based tests in fetch_cmd_test.go already use). ---

func TestDoFetch_BadControllerPubkeyDirectIsExitErrorNoLeak(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg := validFetchConfig(lockPath)
	cfg.ControllerPubkey = "sentinel-bad-pubkey-not-base64-at-all!!"

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := doFetch(env, cfg)

	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), cfg.ControllerPubkey)
}

func TestDoFetch_NamespaceWithSlashIsExitErrorNoLeak(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg := validFetchConfig(lockPath)
	// dhtkey.Key rejects a namespace containing "/" (PLAN.md 2.5); an
	// operator-facing sentinel makes sure neither the namespace nor
	// node_id value is echoed, only the field name (dhtkey's own doc
	// comment "validatePart").
	cfg.Namespace = "sentinel-namespace/with-a-slash"

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := doFetch(env, cfg)

	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), cfg.Namespace)
}

func TestDoFetch_BadProxyURLIsExitErrorNoLeak(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg := validFetchConfig(lockPath)
	cfg.Proxies = []string{"://sentinel-not-a-valid-url"}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := doFetch(env, cfg)

	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	// The bad URL itself is not a secret (dhtproxy.New's own error
	// names it, PLAN.md's secret list is limited to key material, the
	// bundle, the stunmesh text, and the full DHT key); this test only
	// pins the exit code for this branch.
}

// --- applyDiff's remaining failure branches (steps 2-6): step 1
// (writeUCI) is already pinned and leak-checked by
// TestApplyDiff_FailurePartwayThroughLeavesLastJSONUnwritten and
// TestApplyDiff_ErrorNeverLeaksSecrets in fetch_apply_test.go. The
// tests below cover uci commit, network reload, the stunmesh config
// file, /etc/init.d/stunmesh, and last.json -- none of which had an
// exit-code pin or a leak check before this item. ---

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

// wg0Interface's BuildInterface batch (see sentinelDiff): create,
// proto, private_key, addresses -- 4 uci calls, no peers section here
// since the peer is exercised as part of the same batch below.
// bravo peer: create, description, public_key, preshared_key,
// allowed_ips, route_allowed_ips -- 6 more uci calls. Total 10 uci
// calls in writeUCI, then "uci commit network" (index 10), then
// "ubus call network reload" (index 11).
const (
	sentinelCommitIndex = 10
	sentinelReloadIndex = 11
)

func TestApplyDiff_CommitFailureIsExitErrorNoLeak(t *testing.T) {
	cfg := applyTestConfig(t)
	var stdout, stderr strings.Builder
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	results := make([]execx.Result, sentinelCommitIndex+1)
	results[sentinelCommitIndex] = execx.Result{Err: errors.New("boom")}
	env.Runner = execx.NewFake(results...)

	diff, state := sentinelDiff(t)
	code := applyDiff(env, cfg, diff, state)

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
	code := applyDiff(env, cfg, diff, state)

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
	cfg.StunmeshConfigPath = filepath.Join(cfg.StunmeshConfigPath+"-nonexistent-dir", "stunmesh.yaml")

	var stdout, stderr strings.Builder
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.Runner = execx.NewFake() // every uci/ubus call defaults to success

	diff, state := sentinelDiff(t)
	code := applyDiff(env, cfg, diff, state)

	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), sentinels()...)
	if _, err := os.Stat(cfg.LastPath); !os.IsNotExist(err) {
		t.Errorf("last.json was written after a stunmesh config write failure: err=%v", err)
	}
}

func TestApplyDiff_InitdFailureIsExitErrorNoLeak(t *testing.T) {
	cfg := applyTestConfig(t)
	var stdout, stderr strings.Builder
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	initdIndex := sentinelReloadIndex + 1 // right after the successful reload
	results := make([]execx.Result, initdIndex+1)
	results[initdIndex] = execx.Result{Err: errors.New("boom")}
	env.Runner = execx.NewFake(results...)

	diff, state := sentinelDiff(t)
	code := applyDiff(env, cfg, diff, state)

	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), sentinels()...)
	if _, err := os.Stat(cfg.LastPath); !os.IsNotExist(err) {
		t.Errorf("last.json was written after an init.d failure: err=%v", err)
	}
	// The stunmesh config file must already have been written (step 4
	// ran and succeeded before step 5's init.d call failed): its
	// content is expected to hold the sentinel (PLAN.md: this file
	// legitimately carries the stunmesh text), so this checks presence,
	// not absence.
	data, err := os.ReadFile(cfg.StunmeshConfigPath)
	if err != nil {
		t.Fatalf("read stunmesh config: %v", err)
	}
	if string(data) != "sentinel-stunmesh-text-6a1f" {
		t.Errorf("stunmesh config = %q, want the sentinel text (it is supposed to be there, on disk)", data)
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
	code := applyDiff(env, cfg, diff, state)

	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	assertNoSecrets(t, stdout.String()+stderr.String(), sentinels()...)
}

// --- Full pipeline, end to end: real crypto, a real httptest DHT
// proxy, a fake exec Runner. This is the strongest form of the
// sentinel check in this file: every stage the item covers (fetch,
// decrypt, select, checks, compare, diff, uci batch build, apply)
// runs for real on data carrying five different sentinels at once,
// success and failure alike. ---

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
		w.Write(dhtLine(t, sealed))
	}))
	defer srv.Close()

	cfg := &Config{
		Namespace:          namespace,
		NodeID:             nodeID,
		ControllerPubkey:   controllerPub.String(),
		Proxies:            []string{srv.URL},
		IdentityKeyPath:    keyPath,
		LastPath:           filepath.Join(dir, "last.json"),
		LockPath:           filepath.Join(dir, "agent.lock"),
		StunmeshConfigPath: filepath.Join(dir, "stunmesh.yaml"),
	}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.HTTPClient = srv.Client()
	env.Runner = execx.NewFake()

	code := doFetch(env, cfg)
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
		w.Write(dhtLine(t, sealed))
	}))
	defer srv.Close()

	cfg := &Config{
		Namespace:          namespace,
		NodeID:             nodeID,
		ControllerPubkey:   controllerPub.String(),
		Proxies:            []string{srv.URL},
		IdentityKeyPath:    keyPath,
		LastPath:           filepath.Join(dir, "last.json"),
		LockPath:           filepath.Join(dir, "agent.lock"),
		StunmeshConfigPath: filepath.Join(dir, "stunmesh.yaml"),
	}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.HTTPClient = srv.Client()
	// The very first uci call fails, so the apply step fails immediately.
	env.Runner = execx.NewFake(execx.Result{Err: errors.New("boom")})

	code := doFetch(env, cfg)
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
