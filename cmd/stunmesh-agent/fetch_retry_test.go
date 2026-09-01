package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/execx"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
	"github.com/tjjh89017/stunmesh-provisioner/internal/uci"
)

// failMatching wraps an *execx.Fake and makes every call that match
// approves fail with a generic error, regardless of its position in
// the sequence -- exactly what execx's secret policy leaves an error
// looking like (see internal/execx's package doc "Secret policy"):
// no argument echo, no stderr, only "run failed". Every call is still
// recorded through fake.Run first, so Calls() reports the real, full
// sequence; match only changes what Run returns.
type failMatching struct {
	fake  *execx.Fake
	match func(name string, args []string) bool
}

func (f *failMatching) Run(name string, args ...string) (string, error) {
	out, err := f.fake.Run(name, args...)
	if f.match(name, args) {
		return "", errors.New("boom")
	}
	return out, err
}

// Calls returns the wrapped fake's recorded calls.
func (f *failMatching) Calls() []execx.Call {
	return f.fake.Calls()
}

// callRecorder is the subset of execx.Runner both *execx.Fake and
// *failMatching satisfy: run commands, and hand back the recorded
// sequence afterward.
type callRecorder interface {
	execx.Runner
	Calls() []execx.Call
}

// failOnUCITarget builds a failMatching that fails every "uci" call
// (both "uci get" and "uci delete", the only two commands this fix
// issues for a section it might need to remove) whose last argument
// is one of targets ("network.<section>"). It models what a real uci
// binary does for a section that is not there: "uci get" and "uci
// delete" both exit non-zero (see deleteIfPresent's doc comment).
// Every other call succeeds by default (execx.NewFake with no scripted
// results).
func failOnUCITarget(targets ...string) *failMatching {
	set := make(map[string]bool, len(targets))
	for _, target := range targets {
		set[target] = true
	}
	return &failMatching{
		fake: execx.NewFake(),
		match: func(name string, args []string) bool {
			if name != "uci" || len(args) == 0 {
				return false
			}
			return set[args[len(args)-1]]
		},
	}
}

// TestFetch_RetryAfterCommitSucceedsButLaterStepFails is the
// reproduction test for the defect PLAN.md 6's "Rules" warns against:
// "Write last.json only after every step is OK. If a step fails, the
// next fetch tries again. The apply is idempotent."
//
// Before the fix, an apply that got past "uci commit network" and then
// failed at a later step (here, "ubus call network reload") left
// last.json unwritten, as the rule requires. But the next fetch then
// recomputed the same diff against that same, stale last.json, and
// tried to delete the same old UCI sections again -- sections the
// first run's own successful commit had already removed. A real uci
// returns non-zero for deleting an already-absent section, so every
// following fetch failed the same way, forever: the node never
// recovered on its own.
//
// execx.Fake has no notion of persistent uci state across two runs
// (each doFetch call gets its own fresh fake), so this test cannot
// rely on a plain fake to reproduce "the section is genuinely gone by
// the third run" on its own. Run 3 uses failOnUCITarget to make the
// fake behave the way a real uci would for wg0's now-actually-deleted
// sections: "uci get" and "uci delete" both fail for those exact
// names, and succeed for everything else.
//
// Run 2 removes the interface entirely (InterfaceRemoved), not just
// changes its content: an InterfaceChanged retry deletes and
// recreates the same section names, so a retry's delete would find
// them regardless of this bug. An InterfaceRemoved retry deletes
// sections nothing recreates -- the actual failure mode.
func TestFetch_RetryAfterCommitSucceedsButLaterStepFails(t *testing.T) {
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

	const namespace, nodeID = "retry-ns", "retry-node"
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

	publish := func(t *testing.T, plain []byte) {
		t.Helper()
		sealed, err := crypto.Seal(plain, identityPub, controllerPriv)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		proxy.set(t, sealed)
	}

	runWith := func(t *testing.T, runner callRecorder) (code int, calls []execx.Call, stderr string) {
		t.Helper()
		var stdout, stderrBuf bytes.Buffer
		env := newEnv(strings.NewReader(""), &stdout, &stderrBuf)
		env.HTTPClient = proxy.srv.Client()
		env.Runner = runner
		code = runFetchApplyForTest(env, cfg, false)
		return code, runner.Calls(), stderrBuf.String()
	}

	// --- Run 1: create wg0 with three peers. ---------------------------
	publish(t, integrationBundleJSON(namespace, nodeID, 100, `"wg0":`+wg0JSON("alpha-pub"), stunmeshV1))
	code, _, stderr := runWith(t, execx.NewFake())
	if code != ExitOK {
		t.Fatalf("run 1: code = %d, want %d (ExitOK); stderr=%q", code, ExitOK, stderr)
	}

	// --- Run 2: remove wg0 (InterfaceRemoved). "ubus call network
	// reload" fails, right after "uci commit network" succeeds -- so
	// wg0's sections are genuinely gone from UCI once run 2 returns,
	// even though last.json still records them (PLAN.md 6: write
	// last.json only after every step is OK).
	publish(t, integrationBundleJSON(namespace, nodeID, 200, "", stunmeshV1))

	fake2 := &failMatching{
		fake: execx.NewFake(),
		match: func(name string, args []string) bool {
			return name == "ubus" && len(args) == 3 && args[0] == "call" && args[1] == "network" && args[2] == "reload"
		},
	}

	code, calls2, stderr := runWith(t, fake2)
	if code != ExitError {
		t.Fatalf("run 2: code = %d, want %d (ExitError); calls=%+v stderr=%q", code, ExitError, calls2, stderr)
	}
	// Confirm the run actually reached and passed "uci commit network"
	// before failing, and did not write last.json (PLAN.md 6's rule).
	foundCommit := false
	for _, c := range calls2 {
		if c.Name == "uci" && len(c.Args) == 2 && c.Args[0] == "commit" && c.Args[1] == "network" {
			foundCommit = true
		}
	}
	if !foundCommit {
		t.Fatalf("run 2 never reached \"uci commit network\": calls=%+v", calls2)
	}
	if _, err := os.Stat(cfg.LastPath); err != nil {
		t.Fatalf("last.json missing after run 1: %v", err)
	}
	st, err := last.Read(cfg.LastPath)
	if err != nil {
		t.Fatalf("last.Read after run 2: %v", err)
	}
	if _, ok := st.WG["wg0"]; !ok {
		t.Fatalf("last.json lost wg0 after run 2's failure, want it unchanged (PLAN.md 6: write last.json only after every step is OK): %+v", st.WG)
	}

	// --- Run 3: the next fetch, same bundle as run 2. wg0's sections are
	// genuinely gone (run 2's commit removed them for real), so "uci
	// get"/"uci delete" on those exact names fail, the way a real uci
	// would. This is the self-healing retry PLAN.md 6 requires: it must
	// succeed anyway.
	fake3 := failOnUCITarget("network.wg0_p_alpha", "network.wg0_p_bravo", "network.wg0_p_charlie", "network.wg0")

	code, calls3, stderr := runWith(t, fake3)
	if code != ExitOK {
		t.Fatalf("run 3 (retry): code = %d, want %d (ExitOK); calls=%+v stderr=%q", code, ExitOK, calls3, stderr)
	}

	st, err = last.Read(cfg.LastPath)
	if err != nil {
		t.Fatalf("last.Read after run 3: %v", err)
	}
	if _, ok := st.WG["wg0"]; ok {
		t.Errorf("last.json still records wg0 after run 3 removed it: %+v", st.WG)
	}
}

// TestFetch_RetryAfterCommitSucceedsButLaterCreateStepFails is the
// reproduction test for the create half of the same failure window
// TestFetch_RetryAfterCommitSucceedsButLaterStepFails covers for the
// delete half. See that test's doc comment for the general shape of
// the window: "uci commit network" succeeds, a later step (here,
// "ubus call network reload") fails, and last.json stays unwritten
// (PLAN.md 6: write last.json only after every step is OK).
//
// Before the fix, the next fetch recomputed the same diff against the
// same, stale last.json (still not recording wg0 at all, since run 1
// never got to write it) and reran wg0's create commands from
// scratch. "uci set" overwrites, so that half of the retry is
// harmless. "uci add_list" appends: run 1's own successful commit
// already added every entry of wg0's "addresses" and wg0_p_bravo's
// "allowed_ips" once, so a plain retried create would add every entry
// a second time, without any command failing and without any log
// output -- the silent corruption this test pins.
//
// This test drives two real doFetch calls, the same way
// TestFetch_RetryAfterCommitSucceedsButLaterStepFails does, and
// asserts run 2's exact command sequence: after the fix, writeUCI
// clears each list option (a tolerant "uci get" + "uci delete" pair,
// the same idiom deleteIfPresent already uses for a whole section)
// immediately before recreating wg0, so the retried "uci add_list"
// calls start from an empty list every time, not from whatever an
// earlier, partially applied create left behind.
func TestFetch_RetryAfterCommitSucceedsButLaterCreateStepFails(t *testing.T) {
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

	const namespace, nodeID = "retry-create-ns", "retry-create-node"
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

	publish := func(t *testing.T, plain []byte) {
		t.Helper()
		sealed, err := crypto.Seal(plain, identityPub, controllerPriv)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		proxy.set(t, sealed)
	}

	runWith := func(t *testing.T, runner callRecorder) (code int, calls []execx.Call, stderr string) {
		t.Helper()
		var stdout, stderrBuf bytes.Buffer
		env := newEnv(strings.NewReader(""), &stdout, &stderrBuf)
		env.HTTPClient = proxy.srv.Client()
		env.Runner = runner
		code = runFetchApplyForTest(env, cfg, false)
		return code, runner.Calls(), stderrBuf.String()
	}

	// wg0 has one address and one peer (bravo) with one allowed_ips
	// entry -- the minimum needed to exercise both list options
	// BuildInterface uses add_list for (PLAN.md 6 "UCI layout").
	const wg0 = `{"private_key":"wg0-priv","addresses":["10.0.0.1/24"],` +
		`"peers":{"bravo":{"public_key":"bravo-pub","allowed_ips":["10.0.0.2/32"]}}}`

	// --- Run 1: create wg0 (InterfaceNew). "ubus call network reload"
	// fails right after "uci commit network" succeeds, so wg0's
	// sections, including their list entries, are genuinely live in
	// UCI once run 1 returns, even though last.json was never written.
	publish(t, integrationBundleJSON(namespace, nodeID, 100, `"wg0":`+wg0, stunmeshV1))

	fake1 := &failMatching{
		fake: execx.NewFake(),
		match: func(name string, args []string) bool {
			return name == "ubus" && len(args) == 3 && args[0] == "call" && args[1] == "network" && args[2] == "reload"
		},
	}

	code, calls1, stderr := runWith(t, fake1)
	if code != ExitError {
		t.Fatalf("run 1: code = %d, want %d (ExitError); calls=%+v stderr=%q", code, ExitError, calls1, stderr)
	}
	foundCommit := false
	for _, c := range calls1 {
		if c.Name == "uci" && len(c.Args) == 2 && c.Args[0] == "commit" && c.Args[1] == "network" {
			foundCommit = true
		}
	}
	if !foundCommit {
		t.Fatalf("run 1 never reached \"uci commit network\": calls=%+v", calls1)
	}
	if _, err := os.Stat(cfg.LastPath); !os.IsNotExist(err) {
		t.Fatalf("last.json was written after run 1's failure, want it absent (PLAN.md 6: write last.json only after every step is OK): err=%v", err)
	}

	// --- Run 2: the retry, same bundle as run 1. last.json still does
	// not record wg0 at all, so computeDiff classifies wg0 as
	// InterfaceNew again, exactly as run 1 did. The fix must clear
	// wg0's list options before recreating them, so this run's "uci
	// add_list" calls land on an empty list rather than appending onto
	// what run 1's own commit already put there.
	code, calls2, stderr := runWith(t, execx.NewFake())
	if code != ExitOK {
		t.Fatalf("run 2 (retry): code = %d, want %d (ExitOK); calls=%+v stderr=%q", code, ExitOK, calls2, stderr)
	}

	newIface := testInterface(t, wg0)
	want := uciClearListCalls(uci.ListOptions("wg0", newIface))
	want = append(want, uciCalls(uci.BuildInterface("wg0", newIface))...)
	want = append(want, firewallProbeCall, commitCall, reloadCall, ifupCall("wg0"))
	if !reflect.DeepEqual(calls2, want) {
		t.Fatalf("run 2 (retry) Calls() =\n%+v\nwant\n%+v", calls2, want)
	}

	st, err := last.Read(cfg.LastPath)
	if err != nil {
		t.Fatalf("last.Read after run 2: %v", err)
	}
	if _, ok := st.WG["wg0"]; !ok {
		t.Fatalf("last.json has no wg0 entry after run 2: %+v", st.WG)
	}
}
