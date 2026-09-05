package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/execx"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// applyTestConfig builds a *Config pointing --last and --stunmesh-config
// at fresh paths inside t.TempDir(), the paths applyDiff writes to and
// deletes.
func applyTestConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	return &Config{
		LastPath: filepath.Join(dir, "last.json"),
		Stunmesh: StunmeshConfig{WritePath: filepath.Join(dir, "stunmesh.yaml")},
	}
}

// testInterface decodes raw into a bundle.Interface for a test.
// bundle.Interface's json tags apply to decoding regardless of the
// custom MarshalJSON the bundle package defines for encoding (see
// bundle.Bundle's doc comment), so a plain json.Unmarshal is enough;
// this helper does not need bundle.Parse's whole-bundle checks.
func testInterface(t *testing.T, raw string) bundle.Interface {
	t.Helper()
	var iface bundle.Interface
	if err := json.Unmarshal([]byte(raw), &iface); err != nil {
		t.Fatalf("unmarshal interface: %v", err)
	}
	return iface
}

func TestApplyDiff_NewInterface(t *testing.T) {
	cfg := applyTestConfig(t)
	env := newEnv(strings.NewReader(""), new(strings.Builder), new(strings.Builder))
	// index 13 is manageFirewall's "uci get firewall.stunmesh" probe
	// (writeUCI's own 13 calls, index 0-12, come first -- see the "want"
	// comments below). Scripting it to fail means "not there yet": a
	// fresh zone, so manageFirewall creates it. Every other call
	// defaults to success.
	results := make([]execx.Result, 14)
	results[13] = execx.Result{Err: errors.New("no such section")}
	fake := execx.NewFake(results...)
	env.Runner = fake

	newIface := testInterface(t, `{"private_key":"wg0-key","addresses":["10.0.0.1/24"],`+
		`"peers":{"bravo":{"public_key":"bravo-key","allowed_ips":["10.0.0.2/32"]}}}`)
	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceNew, Content: &newIface},
		},
		Stunmesh:        StunmeshEmpty,
		StunmeshContent: "",
	}
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}}

	code := applyDiffForTest(env, cfg, diff, state)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}

	want := []execx.Call{
		// clearListOptions (fetch_apply.go) checks and clears each list
		// option before the create batch runs, so a retried create's "uci
		// add_list" cannot append onto a list an earlier, partly-applied
		// create already populated (applyDiff's doc comment "Retrying a
		// create after a successful commit").
		{Name: "uci", Args: []string{"get", "network.wg0.addresses"}},
		{Name: "uci", Args: []string{"delete", "network.wg0.addresses"}},
		{Name: "uci", Args: []string{"get", "network.wg0_p_bravo.allowed_ips"}},
		{Name: "uci", Args: []string{"delete", "network.wg0_p_bravo.allowed_ips"}},
		{Name: "uci", Args: []string{"set", "network.wg0=interface"}},
		{Name: "uci", Args: []string{"set", "network.wg0.proto=wireguard"}},
		{Name: "uci", Args: []string{"set", "network.wg0.private_key=wg0-key"}},
		{Name: "uci", Args: []string{"add_list", "network.wg0.addresses=10.0.0.1/24"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo=wireguard_wg0"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo.description=bravo"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo.public_key=bravo-key"}},
		{Name: "uci", Args: []string{"add_list", "network.wg0_p_bravo.allowed_ips=10.0.0.2/32"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo.route_allowed_ips=1"}},
		// manageFirewall: wg0 is New and not yet a recorded zone
		// member, so it probes ("uci get", scripted to fail above),
		// creates the zone, then clears and (re)adds
		// wg0's network entry (see manageFirewall's doc comment "Retry
		// safety" for why del_list runs before add_list).
		{Name: "uci", Args: []string{"get", "firewall.stunmesh"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh=zone"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh.name=stunmesh"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh.input=ACCEPT"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh.output=ACCEPT"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh.forward=ACCEPT"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh.mtu_fix=1"}},
		// The three default forwardings are created right after the
		// zone, only on this first creation: lan->stunmesh,
		// stunmesh->lan, and stunmesh->wan. Neither the zone nor any
		// forwarding ever sets "masq", so no NAT happens between
		// "lan" and "stunmesh" in either direction.
		{Name: "uci", Args: []string{"set", "firewall.stunmesh_fwd_lan_stunmesh=forwarding"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh_fwd_lan_stunmesh.src=lan"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh_fwd_lan_stunmesh.dest=stunmesh"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh_fwd_stunmesh_lan=forwarding"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh_fwd_stunmesh_lan.src=stunmesh"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh_fwd_stunmesh_lan.dest=lan"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh_fwd_stunmesh_wan=forwarding"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh_fwd_stunmesh_wan.src=stunmesh"}},
		{Name: "uci", Args: []string{"set", "firewall.stunmesh_fwd_stunmesh_wan.dest=wan"}},
		{Name: "uci", Args: []string{"del_list", "firewall.stunmesh.network=wg0"}},
		{Name: "uci", Args: []string{"add_list", "firewall.stunmesh.network=wg0"}},
		{Name: "uci", Args: []string{"commit", "network"}},
		// firewallChanged is true (the zone was just created), so
		// "firewall" commits separately (applyDiff's doc comment
		// "Firewall config commits separately").
		{Name: "uci", Args: []string{"commit", "firewall"}},
		{Name: "ubus", Args: []string{"call", "network", "reload"}},
		// ifupChangedInterfaces (fetch_apply.go): wg0 is InterfaceNew, so
		// it gets an explicit "ifup" after the reload. See
		// ifupChangedInterfaces's doc comment for why a reload alone is
		// not measured to be enough.
		{Name: "ifup", Args: []string{"wg0"}},
		// "/etc/init.d/firewall reload" runs after ifup, once per apply
		// that changed the firewall zone (applyDiff's doc comment
		// "/etc/init.d/firewall reload").
		{Name: "/etc/init.d/firewall", Args: []string{"reload"}},
		// diff.Stunmesh is StunmeshEmpty and last.json had no old state:
		// anyInterfaceChanged is true (a new interface), so step 6 runs
		// "stop".
	}
	if got := fake.Calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", got, want)
	}

	st, err := last.Read(cfg.LastPath)
	if err != nil {
		t.Fatalf("last.Read: %v", err)
	}
	iface, ok := st.WG["wg0"]
	if !ok {
		t.Fatalf("last.json has no wg0 entry: %+v", st.WG)
	}
	if iface.Sections.Interface != "wg0" {
		t.Errorf("Sections.Interface = %q, want wg0", iface.Sections.Interface)
	}
	if want := []string{"wg0_p_bravo"}; !reflect.DeepEqual(iface.Sections.Peers, want) {
		t.Errorf("Sections.Peers = %v, want %v", iface.Sections.Peers, want)
	}
	if !st.Firewall.ZoneOwned {
		t.Errorf("Firewall.ZoneOwned = false, want true after creating the zone")
	}
	if want := []string{"wg0"}; !reflect.DeepEqual(st.Firewall.Members, want) {
		t.Errorf("Firewall.Members = %v, want %v", st.Firewall.Members, want)
	}
}

func TestApplyDiff_ChangedInterface(t *testing.T) {
	cfg := applyTestConfig(t)
	env := newEnv(strings.NewReader(""), new(strings.Builder), new(strings.Builder))
	fake := execx.NewFake()
	env.Runner = fake

	oldSections := last.Sections{Interface: "wg0", Peers: []string{"wg0_p_bravo"}}
	newIface := testInterface(t, `{"private_key":"wg0-key-2","addresses":["10.0.0.1/24"],`+
		`"peers":{"bravo":{"public_key":"bravo-key-2","allowed_ips":["10.0.0.2/32"]}}}`)

	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceChanged, Content: &newIface, Sections: oldSections},
		},
		Stunmesh:        StunmeshUnchanged,
		StunmeshContent: "unchanged text",
	}
	// wg0 is already a recorded firewall zone member (a previous apply
	// added it): InterfaceChanged does not affect zone membership, so
	// manageFirewall has nothing to add or remove here and stages no
	// firewall uci call at all.
	firewall := last.FirewallState{ZoneOwned: true, Members: []string{"wg0"}}
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}, Stunmesh: "unchanged text", Firewall: firewall}

	code := applyDiffForTest(env, cfg, diff, state)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}

	// Each recorded section gets a "uci get" check before its "uci
	// delete" (deleteIfPresent, fetch_apply.go): the fake defaults to
	// success, so both sections here are treated as present and
	// deleted, the same as before the fix.
	want := []execx.Call{
		{Name: "uci", Args: []string{"get", "network.wg0_p_bravo"}},
		{Name: "uci", Args: []string{"delete", "network.wg0_p_bravo"}},
		{Name: "uci", Args: []string{"get", "network.wg0"}},
		{Name: "uci", Args: []string{"delete", "network.wg0"}},
		// clearListOptions (fetch_apply.go): clear each list option
		// before the create batch runs. See TestApplyDiff_NewInterface's
		// "want" for why.
		{Name: "uci", Args: []string{"get", "network.wg0.addresses"}},
		{Name: "uci", Args: []string{"delete", "network.wg0.addresses"}},
		{Name: "uci", Args: []string{"get", "network.wg0_p_bravo.allowed_ips"}},
		{Name: "uci", Args: []string{"delete", "network.wg0_p_bravo.allowed_ips"}},
		{Name: "uci", Args: []string{"set", "network.wg0=interface"}},
		{Name: "uci", Args: []string{"set", "network.wg0.proto=wireguard"}},
		{Name: "uci", Args: []string{"set", "network.wg0.private_key=wg0-key-2"}},
		{Name: "uci", Args: []string{"add_list", "network.wg0.addresses=10.0.0.1/24"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo=wireguard_wg0"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo.description=bravo"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo.public_key=bravo-key-2"}},
		{Name: "uci", Args: []string{"add_list", "network.wg0_p_bravo.allowed_ips=10.0.0.2/32"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo.route_allowed_ips=1"}},
		{Name: "uci", Args: []string{"commit", "network"}},
		{Name: "ubus", Args: []string{"call", "network", "reload"}},
		// A changed interface gets an explicit "ifup" after the reload.
		{Name: "ifup", Args: []string{"wg0"}},
	}
	if got := fake.Calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", got, want)
	}

	// The stunmesh config file was not touched: stunmesh is unchanged.
	if _, err := os.Stat(cfg.Stunmesh.WritePath); !os.IsNotExist(err) {
		t.Errorf("stunmesh config file exists or errored unexpectedly: %v", err)
	}

	st, err := last.Read(cfg.LastPath)
	if err != nil {
		t.Fatalf("last.Read: %v", err)
	}
	if !reflect.DeepEqual(st.Firewall, firewall) {
		t.Errorf("Firewall = %+v, want it carried forward unchanged: %+v", st.Firewall, firewall)
	}
}

func TestApplyDiff_RemovedInterface(t *testing.T) {
	cfg := applyTestConfig(t)
	env := newEnv(strings.NewReader(""), new(strings.Builder), new(strings.Builder))
	fake := execx.NewFake()
	env.Runner = fake

	sections := last.Sections{Interface: "wg1", Routes: []string{"wg1_r_0"}, Peers: []string{"wg1_p_charlie"}}
	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg1", Change: InterfaceRemoved, Sections: sections},
		},
		Stunmesh:        StunmeshUnchanged,
		StunmeshContent: "text",
	}
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}, Stunmesh: "text"}

	code := applyDiffForTest(env, cfg, diff, state)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}

	want := []execx.Call{
		{Name: "uci", Args: []string{"get", "network.wg1_p_charlie"}},
		{Name: "uci", Args: []string{"delete", "network.wg1_p_charlie"}},
		{Name: "uci", Args: []string{"get", "network.wg1_r_0"}},
		{Name: "uci", Args: []string{"delete", "network.wg1_r_0"}},
		{Name: "uci", Args: []string{"get", "network.wg1"}},
		{Name: "uci", Args: []string{"delete", "network.wg1"}},
		{Name: "uci", Args: []string{"commit", "network"}},
		{Name: "ubus", Args: []string{"call", "network", "reload"}},
		// No "ifup wg1": "network reload" already tears a removed
		// interface's kernel netdev down.
	}
	if got := fake.Calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", got, want)
	}

	st, err := last.Read(cfg.LastPath)
	if err != nil {
		t.Fatalf("last.Read: %v", err)
	}
	if _, ok := st.WG["wg1"]; ok {
		t.Errorf("last.json still records wg1 after removal: %+v", st.WG)
	}
}

func TestApplyDiff_EmptyWGAndEmptyStunmeshTeardown(t *testing.T) {
	cfg := applyTestConfig(t)
	if err := os.WriteFile(cfg.Stunmesh.WritePath, []byte("old text"), 0o600); err != nil {
		t.Fatalf("seed stunmesh config: %v", err)
	}

	env := newEnv(strings.NewReader(""), new(strings.Builder), new(strings.Builder))
	fake := execx.NewFake()
	env.Runner = fake

	sections := last.Sections{Interface: "wg0"}
	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceRemoved, Sections: sections},
		},
		Stunmesh:        StunmeshEmpty,
		StunmeshContent: "",
	}
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}, Stunmesh: "old text"}

	code := applyDiffForTest(env, cfg, diff, state)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}

	want := []execx.Call{
		{Name: "uci", Args: []string{"get", "network.wg0"}},
		{Name: "uci", Args: []string{"delete", "network.wg0"}},
		{Name: "uci", Args: []string{"commit", "network"}},
		{Name: "ubus", Args: []string{"call", "network", "reload"}},
		// No "ifup wg0": InterfaceRemoved never gets one (see
		// TestApplyDiff_RemovedInterface).
	}
	if got := fake.Calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", got, want)
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
		t.Errorf("last.json Stunmesh = %q, want empty", st.Stunmesh)
	}
}

func TestApplyDiff_StunmeshOnlyChange(t *testing.T) {
	cfg := applyTestConfig(t)
	env := newEnv(strings.NewReader(""), new(strings.Builder), new(strings.Builder))
	fake := execx.NewFake()
	env.Runner = fake

	diff := &Diff{
		Interfaces:      nil,
		Stunmesh:        StunmeshChanged,
		StunmeshContent: "new stunmesh text",
	}
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}, Stunmesh: "old stunmesh text"}

	code := applyDiffForTest(env, cfg, diff, state)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}

	// No interface changed, so no uci command runs at all. Only
	// `uci commit network` and `ubus call network reload` run.
	want := []execx.Call{
		{Name: "uci", Args: []string{"commit", "network"}},
		{Name: "ubus", Args: []string{"call", "network", "reload"}},
	}
	if got := fake.Calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", got, want)
	}

	data, err := os.ReadFile(cfg.Stunmesh.WritePath)
	if err != nil {
		t.Fatalf("read stunmesh config: %v", err)
	}
	if string(data) != "new stunmesh text" {
		t.Errorf("stunmesh config = %q, want %q", data, "new stunmesh text")
	}
	info, err := os.Stat(cfg.Stunmesh.WritePath)
	if err != nil {
		t.Fatalf("stat stunmesh config: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("stunmesh config mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestApplyDiff_FailurePartwayThroughLeavesLastJSONUnwritten(t *testing.T) {
	cfg := applyTestConfig(t)
	env := newEnv(strings.NewReader(""), new(strings.Builder), new(strings.Builder))
	// writeUCI's sequence for this interface (no peers, so
	// clearListOptions has only "wg0.addresses" to check, see
	// createInterface, fetch_apply.go): "uci get
	// network.wg0.addresses" (index 0), "uci delete
	// network.wg0.addresses" (index 1), then BuildInterface's own
	// batch starting with "uci set network.wg0=interface" (index 2),
	// "uci set network.wg0.proto=wireguard" (index 3), and "uci set
	// network.wg0.private_key=..." (index 4), which fails. Indices 0-3
	// default to success (execx.Fake's "past the end of results" rule
	// does not apply here since we script index 4 explicitly).
	fake := execx.NewFake(
		execx.Result{},
		execx.Result{},
		execx.Result{},
		execx.Result{},
		execx.Result{Err: errors.New("boom"), Stdout: ""},
	)
	env.Runner = fake

	newIface := testInterface(t, `{"private_key":"wg0-key","addresses":["10.0.0.1/24"],"peers":{}}`)
	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceNew, Content: &newIface},
		},
		Stunmesh:        StunmeshEmpty,
		StunmeshContent: "",
	}
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}}

	code := applyDiffForTest(env, cfg, diff, state)
	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}

	if _, err := os.Stat(cfg.LastPath); !os.IsNotExist(err) {
		t.Errorf("last.json was written after a partial failure: err=%v", err)
	}

	// The failing call is followed only by "uci revert network": no
	// commit, no reload, no init.d call. This is the idempotency
	// safeguard (see applyDiff's doc comment): the next fetch starts
	// clean instead of retrying on top of a stray staged change.
	calls := fake.Calls()
	if len(calls) != 6 {
		t.Fatalf("len(Calls()) = %d, want 6 (2 clear-list uci calls, 2 successful create uci calls, 1 failing uci call, 1 revert); got %+v", len(calls), calls)
	}
	lastCall := calls[len(calls)-1]
	want := execx.Call{Name: "uci", Args: []string{"revert", "network"}}
	if !reflect.DeepEqual(lastCall, want) {
		t.Errorf("final call = %+v, want %+v", lastCall, want)
	}
}

func TestApplyDiff_ErrorNeverLeaksSecrets(t *testing.T) {
	cfg := applyTestConfig(t)
	var stdout, stderr strings.Builder
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	// The first call ("uci get network.wg0.addresses", clearListOptions
	// checking whether the list needs clearing) must succeed so the
	// path is treated as present; the following "uci delete" then
	// fails, so applyDiff still fails on the first call clearListOptions
	// does not tolerate.
	fake := execx.NewFake(execx.Result{}, execx.Result{Err: errors.New("boom")})
	env.Runner = fake

	newIface := testInterface(t, `{"private_key":"top-secret-key","addresses":["10.0.0.1/24"],`+
		`"peers":{"bravo":{"public_key":"bravo-key","preshared_key":"top-secret-psk","allowed_ips":["10.0.0.2/32"]}}}`)
	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceNew, Content: &newIface},
		},
		Stunmesh:        StunmeshChanged,
		StunmeshContent: "top secret stunmesh text",
	}
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}}

	code := applyDiffForTest(env, cfg, diff, state)
	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}

	out := stdout.String() + stderr.String()
	for _, secret := range []string{"top-secret-key", "top-secret-psk", "top secret stunmesh text"} {
		if strings.Contains(out, secret) {
			t.Errorf("output leaked secret %q: %s", secret, out)
		}
	}
}

// TestApplyDiff_IfupRunsOnlyForNewAndChangedInterfaces exercises all
// four InterfaceChange values in a single diff, so it can assert, in
// one place, that "ifup" is issued only for InterfaceNew and
// InterfaceChanged, in diff.Interfaces order, and never for
// InterfaceUnchanged or InterfaceRemoved.
func TestApplyDiff_IfupRunsOnlyForNewAndChangedInterfaces(t *testing.T) {
	cfg := applyTestConfig(t)
	env := newEnv(strings.NewReader(""), new(strings.Builder), new(strings.Builder))
	fake := execx.NewFake()
	env.Runner = fake

	newWG0 := testInterface(t, `{"private_key":"wg0-key","addresses":["10.0.0.1/24"],"peers":{}}`)
	newWG1 := testInterface(t, `{"private_key":"wg1-key","addresses":["10.0.1.1/24"],"peers":{}}`)
	wg1OldSections := last.Sections{Interface: "wg1"}
	wg2Sections := last.Sections{Interface: "wg2"}
	wg3OldSections := last.Sections{Interface: "wg3"}

	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceNew, Content: &newWG0},
			{Name: "wg1", Change: InterfaceChanged, Content: &newWG1, Sections: wg1OldSections},
			{Name: "wg2", Change: InterfaceUnchanged},
			{Name: "wg3", Change: InterfaceRemoved, Sections: wg3OldSections},
		},
		Stunmesh:        StunmeshUnchanged,
		StunmeshContent: "text",
	}
	state := &last.State{
		Version: last.CurrentVersion,
		WG: map[string]last.Interface{
			"wg2": {Content: newWG0, Sections: wg2Sections},
		},
		Stunmesh: "text",
	}

	code := applyDiffForTest(env, cfg, diff, state)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}

	var ifupCalls []execx.Call
	for _, call := range fake.Calls() {
		if call.Name == "ifup" {
			ifupCalls = append(ifupCalls, call)
		}
	}

	want := []execx.Call{
		{Name: "ifup", Args: []string{"wg0"}},
		{Name: "ifup", Args: []string{"wg1"}},
	}
	if !reflect.DeepEqual(ifupCalls, want) {
		t.Errorf("ifup calls = %+v, want %+v (wg2 unchanged and wg3 removed must get none)", ifupCalls, want)
	}

	// "ifup" must run after "ubus call network reload" (applyDiff's doc
	// comment "Steps", step 4).
	calls := fake.Calls()
	reloadIdx, ifupWG0Idx := -1, -1
	for i, call := range calls {
		switch {
		case call.Name == "ubus":
			reloadIdx = i
		case call.Name == "ifup" && len(call.Args) == 1 && call.Args[0] == "wg0":
			ifupWG0Idx = i
		}
	}
	if reloadIdx < 0 || reloadIdx >= ifupWG0Idx {
		t.Errorf("call order = %+v: want reload (%d) < ifup wg0 (%d)", calls, reloadIdx, ifupWG0Idx)
	}
}

// TestApplyDiff_IfupFailureIsFatal asserts that a failing "ifup" stops
// applyDiff the same way a failing "network reload" does: ExitError,
// no last.json write, and no later step (the stunmesh config file,
// the init.d call) runs. UCI is already committed to the new state at
// this point (see applyDiff's doc comment "No revert after uci commit
// succeeds"), so there is nothing to revert; the fix is left to the
// next fetch's retry, not to this run.
func TestApplyDiff_IfupFailureIsFatal(t *testing.T) {
	cfg := applyTestConfig(t)
	env := newEnv(strings.NewReader(""), new(strings.Builder), new(strings.Builder))

	newIface := testInterface(t, `{"private_key":"wg0-key","addresses":["10.0.0.1/24"],"peers":{}}`)
	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceNew, Content: &newIface},
		},
		Stunmesh:        StunmeshChanged,
		StunmeshContent: "new stunmesh text",
	}
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}}

	// Calls, in order: clearListOptions (get/delete wg0.addresses),
	// the create batch (set wg0=interface, set wg0.proto=wireguard,
	// set wg0.private_key=..., add_list wg0.addresses=...) -- 6 calls,
	// index 0-5. manageFirewall then runs (wg0 is InterfaceNew): its
	// "uci get firewall.stunmesh" probe (index 6) is left unscripted,
	// so it defaults to success -- "the zone already exists" -- and
	// since state.Firewall is not recorded as owned, manageFirewall
	// treats that as a conflicting, operator-owned zone and stages
	// nothing further (see manageFirewall's doc comment "Ownership"):
	// no "uci commit firewall" follows. Then "uci commit network"
	// (index 7), "ubus call network reload" (index 8), and "ifup wg0"
	// (index 9), the one scripted to fail.
	results := make([]execx.Result, 10)
	results[9] = execx.Result{Err: errors.New("boom")} // ifup wg0
	fake := execx.NewFake(results...)
	env.Runner = fake

	code := applyDiffForTest(env, cfg, diff, state)
	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}

	calls := fake.Calls()
	lastCall := calls[len(calls)-1]
	want := execx.Call{Name: "ifup", Args: []string{"wg0"}}
	if !reflect.DeepEqual(lastCall, want) {
		t.Errorf("final call = %+v, want %+v (no revert, no stunmesh config, no init.d call after ifup fails)", lastCall, want)
	}

	if _, err := os.Stat(cfg.LastPath); !os.IsNotExist(err) {
		t.Errorf("last.json was written after a failing ifup: err=%v", err)
	}
	if _, err := os.Stat(cfg.Stunmesh.WritePath); !os.IsNotExist(err) {
		t.Errorf("stunmesh config file was written after a failing ifup: err=%v", err)
	}
}
