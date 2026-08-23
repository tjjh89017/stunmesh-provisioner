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
		LastPath:           filepath.Join(dir, "last.json"),
		StunmeshConfigPath: filepath.Join(dir, "stunmesh.yaml"),
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
	fake := execx.NewFake()
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

	code := applyDiff(env, cfg, diff, state)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}

	want := []execx.Call{
		{Name: "uci", Args: []string{"set", "network.wg0=interface"}},
		{Name: "uci", Args: []string{"set", "network.wg0.proto=wireguard"}},
		{Name: "uci", Args: []string{"set", "network.wg0.private_key=wg0-key"}},
		{Name: "uci", Args: []string{"add_list", "network.wg0.addresses=10.0.0.1/24"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo=wireguard_wg0"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo.description=bravo"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo.public_key=bravo-key"}},
		{Name: "uci", Args: []string{"add_list", "network.wg0_p_bravo.allowed_ips=10.0.0.2/32"}},
		{Name: "uci", Args: []string{"set", "network.wg0_p_bravo.route_allowed_ips=1"}},
		{Name: "uci", Args: []string{"commit", "network"}},
		{Name: "ubus", Args: []string{"call", "network", "reload"}},
		// diff.Stunmesh is StunmeshEmpty and last.json had no old state:
		// anyInterfaceChanged is true (a new interface), so step 6 runs
		// "stop".
		{Name: "/etc/init.d/stunmesh", Args: []string{"stop"}},
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
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}, Stunmesh: "unchanged text"}

	code := applyDiff(env, cfg, diff, state)
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
		// stunmesh unchanged, but the interface changed: step 6 runs
		// "reload" (not "stop": stunmesh text is not empty).
		{Name: "/etc/init.d/stunmesh", Args: []string{"reload"}},
	}
	if got := fake.Calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", got, want)
	}

	// The stunmesh config file was not touched: stunmesh is unchanged.
	if _, err := os.Stat(cfg.StunmeshConfigPath); !os.IsNotExist(err) {
		t.Errorf("stunmesh config file exists or errored unexpectedly: %v", err)
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

	code := applyDiff(env, cfg, diff, state)
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
		{Name: "/etc/init.d/stunmesh", Args: []string{"reload"}},
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
	if err := os.WriteFile(cfg.StunmeshConfigPath, []byte("old text"), 0o600); err != nil {
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

	code := applyDiff(env, cfg, diff, state)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}

	want := []execx.Call{
		{Name: "uci", Args: []string{"get", "network.wg0"}},
		{Name: "uci", Args: []string{"delete", "network.wg0"}},
		{Name: "uci", Args: []string{"commit", "network"}},
		{Name: "ubus", Args: []string{"call", "network", "reload"}},
		{Name: "/etc/init.d/stunmesh", Args: []string{"stop"}},
	}
	if got := fake.Calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", got, want)
	}

	if _, err := os.Stat(cfg.StunmeshConfigPath); !os.IsNotExist(err) {
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

	code := applyDiff(env, cfg, diff, state)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}

	// No interface changed, so no uci command runs at all; only the
	// commit, reload, and stunmesh reload (PLAN.md 6 step 3/4 have
	// nothing to do, but step 3/4's own commands still run: "uci commit
	// network" and "ubus call network reload" always run once per
	// apply).
	want := []execx.Call{
		{Name: "uci", Args: []string{"commit", "network"}},
		{Name: "ubus", Args: []string{"call", "network", "reload"}},
		{Name: "/etc/init.d/stunmesh", Args: []string{"reload"}},
	}
	if got := fake.Calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", got, want)
	}

	data, err := os.ReadFile(cfg.StunmeshConfigPath)
	if err != nil {
		t.Fatalf("read stunmesh config: %v", err)
	}
	if string(data) != "new stunmesh text" {
		t.Errorf("stunmesh config = %q, want %q", data, "new stunmesh text")
	}
	info, err := os.Stat(cfg.StunmeshConfigPath)
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
	// The third uci call (index 2: create network.wg0.private_key) fails.
	// Calls 0 and 1 default to success (execx.Fake's "past the end of
	// results" rule does not apply here since we script index 2
	// explicitly; indices 0 and 1 use the zero Result, which is success).
	fake := execx.NewFake(
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

	code := applyDiff(env, cfg, diff, state)
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
	if len(calls) != 4 {
		t.Fatalf("len(Calls()) = %d, want 4 (2 successful uci calls, 1 failing uci call, 1 revert); got %+v", len(calls), calls)
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
	fake := execx.NewFake(execx.Result{Err: errors.New("boom")})
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

	code := applyDiff(env, cfg, diff, state)
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
