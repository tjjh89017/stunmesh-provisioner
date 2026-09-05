package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/execx"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// parseTestBundle parses raw JSON into a *bundle.Bundle for a test,
// failing the test on any parse error. It never validates: some tests
// deliberately build a bundle whose namespace/node_id do not matter to
// the comparison under test.
func parseTestBundle(t *testing.T, raw string) *bundle.Bundle {
	t.Helper()
	b, err := bundle.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("bundle.Parse: %v", err)
	}
	return b
}

func TestSameContent_IdenticalContentIsEqual(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	state := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"wg0": {Content: b.WG["wg0"]}},
		Stunmesh: "text",
	}

	equal, err := sameContent(state, b)
	if err != nil {
		t.Fatalf("sameContent: %v", err)
	}
	if !equal {
		t.Errorf("equal = false, want true for identical content")
	}
}

func TestSameContent_TimestampOnlyDifferenceIsEqual(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":999999,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	state := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"wg0": {Content: b.WG["wg0"]}},
		Stunmesh: "text",
	}

	equal, err := sameContent(state, b)
	if err != nil {
		t.Fatalf("sameContent: %v", err)
	}
	if !equal {
		t.Errorf("equal = false, want true: timestamp must not affect the outcome")
	}
}

func TestSameContent_RealChangeIsNotEqual(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk-new","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	old := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk-old","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	state := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"wg0": {Content: old.WG["wg0"]}},
		Stunmesh: "text",
	}

	equal, err := sameContent(state, b)
	if err != nil {
		t.Fatalf("sameContent: %v", err)
	}
	if equal {
		t.Errorf("equal = true, want false: private_key changed")
	}
}

func TestSameContent_StunmeshOnlyChangeIsNotEqual(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{},"stunmesh":"new text"}`)

	state := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{},
		Stunmesh: "old text",
	}

	equal, err := sameContent(state, b)
	if err != nil {
		t.Fatalf("sameContent: %v", err)
	}
	if equal {
		t.Errorf("equal = true, want false: stunmesh text changed")
	}
}

func TestSameContent_MissingLastTreatsEveryInterfaceAsNew(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	dir := t.TempDir()
	state, err := last.Read(filepath.Join(dir, "does-not-exist.json"))
	if err != nil {
		t.Fatalf("last.Read: %v", err)
	}

	equal, err := sameContent(state, b)
	if err != nil {
		t.Fatalf("sameContent: %v", err)
	}
	if equal {
		t.Errorf("equal = true, want false: a missing last.json must not read as matching a non-empty bundle")
	}
}

func TestSameContent_MissingLastMatchesAnEmptyBundle(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{},"stunmesh":""}`)

	dir := t.TempDir()
	state, err := last.Read(filepath.Join(dir, "does-not-exist.json"))
	if err != nil {
		t.Fatalf("last.Read: %v", err)
	}

	equal, err := sameContent(state, b)
	if err != nil {
		t.Fatalf("sameContent: %v", err)
	}
	if !equal {
		t.Errorf("equal = false, want true: an empty last.json and an empty bundle are the same content")
	}
}

// TestSameContent_AbsentVsExplicitEmptyAreDifferent pins that an
// absent key and an explicit empty container are different content.
// It uses the `options` field of an interface, which is
// *map[string]string with no `omitempty` semantics baked into
// presence: nil means absent, a non-nil empty map means `"options":{}`
// was present.
func TestSameContent_AbsentVsExplicitEmptyAreDifferent(t *testing.T) {
	// The new bundle has an interface with an explicit, empty `options`.
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"options":{},"peers":{}}},"stunmesh":""}`)

	// last.json recorded the same interface but without an `options`
	// key at all (absent, not empty).
	old := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":""}`)

	state := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"wg0": {Content: old.WG["wg0"]}},
		Stunmesh: "",
	}

	equal, err := sameContent(state, b)
	if err != nil {
		t.Fatalf("sameContent: %v", err)
	}
	if equal {
		t.Errorf("equal = true, want false: absent options must not compare equal to explicit empty options")
	}

	// Round-tripping the "absent options" state through last.json's own
	// Read/Write must preserve the distinction: this guards against a
	// future change to last.Interface's JSON tags silently collapsing
	// absent and explicit-empty into the same encoded form.
	path := filepath.Join(t.TempDir(), "last.json")
	if err := last.Write(path, state); err != nil {
		t.Fatalf("last.Write: %v", err)
	}
	reread, err := last.Read(path)
	if err != nil {
		t.Fatalf("last.Read: %v", err)
	}
	if reread.WG["wg0"].Content.Options != nil {
		t.Errorf("Options = %#v after round trip, want nil (absent)", reread.WG["wg0"].Content.Options)
	}
	equal2, err := sameContent(reread, b)
	if err != nil {
		t.Fatalf("sameContent (post round trip): %v", err)
	}
	if equal2 {
		t.Errorf("equal = true after round trip, want false: presence must survive last.json's own Read/Write")
	}
}

func TestCheckAndApply_EqualContentExitsNoChangeAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	lastPath := filepath.Join(dir, "last.json")

	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	initial := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"wg0": {Content: b.WG["wg0"]}},
		Stunmesh: "text",
	}
	if err := last.Write(lastPath, initial); err != nil {
		t.Fatalf("last.Write: %v", err)
	}
	before, err := os.ReadFile(lastPath)
	if err != nil {
		t.Fatalf("read last.json: %v", err)
	}

	cfg := &Config{LastPath: lastPath}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)

	outcome, err := checkAndApply(env, cfg, b, false)
	if err != nil || outcome.Applied {
		t.Errorf("outcome = %+v, err = %v, want Applied=false, err=nil; stderr=%q", outcome, err, stderr.String())
	}

	after, err := os.ReadFile(lastPath)
	if err != nil {
		t.Fatalf("read last.json after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("last.json changed on a no-op run")
	}
}

func TestCheckAndApply_EqualContentNeverLogsSecrets(t *testing.T) {
	dir := t.TempDir()
	lastPath := filepath.Join(dir, "last.json")

	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"top-secret-private-key","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"secret stunmesh text"}`)

	initial := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"wg0": {Content: b.WG["wg0"]}},
		Stunmesh: "secret stunmesh text",
	}
	if err := last.Write(lastPath, initial); err != nil {
		t.Fatalf("last.Write: %v", err)
	}

	cfg := &Config{LastPath: lastPath}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)

	outcome, err := checkAndApply(env, cfg, b, false)
	if err != nil || outcome.Applied {
		t.Fatalf("outcome = %+v, err = %v, want Applied=false, err=nil", outcome, err)
	}
	if strings.Contains(stdout.String()+stderr.String(), "top-secret-private-key") ||
		strings.Contains(stdout.String()+stderr.String(), "secret stunmesh text") {
		t.Errorf("output leaked secret content: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestCheckAndApply_DifferentContentHandsOffToNextSeam(t *testing.T) {
	dir := t.TempDir()
	lastPath := filepath.Join(dir, "last.json")
	// No last.json written: every interface reads as new.

	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	cfg := &Config{LastPath: lastPath, Stunmesh: StunmeshConfig{WritePath: filepath.Join(dir, "stunmesh.yaml")}}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.Runner = execx.NewFake()

	outcome, err := checkAndApply(env, cfg, b, false)
	// applyDiff (fetch_apply.go) applies for real against the fake
	// runner; reaching Applied=true (rather than false) proves the
	// comparison correctly decided "different" and the apply ran end
	// to end.
	if err != nil || !outcome.Applied {
		t.Errorf("outcome = %+v, err = %v; stderr=%q", outcome, err, stderr.String())
	}
	if _, err := os.Stat(lastPath); err != nil {
		t.Errorf("last.json not written after a successful apply: %v", err)
	}
}

func TestCheckAndApply_CorruptLastJSONIsExitError(t *testing.T) {
	dir := t.TempDir()
	lastPath := filepath.Join(dir, "last.json")
	if err := os.WriteFile(lastPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write corrupt last.json: %v", err)
	}

	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{},"stunmesh":""}`)

	cfg := &Config{LastPath: lastPath}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)

	_, err := checkAndApply(env, cfg, b, false)
	if err == nil {
		t.Errorf("err = nil, want an error for a corrupt last.json")
	}
}

// TestCheckAndApply_FullApplyBypassesEqualContentShortcut pins
// forceAll's effect at checkAndApply itself (runFetchApply's doc
// comment): identical content, the exact case
// TestCheckAndApply_EqualContentExitsNoChangeAndWritesNothing pins as
// "no change", instead runs the full apply procedure end to end
// (Applied=true, last.json rewritten, every uci/ubus call made) when
// forceAll is true.
func TestCheckAndApply_FullApplyBypassesEqualContentShortcut(t *testing.T) {
	dir := t.TempDir()
	lastPath := filepath.Join(dir, "last.json")

	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	sections := last.Sections{Interface: "wg0"}
	initial := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"wg0": {Content: b.WG["wg0"], Sections: sections}},
		Stunmesh: "text",
		Firewall: last.FirewallState{ZoneOwned: true, Members: []string{"wg0"}},
	}
	if err := last.Write(lastPath, initial); err != nil {
		t.Fatalf("last.Write: %v", err)
	}
	cfg := &Config{LastPath: lastPath, Stunmesh: StunmeshConfig{WritePath: filepath.Join(dir, "stunmesh.yaml")}}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	fake := execx.NewFake()
	env.Runner = fake

	outcome, err := checkAndApply(env, cfg, b, true)
	if err != nil || !outcome.Applied {
		t.Fatalf("outcome = %+v, err = %v (forceAll must not skip the apply); stderr=%q", outcome, err, stderr.String())
	}

	// wg0 is already a recorded firewall zone member, so manageFirewall
	// has nothing to add there; the point of this assertion is that
	// writeUCI actually ran the interface's own create batch again,
	// not that the firewall zone changed.
	var sawCreate bool
	for _, call := range fake.Calls() {
		if call.Name == "uci" && len(call.Args) == 2 && call.Args[0] == "set" && call.Args[1] == "network.wg0=interface" {
			sawCreate = true
		}
	}
	if !sawCreate {
		t.Errorf("Calls() = %+v, want a full re-creation of network.wg0 even though its content did not change", fake.Calls())
	}

	// "uci commit network" and "ubus call network reload" must have run
	// too: a full apply is the whole procedure, not just the
	// per-interface create batch.
	var sawCommit, sawReload bool
	for _, call := range fake.Calls() {
		if call.Name == "uci" && len(call.Args) == 2 && call.Args[0] == "commit" && call.Args[1] == "network" {
			sawCommit = true
		}
		if call.Name == "ubus" {
			sawReload = true
		}
	}
	if !sawCommit || !sawReload {
		t.Errorf("Calls() = %+v, want both \"uci commit network\" and \"ubus call network reload\"", fake.Calls())
	}

	if _, err := last.Read(lastPath); err != nil {
		t.Errorf("last.Read after full apply: %v", err)
	}
}

// sanity check that our hand-rolled JSON in the tests above actually
// parses the way each test assumes (catches a malformed literal early
// with a clear message rather than a confusing sameContent failure).
func TestParseTestBundleHelperSanity(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,"wg":{},"stunmesh":""}`)
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(data, []byte(`"namespace":"ns"`)) {
		t.Errorf("Marshal = %s, want it to contain the namespace", data)
	}
}
