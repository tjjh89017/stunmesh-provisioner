// Optional-field state coverage.
//
// Every optional field on Bundle/Interface/Peer/Route is exercised in
// three states — absent, explicit empty-or-zero, and populated —
// somewhere in this file. "Covered" means a test parses JSON in that
// state and checks Canonical (most such tests also check against the
// jq -S -c 'del(.timestamp)' reference).
//
//	Field                        Type               States covered
//	Bundle.Stunmesh (required,   *string               absent (rejected by
//	  presence-tracked like the                        Validate: ErrStunmesh) /
//	  optional fields)                                 "" / populated
//	Bundle.WG                    map[string]Interface  absent / {} / populated
//	Interface.ListenPort         *int                  absent / 0 / populated
//	Interface.MTU                *int                  absent / 0 / populated
//	Interface.RouteAllowedIPs    *bool                 absent / false / true
//	Interface.Routes             []Route               absent / [] / populated
//	Interface.Options            map[string]string     absent / {} / populated
//	Interface.Peers (required,   map[string]Peer       absent / {} / populated
//	  presence-tracked like the optional fields)
//	Route.Gateway                *string               absent / "" / populated
//	Route.Metric                 *int                  absent / 0 / populated
//	Peer.PresharedKey            *string               absent / "" / populated
//	Peer.Endpoint                *string               absent / "" / populated
//	Peer.PersistentKeepalive     *int                  absent / 0 / populated
//	Peer.Options                 map[string]string     absent / {} / populated
package bundle_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/testvectors"
)

func mustParse(t *testing.T, data []byte) *bundle.Bundle {
	t.Helper()
	b, err := bundle.Parse(data)
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	return b
}

// strPtr returns a pointer to s, for building code-level Bundle
// literals where Stunmesh, PresharedKey, Endpoint, or Gateway need an
// explicit (non-nil) value.
func strPtr(s string) *string {
	return &s
}

func TestParseRoundTripsToCanonicalVector(t *testing.T) {
	b := mustParse(t, testvectors.BundleJSON())

	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}

	want := testvectors.CanonicalJSON()
	if string(got) != string(want) {
		t.Fatalf("Canonical mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestCanonicalDoesNotHTMLEscape(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(testvectors.BundleJSON(), &m); err != nil {
		t.Fatalf("unmarshal vector: %v", err)
	}
	m["stunmesh"] = "a&b<c>d"
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	b := mustParse(t, data)

	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}

	if !strings.Contains(string(got), "a&b<c>d") {
		t.Fatalf("Canonical output HTML-escapes special characters, want the raw bytes a&b<c>d: %s", got)
	}
}

// TestCanonicalDoesNotHTMLEscapeCodeBuiltBundle exercises the code-built
// path of Canonical (no raw bytes): it marshals the struct first, then
// runs the same no-HTML-escaping encoder.
func TestCanonicalDoesNotHTMLEscapeCodeBuiltBundle(t *testing.T) {
	b := &bundle.Bundle{
		Version:   1,
		Namespace: "test-ns",
		NodeID:    "alpha",
		Timestamp: 1,
		Stunmesh:  strPtr("a&b<c>d"),
	}

	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}

	if !strings.Contains(string(got), "a&b<c>d") {
		t.Fatalf("Canonical output HTML-escapes special characters, want the raw bytes a&b<c>d: %s", got)
	}
}

func TestValidateVectorPasses(t *testing.T) {
	b := mustParse(t, testvectors.BundleJSON())
	if err := b.Validate("test-ns", "alpha"); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
}

func TestValidateChecks(t *testing.T) {
	cases := []struct {
		name      string
		namespace string
		nodeID    string
		mutate    func(*bundle.Bundle)
		wantErr   error
	}{
		{
			name:      "wrong namespace",
			namespace: "other-ns",
			nodeID:    "alpha",
			wantErr:   bundle.ErrNamespace,
		},
		{
			name:      "wrong node id",
			namespace: "test-ns",
			nodeID:    "beta",
			wantErr:   bundle.ErrNodeID,
		},
		{
			name:      "wrong version",
			namespace: "test-ns",
			nodeID:    "alpha",
			mutate:    func(b *bundle.Bundle) { b.Version = 2 },
			wantErr:   bundle.ErrVersion,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := mustParse(t, testvectors.BundleJSON())
			if tc.mutate != nil {
				tc.mutate(b)
			}
			err := b.Validate(tc.namespace, tc.nodeID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate: got %v, want error wrapping %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{
			name: "unknown top-level key",
			json: `{
				"version": 1, "namespace": "test-ns", "node_id": "alpha",
				"timestamp": 1, "wg": {}, "stunmesh": "", "bogus": true
			}`,
		},
		{
			name: "unknown interface key",
			json: `{
				"version": 1, "namespace": "test-ns", "node_id": "alpha",
				"timestamp": 1, "stunmesh": "",
				"wg": { "wg0": {
					"private_key": "k", "addresses": ["10.0.0.1/24"], "peers": {},
					"bogus": true
				}}
			}`,
		},
		{
			name: "unknown peer key",
			json: `{
				"version": 1, "namespace": "test-ns", "node_id": "alpha",
				"timestamp": 1, "stunmesh": "",
				"wg": { "wg0": {
					"private_key": "k", "addresses": ["10.0.0.1/24"],
					"peers": { "bravo": { "public_key": "p", "allowed_ips": ["10.0.0.2/32"], "bogus": true } }
				}}
			}`,
		},
		{
			name: "unknown route key",
			json: `{
				"version": 1, "namespace": "test-ns", "node_id": "alpha",
				"timestamp": 1, "stunmesh": "",
				"wg": { "wg0": {
					"private_key": "k", "addresses": ["10.0.0.1/24"], "peers": {},
					"routes": [ { "cidr": "10.0.0.0/24", "bogus": true } ]
				}}
			}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := bundle.Parse([]byte(tc.json)); err == nil {
				t.Fatalf("Parse: got no error, want an error for %s", tc.name)
			}
		})
	}
}

func TestParseRejectsTrailingData(t *testing.T) {
	data := append(append([]byte{}, testvectors.BundleJSON()...), []byte(`{}`)...)
	if _, err := bundle.Parse(data); err == nil {
		t.Fatal("Parse: got no error, want an error for trailing data")
	}
}

func TestWGMayBeEmptyOrMissing(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{
			name: "empty wg",
			json: `{"version":1,"namespace":"test-ns","node_id":"alpha","timestamp":1,"wg":{},"stunmesh":""}`,
		},
		{
			name: "missing wg",
			json: `{"version":1,"namespace":"test-ns","node_id":"alpha","timestamp":1,"stunmesh":""}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := mustParse(t, []byte(tc.json))
			if err := b.Validate("test-ns", "alpha"); err != nil {
				t.Fatalf("Validate: unexpected error: %v", err)
			}
		})
	}
}

func TestValidateInterfaceAndPeerRequirements(t *testing.T) {
	base := func() map[string]any {
		var m map[string]any
		if err := json.Unmarshal(testvectors.BundleJSON(), &m); err != nil {
			t.Fatalf("unmarshal vector: %v", err)
		}
		return m
	}

	cases := []struct {
		name      string
		mutate    func(m map[string]any)
		wantErr   error
		wantParse bool // if true, expect Parse error instead of Validate error
	}{
		{
			name: "empty private_key names wg0",
			mutate: func(m map[string]any) {
				wg := m["wg"].(map[string]any)
				wg0 := wg["wg0"].(map[string]any)
				wg0["private_key"] = ""
			},
			wantErr: bundle.ErrInterface,
		},
		{
			name: "no addresses",
			mutate: func(m map[string]any) {
				wg := m["wg"].(map[string]any)
				wg0 := wg["wg0"].(map[string]any)
				wg0["addresses"] = []any{}
			},
			wantErr: bundle.ErrInterface,
		},
		{
			name: "empty public_key names the peer",
			mutate: func(m map[string]any) {
				wg := m["wg"].(map[string]any)
				wg0 := wg["wg0"].(map[string]any)
				peers := wg0["peers"].(map[string]any)
				bravo := peers["bravo"].(map[string]any)
				bravo["public_key"] = ""
			},
			wantErr: bundle.ErrPeer,
		},
		{
			name: "no allowed_ips",
			mutate: func(m map[string]any) {
				wg := m["wg"].(map[string]any)
				wg0 := wg["wg0"].(map[string]any)
				peers := wg0["peers"].(map[string]any)
				bravo := peers["bravo"].(map[string]any)
				bravo["allowed_ips"] = []any{}
			},
			wantErr: bundle.ErrPeer,
		},
		{
			name: "empty route cidr",
			mutate: func(m map[string]any) {
				wg := m["wg"].(map[string]any)
				wg0 := wg["wg0"].(map[string]any)
				routes := wg0["routes"].([]any)
				r0 := routes[0].(map[string]any)
				r0["cidr"] = ""
			},
			wantErr: bundle.ErrRoute,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.mutate(m)
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			b, err := bundle.Parse(data)
			if err != nil {
				t.Fatalf("Parse: unexpected error: %v", err)
			}
			verr := b.Validate("test-ns", "alpha")
			if !errors.Is(verr, tc.wantErr) {
				t.Fatalf("Validate: got %v, want error wrapping %v", verr, tc.wantErr)
			}
			if tc.name == "empty private_key names wg0" && !strings.Contains(verr.Error(), "wg0") {
				t.Fatalf("Validate error %q does not name the interface key wg0", verr.Error())
			}
			if tc.name == "empty public_key names the peer" && !strings.Contains(verr.Error(), "bravo") {
				t.Fatalf("Validate error %q does not name the peer key bravo", verr.Error())
			}
		})
	}
}

func TestValidateRejectsMissingPeers(t *testing.T) {
	data := `{
		"version": 1, "namespace": "test-ns", "node_id": "alpha",
		"timestamp": 1, "stunmesh": "",
		"wg": { "wg0": { "private_key": "k", "addresses": ["10.0.0.1/24"] } }
	}`
	b := mustParse(t, []byte(data))
	err := b.Validate("test-ns", "alpha")
	if !errors.Is(err, bundle.ErrInterface) {
		t.Fatalf("Validate: got %v, want error wrapping ErrInterface", err)
	}
}

func TestRouteAllowedIPsOrDefault(t *testing.T) {
	var withNil bundle.Interface
	if got := withNil.RouteAllowedIPsOrDefault(); got != true {
		t.Fatalf("nil RouteAllowedIPs: got %v, want true", got)
	}

	f := false
	withFalse := bundle.Interface{RouteAllowedIPs: &f}
	if got := withFalse.RouteAllowedIPsOrDefault(); got != false {
		t.Fatalf("false RouteAllowedIPs: got %v, want false", got)
	}
}

// TestCanonicalReflectsMutationAfterParse proves Canonical derives
// from the current struct state, not from bytes captured at Parse
// time: mutating a field after Parse must change Canonical's output.
func TestCanonicalReflectsMutationAfterParse(t *testing.T) {
	b := mustParse(t, testvectors.BundleJSON())

	before, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}

	b.Stunmesh = strPtr("mutated-after-parse")

	after, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}

	if bytes.Equal(before, after) {
		t.Fatalf("Canonical did not reflect the mutation: %s", after)
	}
	if !strings.Contains(string(after), "mutated-after-parse") {
		t.Fatalf("Canonical does not contain the mutated value: %s", after)
	}
}

// TestEqualReflectsMutationAfterParse proves Equal, which is built on
// Canonical, sees a post-Parse mutation instead of comparing stale
// captured bytes.
func TestEqualReflectsMutationAfterParse(t *testing.T) {
	a := mustParse(t, testvectors.BundleJSON())
	b := mustParse(t, testvectors.BundleJSON())

	b.Stunmesh = strPtr("mutated-after-parse")

	eq, err := a.Equal(b)
	if err != nil {
		t.Fatalf("Equal: unexpected error: %v", err)
	}
	if eq {
		t.Fatal("Equal: got true, want false after mutating b post-Parse")
	}
}

// TestCanonicalNilWGIsAbsentNotNull proves that a code-built Bundle
// with a nil WG map canonicalizes with no "wg" key at all, never
// `"wg":null`.
func TestCanonicalNilWGIsAbsentNotNull(t *testing.T) {
	b := &bundle.Bundle{
		Version:   1,
		Namespace: "test-ns",
		NodeID:    "alpha",
		Timestamp: 1,
		Stunmesh:  strPtr(""),
		// WG left nil on purpose.
	}

	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}
	if strings.Contains(string(got), `"wg"`) {
		t.Fatalf("Canonical emitted a wg key for a nil WG map, want it absent: %s", got)
	}
}

func TestEqualIgnoresTimestamp(t *testing.T) {
	a := mustParse(t, testvectors.BundleJSON())
	b := mustParse(t, testvectors.BundleJSON())
	b.Timestamp = a.Timestamp + 1000

	eq, err := a.Equal(b)
	if err != nil {
		t.Fatalf("Equal: unexpected error: %v", err)
	}
	if !eq {
		t.Fatal("Equal: got false, want true for bundles differing only in timestamp")
	}
}

func TestEqualDetectsPeerFieldChange(t *testing.T) {
	a := mustParse(t, testvectors.BundleJSON())

	var m map[string]any
	if err := json.Unmarshal(testvectors.BundleJSON(), &m); err != nil {
		t.Fatalf("unmarshal vector: %v", err)
	}
	wg := m["wg"].(map[string]any)
	wg0 := wg["wg0"].(map[string]any)
	peers := wg0["peers"].(map[string]any)
	bravo := peers["bravo"].(map[string]any)
	bravo["endpoint"] = "changed.example.com:51820"
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b := mustParse(t, data)

	eq, err := a.Equal(b)
	if err != nil {
		t.Fatalf("Equal: unexpected error: %v", err)
	}
	if eq {
		t.Fatal("Equal: got true, want false for bundles differing in a peer field")
	}
}

func TestErrorsNeverContainPrivateKeyValue(t *testing.T) {
	const marker = "SECRET-MARKER-DO-NOT-LEAK-0123456789"

	var m map[string]any
	if err := json.Unmarshal(testvectors.BundleJSON(), &m); err != nil {
		t.Fatalf("unmarshal vector: %v", err)
	}
	wg := m["wg"].(map[string]any)
	wg0 := wg["wg0"].(map[string]any)
	wg0["private_key"] = marker
	// also break a check so Validate returns an error that has to name
	// something about this interface.
	m["namespace"] = "wrong-ns"

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	b, err := bundle.Parse(data)
	if err != nil {
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("Parse error contains the private key value: %q", err.Error())
		}
		t.Fatalf("Parse: unexpected error: %v", err)
	}

	verr := b.Validate("test-ns", "alpha")
	if verr == nil {
		t.Fatal("Validate: got no error, want ErrNamespace")
	}
	if strings.Contains(verr.Error(), marker) {
		t.Fatalf("Validate error contains the private key value: %q", verr.Error())
	}

	// Also exercise a Validate error that names the interface, to make
	// sure that path does not leak the private key either.
	m["namespace"] = "test-ns"
	wg0["addresses"] = []any{}
	data, err = json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b2 := mustParse(t, data)
	verr2 := b2.Validate("test-ns", "alpha")
	if verr2 == nil {
		t.Fatal("Validate: got no error, want ErrInterface")
	}
	if strings.Contains(verr2.Error(), marker) {
		t.Fatalf("Validate error contains the private key value: %q", verr2.Error())
	}
}

func TestCanonicalPreservesExplicitEmptyWG(t *testing.T) {
	data := []byte(`{"version":1,"namespace":"test-ns","node_id":"alpha","timestamp":1,"wg":{},"stunmesh":""}`)
	b := mustParse(t, data)

	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}
	if !strings.Contains(string(got), `"wg":{}`) {
		t.Fatalf("Canonical dropped an explicitly empty wg: %s", got)
	}
}

func TestCanonicalPreservesExplicitEmptyRoutesAndOptions(t *testing.T) {
	data := []byte(`{
		"version": 1, "namespace": "test-ns", "node_id": "alpha",
		"timestamp": 1, "stunmesh": "",
		"wg": { "wg0": {
			"private_key": "k", "addresses": ["10.0.0.1/24"],
			"routes": [], "options": {}, "peers": {}
		}}
	}`)
	b := mustParse(t, data)

	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}
	if !strings.Contains(string(got), `"routes":[]`) {
		t.Fatalf("Canonical dropped an explicitly empty routes list: %s", got)
	}
	if !strings.Contains(string(got), `"options":{}`) {
		t.Fatalf("Canonical dropped an explicitly empty options map: %s", got)
	}
}

// TestCanonicalMatchesJQReference checks Canonical against the
// `jq -S -c 'del(.timestamp)'` reference command (PLAN.md 4.5), on
// inputs that carry explicitly empty containers plus the golden
// vector. It skips when jq is not on PATH.
func TestCanonicalMatchesJQReference(t *testing.T) {
	jqPath, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq not found on PATH, skipping byte-equality check against the jq reference")
	}

	inputs := map[string][]byte{
		"explicit empty wg": []byte(
			`{"version":1,"namespace":"test-ns","node_id":"alpha","timestamp":1,"wg":{},"stunmesh":""}`,
		),
		"explicit empty routes and options": []byte(`{
			"version": 1, "namespace": "test-ns", "node_id": "alpha",
			"timestamp": 1, "stunmesh": "",
			"wg": { "wg0": {
				"private_key": "k", "addresses": ["10.0.0.1/24"],
				"routes": [], "options": {}, "peers": {}
			}}
		}`),
		"absent peers": []byte(
			`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"]}},"stunmesh":""}`,
		),
		"golden vector": testvectors.BundleJSON(),
	}

	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			b := mustParse(t, in)
			got, err := b.Canonical()
			if err != nil {
				t.Fatalf("Canonical: unexpected error: %v", err)
			}

			cmd := exec.Command(jqPath, "-S", "-c", "del(.timestamp)")
			cmd.Stdin = bytes.NewReader(in)
			want, err := cmd.Output()
			if err != nil {
				t.Fatalf("jq: %v", err)
			}
			want = bytes.TrimRight(want, "\n")

			if !bytes.Equal(got, want) {
				t.Fatalf("Canonical mismatch with jq reference\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// TestCanonicalOmitsAbsentPeers checks that an interface parsed from
// input with no `peers` key canonicalizes without a `peers` key at
// all, and never as `"peers":null`. This mirrors the rule already
// applied to `routes` and `options`.
func TestCanonicalOmitsAbsentPeers(t *testing.T) {
	data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"]}},"stunmesh":""}`)
	b := mustParse(t, data)

	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}
	if strings.Contains(string(got), `"peers"`) {
		t.Fatalf("Canonical emitted a peers key for an absent peers input: %s", got)
	}
	if strings.Contains(string(got), "null") {
		t.Fatalf("Canonical emitted null for an absent peers input: %s", got)
	}
}

// TestCanonicalPreservesExplicitEmptyPeers checks that an explicit
// `"peers":{}` in the input is preserved in canonical form, matching
// the presence rule for `wg`, `routes`, and `options`.
func TestCanonicalPreservesExplicitEmptyPeers(t *testing.T) {
	data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{}}},"stunmesh":""}`)
	b := mustParse(t, data)

	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}
	if !strings.Contains(string(got), `"peers":{}`) {
		t.Fatalf("Canonical dropped an explicitly empty peers map: %s", got)
	}
}

// TestCodeBuiltBundleNilAddressesFailsValidate documents the chosen
// behavior for a Bundle built in code with a nil Addresses slice: it
// is rejected by Validate (addresses must have at least one entry),
// so it never reaches Canonical and can never emit a `null` in place
// of the required list.
func TestCodeBuiltBundleNilAddressesFailsValidate(t *testing.T) {
	b := &bundle.Bundle{
		Version:   1,
		Namespace: "test-ns",
		NodeID:    "alpha",
		Timestamp: 1,
		Stunmesh:  strPtr(""),
		WG: map[string]bundle.Interface{
			"wg0": {
				PrivateKey: "k",
				// Addresses left nil on purpose.
				Peers: map[string]bundle.Peer{},
			},
		},
	}

	err := b.Validate("test-ns", "alpha")
	if !errors.Is(err, bundle.ErrInterface) {
		t.Fatalf("Validate: got %v, want error wrapping ErrInterface for nil addresses", err)
	}
}

func TestValidateRejectsNonPositiveTimestamp(t *testing.T) {
	cases := []struct {
		name      string
		timestamp int64
	}{
		{"zero timestamp", 0},
		{"negative timestamp", -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := mustParse(t, testvectors.BundleJSON())
			b.Timestamp = tc.timestamp

			err := b.Validate("test-ns", "alpha")
			if !errors.Is(err, bundle.ErrTimestamp) {
				t.Fatalf("Validate: got %v, want error wrapping ErrTimestamp", err)
			}
		})
	}
}

// jqOrSkip returns the path to jq, or skips the test if jq is not on
// PATH. Tests that check Canonical byte-for-byte against the
// `jq -S -c 'del(.timestamp)'` reference (PLAN.md 4.5) use this.
func jqOrSkip(t *testing.T) string {
	t.Helper()
	jqPath, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq not found on PATH, skipping byte-equality check against the jq reference")
	}
	return jqPath
}

// wantJQCanonical runs the jq reference command on input and fails
// the test if got does not match its output byte for byte.
func wantJQCanonical(t *testing.T, jqPath string, input, got []byte) {
	t.Helper()
	cmd := exec.Command(jqPath, "-S", "-c", "del(.timestamp)")
	cmd.Stdin = bytes.NewReader(input)
	want, err := cmd.Output()
	if err != nil {
		t.Fatalf("jq: %v", err)
	}
	want = bytes.TrimRight(want, "\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("Canonical mismatch with jq reference\n got: %s\nwant: %s", got, want)
	}
}

// TestBundleStunmeshStates covers the three states of the required,
// presence-tracked `stunmesh` field: absent (rejected by Validate
// with ErrStunmesh), explicit empty string (valid, "no stunmesh
// config"), and populated (valid).
func TestBundleStunmeshStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	t.Run("absent", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"wg":{}}`)
		b := mustParse(t, data)
		err := b.Validate("n", "a")
		if !errors.Is(err, bundle.ErrStunmesh) {
			t.Fatalf("Validate: got %v, want error wrapping ErrStunmesh for absent stunmesh", err)
		}
	})

	t.Run("explicit empty", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"wg":{},"stunmesh":""}`)
		b := mustParse(t, data)
		if err := b.Validate("n", "a"); err != nil {
			t.Fatalf("Validate: unexpected error: %v", err)
		}
		got, err := b.Canonical()
		if err != nil {
			t.Fatalf("Canonical: unexpected error: %v", err)
		}
		if !strings.Contains(string(got), `"stunmesh":""`) {
			t.Fatalf("Canonical dropped an explicitly empty stunmesh: %s", got)
		}
		wantJQCanonical(t, jqPath, data, got)
	})

	t.Run("populated", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"wg":{},"stunmesh":"cfg text"}`)
		b := mustParse(t, data)
		if err := b.Validate("n", "a"); err != nil {
			t.Fatalf("Validate: unexpected error: %v", err)
		}
		got, err := b.Canonical()
		if err != nil {
			t.Fatalf("Canonical: unexpected error: %v", err)
		}
		if !strings.Contains(string(got), `"stunmesh":"cfg text"`) {
			t.Fatalf("Canonical dropped a populated stunmesh: %s", got)
		}
		wantJQCanonical(t, jqPath, data, got)
	})
}

// TestParseAbsentStunmeshFailsValidateNotUnknownField makes sure an
// absent stunmesh key is a normal Parse success followed by a
// Validate failure (ErrStunmesh), not a Parse-time error: `stunmesh`
// is not decorated `omitempty` for decoding purposes, but Parse must
// still accept its absence since Go's decoder does not require every
// declared field to be present.
func TestParseAbsentStunmeshFailsValidateNotUnknownField(t *testing.T) {
	data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"wg":{}}`)
	b, err := bundle.Parse(data)
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if err := b.Validate("n", "a"); !errors.Is(err, bundle.ErrStunmesh) {
		t.Fatalf("Validate: got %v, want error wrapping ErrStunmesh", err)
	}
}

// TestPeerPresharedKeyStates covers the three states of the optional
// `preshared_key` field: absent, explicit empty string (invalid, an
// empty preshared key is never meaningful), and populated.
func TestPeerPresharedKeyStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	t.Run("absent", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{"bravo":{"public_key":"p","allowed_ips":["1.1.1.2/32"]}}}}}`)
		b := mustParse(t, data)
		if err := b.Validate("n", "a"); err != nil {
			t.Fatalf("Validate: unexpected error: %v", err)
		}
		got, err := b.Canonical()
		if err != nil {
			t.Fatalf("Canonical: unexpected error: %v", err)
		}
		if strings.Contains(string(got), "preshared_key") {
			t.Fatalf("Canonical emitted preshared_key for an absent input: %s", got)
		}
		wantJQCanonical(t, jqPath, data, got)
	})

	t.Run("explicit empty", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{"bravo":{"public_key":"p","allowed_ips":["1.1.1.2/32"],"preshared_key":""}}}}}`)
		b := mustParse(t, data)
		err := b.Validate("n", "a")
		if !errors.Is(err, bundle.ErrPeer) {
			t.Fatalf("Validate: got %v, want error wrapping ErrPeer for an explicit empty preshared_key", err)
		}
	})

	t.Run("populated", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{"bravo":{"public_key":"p","allowed_ips":["1.1.1.2/32"],"preshared_key":"psk-value"}}}}}`)
		b := mustParse(t, data)
		if err := b.Validate("n", "a"); err != nil {
			t.Fatalf("Validate: unexpected error: %v", err)
		}
		got, err := b.Canonical()
		if err != nil {
			t.Fatalf("Canonical: unexpected error: %v", err)
		}
		if !strings.Contains(string(got), `"preshared_key":"psk-value"`) {
			t.Fatalf("Canonical dropped a populated preshared_key: %s", got)
		}
		wantJQCanonical(t, jqPath, data, got)
	})
}

// TestPeerEndpointStates covers the three states of the optional
// `endpoint` field: absent, explicit empty string (invalid), and
// populated.
func TestPeerEndpointStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	t.Run("absent", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{"bravo":{"public_key":"p","allowed_ips":["1.1.1.2/32"]}}}}}`)
		b := mustParse(t, data)
		if err := b.Validate("n", "a"); err != nil {
			t.Fatalf("Validate: unexpected error: %v", err)
		}
		got, err := b.Canonical()
		if err != nil {
			t.Fatalf("Canonical: unexpected error: %v", err)
		}
		if strings.Contains(string(got), "endpoint") {
			t.Fatalf("Canonical emitted endpoint for an absent input: %s", got)
		}
		wantJQCanonical(t, jqPath, data, got)
	})

	t.Run("explicit empty", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{"bravo":{"public_key":"p","allowed_ips":["1.1.1.2/32"],"endpoint":""}}}}}`)
		b := mustParse(t, data)
		err := b.Validate("n", "a")
		if !errors.Is(err, bundle.ErrPeer) {
			t.Fatalf("Validate: got %v, want error wrapping ErrPeer for an explicit empty endpoint", err)
		}
	})

	t.Run("populated", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{"bravo":{"public_key":"p","allowed_ips":["1.1.1.2/32"],"endpoint":"host.example.com:51820"}}}}}`)
		b := mustParse(t, data)
		if err := b.Validate("n", "a"); err != nil {
			t.Fatalf("Validate: unexpected error: %v", err)
		}
		got, err := b.Canonical()
		if err != nil {
			t.Fatalf("Canonical: unexpected error: %v", err)
		}
		if !strings.Contains(string(got), `"endpoint":"host.example.com:51820"`) {
			t.Fatalf("Canonical dropped a populated endpoint: %s", got)
		}
		wantJQCanonical(t, jqPath, data, got)
	})
}

// TestRouteGatewayStates covers the three states of the optional
// `gateway` field: absent, explicit empty string (invalid), and
// populated.
func TestRouteGatewayStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	t.Run("absent", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"routes":[{"cidr":"10.0.0.0/24"}]}}}`)
		b := mustParse(t, data)
		if err := b.Validate("n", "a"); err != nil {
			t.Fatalf("Validate: unexpected error: %v", err)
		}
		got, err := b.Canonical()
		if err != nil {
			t.Fatalf("Canonical: unexpected error: %v", err)
		}
		if strings.Contains(string(got), "gateway") {
			t.Fatalf("Canonical emitted gateway for an absent input: %s", got)
		}
		wantJQCanonical(t, jqPath, data, got)
	})

	t.Run("explicit empty", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"routes":[{"cidr":"10.0.0.0/24","gateway":""}]}}}`)
		b := mustParse(t, data)
		err := b.Validate("n", "a")
		if !errors.Is(err, bundle.ErrRoute) {
			t.Fatalf("Validate: got %v, want error wrapping ErrRoute for an explicit empty gateway", err)
		}
	})

	t.Run("populated", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"routes":[{"cidr":"10.0.0.0/24","gateway":"10.0.0.1"}]}}}`)
		b := mustParse(t, data)
		if err := b.Validate("n", "a"); err != nil {
			t.Fatalf("Validate: unexpected error: %v", err)
		}
		got, err := b.Canonical()
		if err != nil {
			t.Fatalf("Canonical: unexpected error: %v", err)
		}
		if !strings.Contains(string(got), `"gateway":"10.0.0.1"`) {
			t.Fatalf("Canonical dropped a populated gateway: %s", got)
		}
		wantJQCanonical(t, jqPath, data, got)
	})
}

// TestRouteMetricStates covers the three states of `routes[].metric`:
// absent, explicit zero (must be preserved as `0`, not dropped like a
// plain `omitempty` int would), and populated.
func TestRouteMetricStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name  string
		route string
	}{
		{"absent", `{"cidr":"10.0.0.0/24"}`},
		{"explicit zero", `{"cidr":"10.0.0.0/24","metric":0}`},
		{"populated", `{"cidr":"10.0.0.0/24","metric":7}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"routes":[` + tc.route + `]}}}`)
			b := mustParse(t, data)
			if err := b.Validate("n", "a"); err != nil {
				t.Fatalf("Validate: unexpected error: %v", err)
			}
			got, err := b.Canonical()
			if err != nil {
				t.Fatalf("Canonical: unexpected error: %v", err)
			}
			wantJQCanonical(t, jqPath, data, got)
		})
	}
}

// TestPeerOptionsStates covers the three states of the optional peer
// `options` field: absent, explicit empty map, and populated. This
// mirrors the interface-level `options` coverage already exercised by
// TestCanonicalPreservesExplicitEmptyRoutesAndOptions, but for a peer.
func TestPeerOptionsStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name string
		opts string
	}{
		{"absent", ``},
		{"explicit empty", `,"options":{}`},
		{"populated", `,"options":{"note":"x"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{"bravo":{"public_key":"p","allowed_ips":["1.1.1.2/32"]` + tc.opts + `}}}}}`)
			b := mustParse(t, data)
			if err := b.Validate("n", "a"); err != nil {
				t.Fatalf("Validate: unexpected error: %v", err)
			}
			got, err := b.Canonical()
			if err != nil {
				t.Fatalf("Canonical: unexpected error: %v", err)
			}
			wantJQCanonical(t, jqPath, data, got)
		})
	}
}

// TestInterfaceListenPortStates covers the three states of the
// optional `listen_port` field: absent, explicit zero, and populated.
func TestInterfaceListenPortStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name  string
		field string
	}{
		{"absent", ``},
		{"explicit zero", `,"listen_port":0`},
		{"populated", `,"listen_port":51820`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{}` + tc.field + `}}}`)
			b := mustParse(t, data)
			if err := b.Validate("n", "a"); err != nil {
				t.Fatalf("Validate: unexpected error: %v", err)
			}
			got, err := b.Canonical()
			if err != nil {
				t.Fatalf("Canonical: unexpected error: %v", err)
			}
			wantJQCanonical(t, jqPath, data, got)
		})
	}
}

// TestInterfaceMTUStates covers the three states of the optional
// `mtu` field: absent, explicit zero, and populated.
func TestInterfaceMTUStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name  string
		field string
	}{
		{"absent", ``},
		{"explicit zero", `,"mtu":0`},
		{"populated", `,"mtu":1420`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{}` + tc.field + `}}}`)
			b := mustParse(t, data)
			if err := b.Validate("n", "a"); err != nil {
				t.Fatalf("Validate: unexpected error: %v", err)
			}
			got, err := b.Canonical()
			if err != nil {
				t.Fatalf("Canonical: unexpected error: %v", err)
			}
			wantJQCanonical(t, jqPath, data, got)
		})
	}
}

// TestInterfaceRouteAllowedIPsStates covers the three states of the
// optional `route_allowed_ips` field: absent (default true, but
// stored as absent, not as an explicit `true`), explicit false
// (the zero value for bool), and explicit true.
func TestInterfaceRouteAllowedIPsStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name  string
		field string
	}{
		{"absent", ``},
		{"explicit false", `,"route_allowed_ips":false`},
		{"explicit true", `,"route_allowed_ips":true`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{}` + tc.field + `}}}`)
			b := mustParse(t, data)
			if err := b.Validate("n", "a"); err != nil {
				t.Fatalf("Validate: unexpected error: %v", err)
			}
			got, err := b.Canonical()
			if err != nil {
				t.Fatalf("Canonical: unexpected error: %v", err)
			}
			wantJQCanonical(t, jqPath, data, got)
		})
	}
}

// TestInterfaceOptionsStates covers the three states of the optional
// interface-level `options` field: absent, explicit empty map, and
// populated.
func TestInterfaceOptionsStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name  string
		field string
	}{
		{"absent", ``},
		{"explicit empty", `,"options":{}`},
		{"populated", `,"options":{"defaultroute":"0"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{}` + tc.field + `}}}`)
			b := mustParse(t, data)
			if err := b.Validate("n", "a"); err != nil {
				t.Fatalf("Validate: unexpected error: %v", err)
			}
			got, err := b.Canonical()
			if err != nil {
				t.Fatalf("Canonical: unexpected error: %v", err)
			}
			wantJQCanonical(t, jqPath, data, got)
		})
	}
}

// TestInterfaceRoutesStates covers the three states of the optional
// interface-level `routes` field: absent, explicit empty list, and
// populated.
func TestInterfaceRoutesStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name  string
		field string
	}{
		{"absent", ``},
		{"explicit empty", `,"routes":[]`},
		{"populated", `,"routes":[{"cidr":"10.0.0.0/24"}]`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{}` + tc.field + `}}}`)
			b := mustParse(t, data)
			if err := b.Validate("n", "a"); err != nil {
				t.Fatalf("Validate: unexpected error: %v", err)
			}
			got, err := b.Canonical()
			if err != nil {
				t.Fatalf("Canonical: unexpected error: %v", err)
			}
			wantJQCanonical(t, jqPath, data, got)
		})
	}
}

// TestPeerPersistentKeepaliveStates covers the three states of the
// optional `persistent_keepalive` field: absent, explicit zero, and
// populated.
func TestPeerPersistentKeepaliveStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name  string
		field string
	}{
		{"absent", ``},
		{"explicit zero", `,"persistent_keepalive":0`},
		{"populated", `,"persistent_keepalive":25`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{"bravo":{"public_key":"p","allowed_ips":["1.1.1.2/32"]` + tc.field + `}}}}}`)
			b := mustParse(t, data)
			if err := b.Validate("n", "a"); err != nil {
				t.Fatalf("Validate: unexpected error: %v", err)
			}
			got, err := b.Canonical()
			if err != nil {
				t.Fatalf("Canonical: unexpected error: %v", err)
			}
			wantJQCanonical(t, jqPath, data, got)
		})
	}
}
