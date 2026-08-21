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
//	Bundle.WG (required,         map[string]Interface  absent (rejected by
//	  presence-tracked like the                        Validate: ErrWG) /
//	  optional fields)                                 {} / populated
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

// TestCanonicalMatchesJQForLineSeparators checks Canonical against
// the jq reference (PLAN.md 4.5) for U+2028 and U+2029: Go's
// encoding/json always escapes these two runes as the six-byte
// sequences `\u2028` / `\u2029`, even with SetEscapeHTML(false),
// while jq emits their raw UTF-8 bytes. It also checks that literal
// backslash-u2028/backslash-u2029 text already present in the input
// (an escaped backslash followed by literal "u2028"/"u2029") is left
// as the same escape text, not mistaken for an encoder-introduced
// escape.
func TestCanonicalMatchesJQForLineSeparators(t *testing.T) {
	jqPath := jqOrSkip(t)

	// A genuine U+2028/U+2029 rune in the input always comes back from
	// encoding/json as the six-byte escape `\u2028`/`\u2029`; jq
	// instead emits the raw UTF-8 rune. A Go string holding one literal
	// backslash followed by the literal text "u2028"/"u2029" is a
	// different case: marshaling escapes only the backslash (as `\\`),
	// so the JSON text already contains the ASCII escape spelling
	// verbatim, indistinguishable in bytes from what the encoder would
	// produce for a genuine rune -- this is exactly the case
	// unescapeLineSeparators must not touch.
	cases := []struct {
		name string
		// value is the Go string placed in `stunmesh`.
		value string
		// wantSubstring is the exact bytes Canonical's output must
		// contain: the raw UTF-8 rune for a genuine separator, or the
		// JSON-escaped spelling (backslash doubled) for literal
		// backslash-u2028/u2029 text, since a literal backslash is
		// always JSON-escaped regardless of this fix.
		wantSubstring string
	}{
		{"raw U+2028 rune", "before\u2028after", "before\u2028after"},
		{"raw U+2029 rune", "before\u2029after", "before\u2029after"},
		{"literal backslash-u2028 text", "before\\u2028after", `before\\u2028after`},
		{"literal backslash-u2029 text", "before\\u2029after", `before\\u2029after`},
		{"both raw runes in one string", "a\u2028b\u2029c", "a\u2028b\u2029c"},
		{"raw U+2028 rune at string start", "\u2028after", "\u2028after"},
		{"raw U+2028 rune at string end", "before\u2028", "before\u2028"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]any{
				"version":   1,
				"namespace": "n",
				"node_id":   "a",
				"timestamp": 1,
				"wg":        map[string]any{},
				"stunmesh":  tc.value,
			}
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			b := mustParse(t, data)
			got, err := b.Canonical()
			if err != nil {
				t.Fatalf("Canonical: unexpected error: %v", err)
			}

			if !strings.Contains(string(got), tc.wantSubstring) {
				t.Fatalf("Canonical does not contain %q: %s", tc.wantSubstring, got)
			}
			wantJQCanonical(t, jqPath, data, got)
		})
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

// TestParseRejectsExplicitNull covers every field named in the
// finding: a JSON `null` decodes to a Go nil, indistinguishable from
// an absent key, so Parse must reject it outright instead of letting
// it silently look like "absent" to Canonical.
func TestParseRejectsExplicitNull(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{
			name: "wg null",
			json: `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":null}`,
		},
		{
			name: "routes null",
			json: `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"routes":null}}}`,
		},
		{
			name: "options null",
			json: `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"options":null}}}`,
		},
		{
			name: "peers null",
			json: `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":null}}}`,
		},
		{
			name: "stunmesh null",
			json: `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"wg":{},"stunmesh":null}`,
		},
		{
			name: "metric null",
			json: `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"routes":[{"cidr":"10.0.0.0/24","metric":null}]}}}`,
		},
		{
			name: "nested null inside a peer",
			json: `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{"bravo":{"public_key":"p","allowed_ips":["1.1.1.2/32"],"endpoint":null}}}}}`,
		},
		{
			name: "nested null inside a route",
			json: `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"routes":[{"cidr":null}]}}}`,
		},
		{
			name: "null inside an array element",
			json: `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32",null],"peers":{}}}}`,
		},
		{
			name: "whole document is null",
			json: `null`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bundle.Parse([]byte(tc.json))
			if !errors.Is(err, bundle.ErrNull) {
				t.Fatalf("Parse: got %v, want error wrapping ErrNull", err)
			}
		})
	}
}

// TestParseAcceptsValidBundleWithNoNull proves TestParseRejectsExplicitNull
// is not vacuous: a bundle with no `null` anywhere still parses.
func TestParseAcceptsValidBundleWithNoNull(t *testing.T) {
	mustParse(t, testvectors.BundleJSON())
}

// TestWGMayBeEmpty proves that an explicit `"wg":{}` validates: `wg`
// is required (PLAN.md 4.3), but empty means "remove every
// interface", not an error.
func TestWGMayBeEmpty(t *testing.T) {
	data := `{"version":1,"namespace":"test-ns","node_id":"alpha","timestamp":1,"wg":{},"stunmesh":""}`
	b := mustParse(t, []byte(data))
	if err := b.Validate("test-ns", "alpha"); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
}

// TestValidateRejectsMissingWG proves that an absent `wg` key fails
// Validate with ErrWG: `wg` is required (PLAN.md 4.3), and absence is
// distinct from an explicit empty map.
func TestValidateRejectsMissingWG(t *testing.T) {
	data := `{"version":1,"namespace":"test-ns","node_id":"alpha","timestamp":1,"stunmesh":""}`
	b := mustParse(t, []byte(data))
	err := b.Validate("test-ns", "alpha")
	if !errors.Is(err, bundle.ErrWG) {
		t.Fatalf("Validate: got %v, want error wrapping ErrWG", err)
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
// optional `listen_port` field: absent, populated, and explicit zero.
// Explicit zero is outside the valid range (1-65535, see
// TestValidateListenPortRange), so it is covered here as a rejection,
// not as a jq-equality case: the byte-equality contract of Canonical
// only applies to input Validate accepts (PLAN.md 4.5).
func TestInterfaceListenPortStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name  string
		field string
	}{
		{"absent", ``},
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

	t.Run("explicit zero is out of range", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"listen_port":0}}}`)
		b := mustParse(t, data)
		if err := b.Validate("n", "a"); !errors.Is(err, bundle.ErrRange) {
			t.Fatalf("Validate: got %v, want error wrapping ErrRange", err)
		}
	})
}

// TestInterfaceMTUStates covers the three states of the optional
// `mtu` field: absent, populated, and explicit zero. Explicit zero is
// outside the valid range (576-65535, see TestValidateMTURange), so
// it is covered here as a rejection, not as a jq-equality case: the
// byte-equality contract of Canonical only applies to input Validate
// accepts (PLAN.md 4.5).
func TestInterfaceMTUStates(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name  string
		field string
	}{
		{"absent", ``},
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

	t.Run("explicit zero is out of range", func(t *testing.T) {
		data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"mtu":0}}}`)
		b := mustParse(t, data)
		if err := b.Validate("n", "a"); !errors.Is(err, bundle.ErrRange) {
			t.Fatalf("Validate: got %v, want error wrapping ErrRange", err)
		}
	})
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

// listenPortDoc, mtuDoc, metricDoc, and keepaliveDoc build a minimal
// valid bundle JSON document with the given field set on `wg0`, or on
// its first route (metric) or its `bravo` peer (persistent_keepalive).
// Shared by the range-boundary and number-literal tests below.
func listenPortDoc(field string) string {
	return `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{}` + field + `}}}`
}

func mtuDoc(field string) string {
	return `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{}` + field + `}}}`
}

func metricDoc(metric string) string {
	return `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"routes":[{"cidr":"10.0.0.0/24","metric":` + metric + `}]}}}`
}

func keepaliveDoc(field string) string {
	return `{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{"bravo":{"public_key":"p","allowed_ips":["1.1.1.2/32"]` + field + `}}}}}`
}

// TestValidateListenPortRange checks the `listen_port` bound
// (1-65535, docs/format.md 5) at and past each edge.
func TestValidateListenPortRange(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"just below minimum", "0", true},
		{"minimum", "1", false},
		{"maximum", "65535", false},
		{"just above maximum", "65536", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(listenPortDoc(`,"listen_port":` + tc.value))
			b := mustParse(t, data)
			err := b.Validate("n", "a")
			if tc.wantErr {
				if !errors.Is(err, bundle.ErrRange) {
					t.Fatalf("Validate: got %v, want error wrapping ErrRange", err)
				}
				return
			}
			if err != nil {
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

// TestValidateMTURange checks the `mtu` bound (576-65535,
// docs/format.md 5) at and past each edge.
func TestValidateMTURange(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"just below minimum", "575", true},
		{"minimum", "576", false},
		{"maximum", "65535", false},
		{"just above maximum", "65536", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(mtuDoc(`,"mtu":` + tc.value))
			b := mustParse(t, data)
			err := b.Validate("n", "a")
			if tc.wantErr {
				if !errors.Is(err, bundle.ErrRange) {
					t.Fatalf("Validate: got %v, want error wrapping ErrRange", err)
				}
				return
			}
			if err != nil {
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

// TestValidateRouteMetricRange checks the `routes[].metric` bound
// (0-4294967295, docs/format.md 5) at and past each edge.
func TestValidateRouteMetricRange(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"just below minimum", "-1", true},
		{"minimum", "0", false},
		{"maximum", "4294967295", false},
		{"just above maximum", "4294967296", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(metricDoc(tc.value))
			b := mustParse(t, data)
			err := b.Validate("n", "a")
			if tc.wantErr {
				if !errors.Is(err, bundle.ErrRange) {
					t.Fatalf("Validate: got %v, want error wrapping ErrRange", err)
				}
				return
			}
			if err != nil {
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

// TestValidatePersistentKeepaliveRange checks the
// `persistent_keepalive` bound (0-65535, docs/format.md 5) at and
// past each edge.
func TestValidatePersistentKeepaliveRange(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"just below minimum", "-1", true},
		{"minimum", "0", false},
		{"maximum", "65535", false},
		{"just above maximum", "65536", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(keepaliveDoc(`,"persistent_keepalive":` + tc.value))
			b := mustParse(t, data)
			err := b.Validate("n", "a")
			if tc.wantErr {
				if !errors.Is(err, bundle.ErrRange) {
					t.Fatalf("Validate: got %v, want error wrapping ErrRange", err)
				}
				return
			}
			if err != nil {
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

// TestValidateTimestampRange checks the timestamp upper bound
// (2^53-1, docs/format.md 5) at and past the edge. The lower bound
// (must be positive) is already covered by
// TestValidateRejectsNonPositiveTimestamp.
func TestValidateTimestampRange(t *testing.T) {
	jqPath := jqOrSkip(t)

	cases := []struct {
		name      string
		timestamp string
		wantErr   bool
	}{
		{"maximum", "9007199254740991", false},
		{"just above maximum", "9007199254740992", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":` + tc.timestamp + `,"stunmesh":"","wg":{}}`)
			b := mustParse(t, data)
			err := b.Validate("n", "a")
			if tc.wantErr {
				if !errors.Is(err, bundle.ErrRange) {
					t.Fatalf("Validate: got %v, want error wrapping ErrRange", err)
				}
				return
			}
			if err != nil {
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

// TestParseRejectsNonCanonicalNumberLiterals covers ErrNumber: a JSON
// number literal that Go's *int/int64 decoding accepts but that jq
// would not represent identically (a fraction, an exponent, or `-0`,
// which Go silently rounds to plain `0`).
func TestParseRejectsNonCanonicalNumberLiterals(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{
			name: "metric negative zero",
			json: metricDoc("-0"),
		},
		{
			name: "mtu fraction",
			json: mtuDoc(`,"mtu":1.0`),
		},
		{
			name: "listen_port exponent lowercase e",
			json: listenPortDoc(`,"listen_port":1e3`),
		},
		{
			name: "listen_port exponent uppercase E",
			json: listenPortDoc(`,"listen_port":1E3`),
		},
		{
			name: "timestamp negative zero",
			json: `{"version":1,"namespace":"n","node_id":"a","timestamp":-0,"stunmesh":"","wg":{}}`,
		},
		{
			name: "version fraction",
			json: `{"version":1.0,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bundle.Parse([]byte(tc.json))
			if !errors.Is(err, bundle.ErrNumber) {
				t.Fatalf("Parse: got %v, want error wrapping ErrNumber", err)
			}
		})
	}
}

// TestParseAcceptsCanonicalNumberLiterals proves
// TestParseRejectsNonCanonicalNumberLiterals is not vacuous: a bundle
// whose numbers are all plain base-10 integers still parses, and the
// golden vector (whose numbers were never in question) still parses
// and validates.
func TestParseAcceptsCanonicalNumberLiterals(t *testing.T) {
	data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{},"listen_port":51820,"mtu":1420,"routes":[{"cidr":"10.0.0.0/24","metric":0}]}}}`)
	b := mustParse(t, data)
	if err := b.Validate("n", "a"); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}

	b2 := mustParse(t, testvectors.BundleJSON())
	if err := b2.Validate("test-ns", "alpha"); err != nil {
		t.Fatalf("Validate on golden vector: unexpected error: %v", err)
	}
}
