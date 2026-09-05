package main

import (
	"encoding/json"
	"testing"
)

// wgFwmark builds a minimal wg.yaml body with fwmark set to raw
// (unquoted, so raw's own YAML/JSON spelling controls the type).
func wgFwmark(raw string) string {
	return `wg0:
  private_key: cGxhY2Vob2xkZXItcHJpdmF0ZS1rZXktMzItYnl0ZXMh
  addresses:
    - 10.0.0.1/24
  fwmark: ` + raw + `
  peers:
    bravo:
      public_key: cGxhY2Vob2xkZXItcHVibGljLWtleS0zMi1ieXRlcyE=
      allowed_ips:
        - 10.0.0.2/32
`
}

// TestBuildBundle_FwmarkString checks fwmark as a JSON/YAML string
// (hex, octal, decimal) normalizes to the matching bundle integer.
func TestBuildBundle_FwmarkString(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int64
	}{
		{"quoted hex", `"0xca6c"`, 51820},
		{"quoted octal", `"0o10"`, 8},
		{"quoted decimal", `"51820"`, 51820},
		{"bare integer", `51820`, 51820},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := testNode(t, "alpha", wgFwmark(tc.raw), "")
			b, err := buildBundle("myns", node, fixedNow())
			if err != nil {
				t.Fatalf("buildBundle: %v", err)
			}
			iface, ok := b.WG["wg0"]
			if !ok {
				t.Fatal("bundle has no wg0 interface")
			}
			if iface.Fwmark == nil || *iface.Fwmark != tc.want {
				t.Fatalf("iface.Fwmark = %v, want %d", iface.Fwmark, tc.want)
			}
		})
	}
}

// TestBuildBundle_FwmarkMaxValuePreservesPrecision checks fwmark at
// its documented maximum (docs/format.md 6) round-trips exactly:
// normalizeWG's json.Number path must not lose precision by passing
// the value through a float64.
func TestBuildBundle_FwmarkMaxValuePreservesPrecision(t *testing.T) {
	node := testNode(t, "alpha", wgFwmark("4294967295"), "")
	b, err := buildBundle("myns", node, fixedNow())
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	iface := b.WG["wg0"]
	if iface.Fwmark == nil || *iface.Fwmark != 4294967295 {
		t.Fatalf("iface.Fwmark = %v, want 4294967295", iface.Fwmark)
	}
}

// TestBuildBundle_FwmarkRejected checks an invalid fwmark fails buildBundle.
func TestBuildBundle_FwmarkRejected(t *testing.T) {
	for _, raw := range []string{`"0"`, `"abc"`, `"0x1ffffffff"`, `"010"`, `true`} {
		t.Run(raw, func(t *testing.T) {
			node := testNode(t, "alpha", wgFwmark(raw), "")
			if _, err := buildBundle("myns", node, fixedNow()); err == nil {
				t.Fatalf("buildBundle: got nil error, want an error for fwmark %s", raw)
			}
		})
	}
}

// TestBuildBundle_FwmarkUnquotedYAMLHexOctal pins what
// store.ReadNode's yamlx conversion does to an unquoted wg.yaml
// fwmark before normalizeWG ever runs: `0x..`, `0o..`, and a bare
// leading-zero `0..` all resolve to hex/octal integers, so each
// already lands on buildBundle as a JSON number.
func TestBuildBundle_FwmarkUnquotedYAMLHexOctal(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int64
	}{
		{"unquoted hex", "0xca6c", 51820},
		{"unquoted octal", "010", 8},
		{"unquoted 0o octal", "0o10", 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := testNode(t, "alpha", wgFwmark(tc.raw), "")
			b, err := buildBundle("myns", node, fixedNow())
			if err != nil {
				t.Fatalf("buildBundle: %v", err)
			}
			iface := b.WG["wg0"]
			if iface.Fwmark == nil || *iface.Fwmark != tc.want {
				t.Fatalf("iface.Fwmark = %v, want %d", iface.Fwmark, tc.want)
			}
		})
	}
}

// wgRoutingTable builds a minimal wg.yaml body with routing_table.ipv4
// set to raw (unquoted, so raw's own YAML spelling controls the type).
func wgRoutingTable(raw string) string {
	return `wg0:
  private_key: cGxhY2Vob2xkZXItcHJpdmF0ZS1rZXktMzItYnl0ZXMh
  addresses:
    - 10.0.0.1/24
  routing_table:
    ipv4: ` + raw + `
  peers:
    bravo:
      public_key: cGxhY2Vob2xkZXItcHVibGljLWtleS0zMi1ieXRlcyE=
      allowed_ips:
        - 10.0.0.2/32
`
}

// TestBuildBundle_RoutingTableIntegerNormalizes checks a YAML integer
// routing_table.ipv4 normalizes to its decimal string.
func TestBuildBundle_RoutingTableIntegerNormalizes(t *testing.T) {
	node := testNode(t, "alpha", wgRoutingTable("100"), "")
	b, err := buildBundle("myns", node, fixedNow())
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	iface := b.WG["wg0"]
	if iface.RoutingTable == nil || iface.RoutingTable.IPv4 == nil || *iface.RoutingTable.IPv4 != "100" {
		t.Fatalf("iface.RoutingTable = %+v, want ipv4 = \"100\"", iface.RoutingTable)
	}
}

// TestBuildBundle_RoutingTableStringPassesThrough checks a quoted
// routing_table.ipv4 string reaches the bundle unchanged.
func TestBuildBundle_RoutingTableStringPassesThrough(t *testing.T) {
	node := testNode(t, "alpha", wgRoutingTable(`"main"`), "")
	b, err := buildBundle("myns", node, fixedNow())
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	iface := b.WG["wg0"]
	if iface.RoutingTable == nil || iface.RoutingTable.IPv4 == nil || *iface.RoutingTable.IPv4 != "main" {
		t.Fatalf("iface.RoutingTable = %+v, want ipv4 = \"main\"", iface.RoutingTable)
	}
}

// TestBuildBundle_RoutingTableZeroRejected checks a zero
// routing_table.ipv4 fails buildBundle.
func TestBuildBundle_RoutingTableZeroRejected(t *testing.T) {
	node := testNode(t, "alpha", wgRoutingTable("0"), "")
	if _, err := buildBundle("myns", node, fixedNow()); err == nil {
		t.Fatal("buildBundle: got nil error, want an error for routing_table.ipv4 = 0")
	}
}

// TestNormalizeWG_NonObjectShapesDoNotPanic checks normalizeWG on a
// wg document that is not an object, and on an interface entry that
// is not an object: both are bundle.Parse's errors to report, so
// normalizeWG must pass them through untouched instead of panicking.
func TestNormalizeWG_NonObjectShapesDoNotPanic(t *testing.T) {
	cases := []string{
		`[]`,
		`"not an object"`,
		`{"wg0":"not an object"}`,
		`{"wg0":{}}`,
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			out, err := normalizeWG([]byte(in))
			if err != nil {
				t.Fatalf("normalizeWG(%s): %v", in, err)
			}
			if out == nil {
				t.Fatalf("normalizeWG(%s): got nil output", in)
			}
		})
	}
}

// TestNormalizeWG_LeavesOtherFieldsUnchanged checks normalizeWG does
// not disturb fields it does not normalize.
func TestNormalizeWG_LeavesOtherFieldsUnchanged(t *testing.T) {
	in := []byte(`{"wg0":{"private_key":"k","addresses":["10.0.0.1/24"],"mtu":1420,"peers":{}}}`)
	out, err := normalizeWG(in)
	if err != nil {
		t.Fatalf("normalizeWG: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	iface := got["wg0"].(map[string]any)
	if iface["mtu"].(float64) != 1420 {
		t.Fatalf("mtu = %v, want 1420", iface["mtu"])
	}
}
