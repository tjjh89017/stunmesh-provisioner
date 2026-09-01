package uci_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
	"github.com/tjjh89017/stunmesh-provisioner/internal/uci"
)

// update regenerates the golden files under testdata/ from the
// current BuildInterface/BuildDelete output, instead of checking
// against them. Run `go test ./internal/uci/... -update` after a
// deliberate, reviewed change to the batch this package builds.
var update = flag.Bool("update", false, "update golden files")

// checkGolden compares got against the content of testdata/name. With
// -update it writes got there instead of comparing.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden file %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file %s: %v (run with -update to create it)", path, err)
	}
	if got != string(want) {
		t.Errorf("output does not match %s\n--- got ---\n%s\n--- want ---\n%s", path, got, string(want))
	}
}

func intPtr(v int) *int       { return &v }
func int64Ptr(v int64) *int64 { return &v }
func strPtr(v string) *string { return &v }
func boolPtr(v bool) *bool    { return &v }

// TestBuildInterface_Full covers an interface with every optional
// field set: listen_port, mtu, interface options, an IPv4 and an IPv6
// route (one with a gateway and a metric, one without), and two peers
// that each set every optional peer field, including a
// preshared_key, an IPv4 endpoint with a port, and interface-level
// route_allowed_ips true.
func TestBuildInterface_Full(t *testing.T) {
	iface := bundle.Interface{
		PrivateKey:      "wg0-private-key",
		ListenPort:      intPtr(51820),
		Addresses:       []string{"10.0.0.1/24", "fd00::1/64"},
		MTU:             intPtr(1420),
		RouteAllowedIPs: boolPtr(true),
		Options: map[string]string{
			"defaultroute": "0",
			"multipath":    "off",
		},
		Routes: []bundle.Route{
			{CIDR: "10.20.0.0/16", Gateway: strPtr("10.0.0.2"), Metric: int64Ptr(100)},
			{CIDR: "fd00:20::/32"},
		},
		Peers: map[string]bundle.Peer{
			"bravo": {
				PublicKey:           "bravo-public-key",
				PresharedKey:        strPtr("bravo-preshared-key"),
				AllowedIPs:          []string{"10.0.0.2/32"},
				Endpoint:            strPtr("bravo.example.com:51820"),
				PersistentKeepalive: intPtr(25),
				Options: map[string]string{
					"note": "primary",
				},
			},
			"charlie": {
				PublicKey:    "charlie-public-key",
				PresharedKey: strPtr("charlie-preshared-key"),
				AllowedIPs:   []string{"10.0.0.3/32", "fd00::3/128"},
				Endpoint:     strPtr("[fd00::10]:51821"),
			},
		},
	}
	got := uci.BuildInterface("wg0", iface).Text()
	checkGolden(t, "interface_full.golden", got)
}

// TestBuildInterface_Minimal covers an interface with only the
// required fields set: no listen_port, no mtu, no interface options,
// no routes, and one peer with only public_key and allowed_ips.
func TestBuildInterface_Minimal(t *testing.T) {
	iface := bundle.Interface{
		PrivateKey: "wg0-private-key",
		Addresses:  []string{"10.0.0.1/24"},
		Peers: map[string]bundle.Peer{
			"bravo": {
				PublicKey:  "bravo-public-key",
				AllowedIPs: []string{"10.0.0.2/32"},
			},
		},
	}
	got := uci.BuildInterface("wg0", iface).Text()
	checkGolden(t, "interface_minimal.golden", got)
}

// TestBuildInterface_IPv6 covers an interface whose addresses and
// routes are IPv6-only, and a peer whose endpoint is a bracketed
// IPv6 literal, once with a port and once without.
func TestBuildInterface_IPv6(t *testing.T) {
	iface := bundle.Interface{
		PrivateKey: "wg0-private-key",
		Addresses:  []string{"fd00::1/64"},
		Routes: []bundle.Route{
			{CIDR: "fd00:20::/32"},
			{CIDR: "fd00:30::/32", Gateway: strPtr("fd00::2")},
		},
		Peers: map[string]bundle.Peer{
			"bravo": {
				PublicKey:  "bravo-public-key",
				AllowedIPs: []string{"fd00::2/128"},
				Endpoint:   strPtr("[fd00::2]:51820"),
			},
			"charlie": {
				PublicKey:  "charlie-public-key",
				AllowedIPs: []string{"fd00::3/128"},
				Endpoint:   strPtr("[fd00::3]"),
			},
		},
	}
	got := uci.BuildInterface("wg0", iface).Text()
	checkGolden(t, "interface_ipv6.golden", got)
}

// TestBuildInterface_MultiplePeersRoutes covers three peers and three
// routes (mixed IPv4/IPv6, with and without gateway/metric), so the
// route index and the sorted-peer-name order are both exercised past
// a single entry.
func TestBuildInterface_MultiplePeersRoutes(t *testing.T) {
	iface := bundle.Interface{
		PrivateKey: "wg0-private-key",
		Addresses:  []string{"10.0.0.1/24"},
		Routes: []bundle.Route{
			{CIDR: "10.20.0.0/16", Gateway: strPtr("10.0.0.2")},
			{CIDR: "10.30.0.0/16", Metric: int64Ptr(50)},
			{CIDR: "fd00:40::/32"},
		},
		Peers: map[string]bundle.Peer{
			"charlie": {PublicKey: "charlie-public-key", AllowedIPs: []string{"10.0.0.4/32"}},
			"alfa":    {PublicKey: "alfa-public-key", AllowedIPs: []string{"10.0.0.2/32"}},
			"bravo":   {PublicKey: "bravo-public-key", AllowedIPs: []string{"10.0.0.3/32"}},
		},
	}
	got := uci.BuildInterface("wg0", iface).Text()
	checkGolden(t, "interface_multi.golden", got)
}

// TestBuildInterface_EmptyVsNilOptions pins that a nil Options map
// and a non-nil, explicitly empty one produce byte-identical UCI
// output. bundle presence rules (PLAN.md 4.3) tell the two apart at
// the JSON level, but UCI has no notion of "an explicitly empty
// option set"; see optionCommands' doc comment.
func TestBuildInterface_EmptyVsNilOptions(t *testing.T) {
	base := bundle.Interface{
		PrivateKey: "wg0-private-key",
		Addresses:  []string{"10.0.0.1/24"},
		Peers:      map[string]bundle.Peer{},
	}

	nilOptions := base
	nilOptions.Options = nil

	emptyOptions := base
	emptyOptions.Options = map[string]string{}

	gotNil := uci.BuildInterface("wg0", nilOptions).Text()
	gotEmpty := uci.BuildInterface("wg0", emptyOptions).Text()
	if gotNil != gotEmpty {
		t.Fatalf("nil Options and empty Options produced different output:\nnil:\n%s\nempty:\n%s", gotNil, gotEmpty)
	}
	checkGolden(t, "interface_no_peers.golden", gotNil)
}

// TestBuildInterface_Determinism rebuilds the same interface, with
// several peers and option keys, many times and asserts every build
// produces byte-identical text. Peers and Options both come from Go
// maps, whose iteration order is randomized per run; this test would
// flake (or fail deterministically on a build with a different map
// seed) if BuildInterface's sorted-key rule (see the package doc
// "Ordering") were ever dropped.
func TestBuildInterface_Determinism(t *testing.T) {
	iface := bundle.Interface{
		PrivateKey: "wg0-private-key",
		Addresses:  []string{"10.0.0.1/24"},
		Options: map[string]string{
			"zzz": "1",
			"aaa": "2",
			"mmm": "3",
		},
		Peers: map[string]bundle.Peer{
			"zulu":    {PublicKey: "zulu-key", AllowedIPs: []string{"10.0.0.5/32"}},
			"alfa":    {PublicKey: "alfa-key", AllowedIPs: []string{"10.0.0.2/32"}},
			"mike":    {PublicKey: "mike-key", AllowedIPs: []string{"10.0.0.6/32"}},
			"charlie": {PublicKey: "charlie-key", AllowedIPs: []string{"10.0.0.4/32"}},
		},
	}

	want := uci.BuildInterface("wg0", iface).Text()
	for i := 0; i < 50; i++ {
		got := uci.BuildInterface("wg0", iface).Text()
		if got != want {
			t.Fatalf("run %d produced different output:\nfirst:\n%s\nthis run:\n%s", i, want, got)
		}
	}
}

// TestListOptions_InterfaceAndPeers covers an interface with several
// peers, whose map iteration order is randomized per process (see
// TestBuildInterface_Determinism), to pin that ListOptions names the
// interface's own "addresses" first, then each peer's "allowed_ips"
// sorted by peer name -- the same order BuildInterface itself uses
// (the package doc "Ordering").
func TestListOptions_InterfaceAndPeers(t *testing.T) {
	iface := bundle.Interface{
		PrivateKey: "wg0-private-key",
		Addresses:  []string{"10.0.0.1/24"},
		Peers: map[string]bundle.Peer{
			"charlie": {PublicKey: "charlie-key", AllowedIPs: []string{"10.0.0.4/32"}},
			"alfa":    {PublicKey: "alfa-key", AllowedIPs: []string{"10.0.0.2/32"}},
			"bravo":   {PublicKey: "bravo-key", AllowedIPs: []string{"10.0.0.3/32"}},
		},
	}
	got := uci.ListOptions("wg0", iface)
	want := []string{
		"wg0.addresses",
		"wg0_p_alfa.allowed_ips",
		"wg0_p_bravo.allowed_ips",
		"wg0_p_charlie.allowed_ips",
	}
	if len(got) != len(want) {
		t.Fatalf("ListOptions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ListOptions = %v, want %v", got, want)
		}
	}
}

// TestListOptions_NoPeers covers an interface with no peers: only the
// interface's own "addresses" needs clearing.
func TestListOptions_NoPeers(t *testing.T) {
	iface := bundle.Interface{
		PrivateKey: "wg0-private-key",
		Addresses:  []string{"10.0.0.1/24"},
		Peers:      map[string]bundle.Peer{},
	}
	got := uci.ListOptions("wg0", iface)
	want := []string{"wg0.addresses"}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("ListOptions = %v, want %v", got, want)
	}
}

// TestRouteSectionNames_PeerSectionNames pins the exact names
// RouteSectionNames and PeerSectionNames return for a multi-route,
// multi-peer interface, with peer map iteration randomized per
// process (see TestBuildInterface_Determinism), the same way
// TestListOptions_InterfaceAndPeers pins ListOptions.
func TestRouteSectionNames_PeerSectionNames(t *testing.T) {
	routes := []bundle.Route{
		{CIDR: "10.20.0.0/16"},
		{CIDR: "10.30.0.0/16"},
		{CIDR: "fd00:40::/32"},
	}
	peers := map[string]bundle.Peer{
		"charlie": {PublicKey: "charlie-key", AllowedIPs: []string{"10.0.0.4/32"}},
		"alfa":    {PublicKey: "alfa-key", AllowedIPs: []string{"10.0.0.2/32"}},
		"bravo":   {PublicKey: "bravo-key", AllowedIPs: []string{"10.0.0.3/32"}},
	}

	gotRoutes := uci.RouteSectionNames("wg0", routes)
	wantRoutes := []string{"wg0_r_0", "wg0_r_1", "wg0_r_2"}
	if len(gotRoutes) != len(wantRoutes) {
		t.Fatalf("RouteSectionNames = %v, want %v", gotRoutes, wantRoutes)
	}
	for i := range wantRoutes {
		if gotRoutes[i] != wantRoutes[i] {
			t.Fatalf("RouteSectionNames = %v, want %v", gotRoutes, wantRoutes)
		}
	}

	gotPeers := uci.PeerSectionNames("wg0", peers)
	wantPeers := []string{"wg0_p_alfa", "wg0_p_bravo", "wg0_p_charlie"}
	if len(gotPeers) != len(wantPeers) {
		t.Fatalf("PeerSectionNames = %v, want %v", gotPeers, wantPeers)
	}
	for i := range wantPeers {
		if gotPeers[i] != wantPeers[i] {
			t.Fatalf("PeerSectionNames = %v, want %v", gotPeers, wantPeers)
		}
	}
}

// TestRouteSectionNames_PeerSectionNames_MatchBuildInterface pins that
// RouteSectionNames and PeerSectionNames name exactly the route and
// peer sections BuildInterface's own batch creates -- not merely
// names that look right in isolation. It parses the section names out
// of BuildInterface's create commands ("uci set network.<section>=
// <type>", the only Command form with no "." between "network." and
// "=") and compares them against RouteSectionNames/PeerSectionNames,
// in creation order. Since sectionsFor (cmd/stunmesh-agent) builds
// last.Sections from these same two functions, this test is also the
// guarantee that the create side and the record side cannot drift:
// both read the identical section names from the identical call.
func TestRouteSectionNames_PeerSectionNames_MatchBuildInterface(t *testing.T) {
	iface := bundle.Interface{
		PrivateKey: "wg0-private-key",
		Addresses:  []string{"10.0.0.1/24"},
		Routes: []bundle.Route{
			{CIDR: "10.20.0.0/16", Gateway: strPtr("10.0.0.2")},
			{CIDR: "10.30.0.0/16", Metric: int64Ptr(50)},
			{CIDR: "fd00:40::/32"},
		},
		Peers: map[string]bundle.Peer{
			"charlie": {PublicKey: "charlie-public-key", AllowedIPs: []string{"10.0.0.4/32"}},
			"alfa":    {PublicKey: "alfa-public-key", AllowedIPs: []string{"10.0.0.2/32"}},
			"bravo":   {PublicKey: "bravo-public-key", AllowedIPs: []string{"10.0.0.3/32"}},
		},
	}

	batch := uci.BuildInterface("wg0", iface)
	gotRoutes, gotPeers := createdSectionNames(batch, len(iface.Routes))

	wantRoutes := uci.RouteSectionNames("wg0", iface.Routes)
	wantPeers := uci.PeerSectionNames("wg0", iface.Peers)

	if !equalStrings(gotRoutes, wantRoutes) {
		t.Fatalf("route sections created = %v, RouteSectionNames = %v", gotRoutes, wantRoutes)
	}
	if !equalStrings(gotPeers, wantPeers) {
		t.Fatalf("peer sections created = %v, PeerSectionNames = %v", gotPeers, wantPeers)
	}
}

// createdSectionNames extracts, in order, the route and peer section
// names that batch's "uci set network.<section>=<type>" create
// commands name, skipping the leading interface-section create.
// wantRouteCount tells it how many of the create commands after the
// interface are routes (the rest are peers); BuildInterface always
// emits all route creates before any peer create (package doc
// "Ordering"). It ignores every other command (option sets, add_list
// calls): those share the "network.<section>.<option>=<value>" form,
// which always has a "." before the "=", so a create command --
// "network.<section>=<type>", with no such "." -- is unambiguous.
func createdSectionNames(batch uci.Batch, wantRouteCount int) (routes, peers []string) {
	first := true
	for _, cmd := range batch {
		if len(cmd.Args) != 2 || cmd.Args[0] != "set" {
			continue
		}
		body := strings.TrimPrefix(cmd.Args[1], "network.")
		eq := strings.Index(body, "=")
		if eq < 0 || strings.Contains(body[:eq], ".") {
			continue // an option set or add_list, not a section create.
		}
		section := body[:eq]
		if first {
			first = false
			continue // the interface section itself, not a route or peer.
		}
		if len(routes) < wantRouteCount {
			routes = append(routes, section)
		} else {
			peers = append(peers, section)
		}
	}
	return routes, peers
}

// TestBuildFirewallZoneCreate pins the exact batch that creates the
// shared "stunmesh" firewall zone (PLAN.md 6 "Firewall zone"): the
// zone section itself, plus its name/input/output/forward options.
func TestBuildFirewallZoneCreate(t *testing.T) {
	got := uci.BuildFirewallZoneCreate().Text()
	checkGolden(t, "firewall_zone_create.golden", got)
}

// TestAddRemoveFirewallZoneNetwork pins the exact Command each of
// AddFirewallZoneNetwork and RemoveFirewallZoneNetwork builds for one
// interface name, and TestDeleteFirewallZone pins the Command that
// deletes the whole zone section.
func TestAddRemoveFirewallZoneNetwork(t *testing.T) {
	add := uci.AddFirewallZoneNetwork("wg0")
	wantAdd := []string{"add_list", "firewall.stunmesh.network=wg0"}
	if !equalStrings(add.Args, wantAdd) {
		t.Errorf("AddFirewallZoneNetwork(\"wg0\").Args = %v, want %v", add.Args, wantAdd)
	}

	remove := uci.RemoveFirewallZoneNetwork("wg0")
	wantRemove := []string{"del_list", "firewall.stunmesh.network=wg0"}
	if !equalStrings(remove.Args, wantRemove) {
		t.Errorf("RemoveFirewallZoneNetwork(\"wg0\").Args = %v, want %v", remove.Args, wantRemove)
	}
}

func TestDeleteFirewallZone(t *testing.T) {
	del := uci.DeleteFirewallZone()
	want := []string{"delete", "firewall.stunmesh"}
	if !equalStrings(del.Args, want) {
		t.Errorf("DeleteFirewallZone().Args = %v, want %v", del.Args, want)
	}
}

// TestBuildFirewallForwardingsCreate pins the exact batch that creates
// the three default forwarding sections (PLAN.md 6 "Firewall zone"):
// lan->stunmesh, stunmesh->lan, and stunmesh->wan. It also pins, by
// omission, that BuildFirewallZoneCreate's own golden file
// (TestBuildFirewallZoneCreate) never sets `option masq`: the zone
// batch and this batch are disjoint, and neither one names "masq"
// anywhere in either golden file.
func TestBuildFirewallForwardingsCreate(t *testing.T) {
	got := uci.BuildFirewallForwardingsCreate().Text()
	checkGolden(t, "firewall_forwardings_create.golden", got)
}

func TestDeleteFirewallForwardings(t *testing.T) {
	got := uci.DeleteFirewallForwardings().Text()
	checkGolden(t, "firewall_forwardings_delete.golden", got)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestBuildDelete_Full covers an interface with an interface section,
// route sections, and peer sections all recorded.
func TestBuildDelete_Full(t *testing.T) {
	sections := last.Sections{
		Interface: "wg0",
		Routes:    []string{"wg0_r_0", "wg0_r_1"},
		Peers:     []string{"wg0_p_bravo", "wg0_p_charlie"},
	}
	got := uci.BuildDelete(sections).Text()
	checkGolden(t, "delete_full.golden", got)
}

// TestBuildDelete_InterfaceOnly covers an interface recorded with no
// route sections and no peer sections.
func TestBuildDelete_InterfaceOnly(t *testing.T) {
	sections := last.Sections{Interface: "wg0"}
	got := uci.BuildDelete(sections).Text()
	checkGolden(t, "delete_interface_only.golden", got)
}

// TestBuildDelete_ExactNamesNotPattern pins PLAN.md 6's "Rules": the
// delete batch names only the sections last.json recorded, never a
// derived or guessed name. A section recorded under a name that does
// not follow the "<iface>_p_<peer>" / "<iface>_r_<n>" convention (for
// example, left over from a future format change) is still deleted
// by that exact recorded name, and no other section is touched.
func TestBuildDelete_ExactNamesNotPattern(t *testing.T) {
	sections := last.Sections{
		Interface: "wg0",
		Routes:    []string{"wg0_r_0"},
		Peers:     []string{"wg0_p_bravo", "some_other_recorded_name"},
	}
	got := uci.BuildDelete(sections)

	wantArgs := [][]string{
		{"delete", "network.wg0_p_bravo"},
		{"delete", "network.some_other_recorded_name"},
		{"delete", "network.wg0_r_0"},
		{"delete", "network.wg0"},
	}
	if len(got) != len(wantArgs) {
		t.Fatalf("got %d commands, want %d: %+v", len(got), len(wantArgs), got)
	}
	for i, cmd := range got {
		if len(cmd.Args) != len(wantArgs[i]) {
			t.Fatalf("command %d: got %v, want %v", i, cmd.Args, wantArgs[i])
		}
		for j, a := range cmd.Args {
			if a != wantArgs[i][j] {
				t.Fatalf("command %d arg %d: got %q, want %q", i, j, a, wantArgs[i][j])
			}
		}
	}
}
