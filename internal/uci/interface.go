package uci

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
)

// BuildInterface builds the full UCI batch for one interface: the
// interface section, its route sections, and its peer sections
// (PLAN.md 6 "UCI layout for one interface"). name is the interface
// name: the bundle's `wg` key, which PLAN.md 6 fixes equal to the UCI
// interface section name and the netdev name.
//
// BuildInterface does not validate iface; it assumes the caller
// already ran it through bundle.Bundle.Validate (PLAN.md 4.4). It
// still degrades gracefully on unvalidated input -- see routeFamily
// for the one place that matters.
func BuildInterface(name string, iface bundle.Interface) Batch {
	var b Batch

	b = append(b, createCmd(name, "interface"))
	b = append(b, setCmd(name, "proto", "wireguard"))
	b = append(b, setCmd(name, "private_key", iface.PrivateKey))
	if iface.ListenPort != nil {
		b = append(b, setCmd(name, "listen_port", strconv.Itoa(*iface.ListenPort)))
	}
	for _, addr := range iface.Addresses {
		b = append(b, addListCmd(name, "addresses", addr))
	}
	if iface.MTU != nil {
		b = append(b, setCmd(name, "mtu", strconv.Itoa(*iface.MTU)))
	}
	b = append(b, optionCommands(name, iface.Options)...)

	for n, route := range iface.Routes {
		b = append(b, buildRoute(name, n, route)...)
	}

	routeAllowedIPs := "0"
	if iface.RouteAllowedIPsOrDefault() {
		routeAllowedIPs = "1"
	}
	for _, peerName := range sortedKeys(iface.Peers) {
		b = append(b, buildPeer(name, peerName, iface.Peers[peerName], routeAllowedIPs)...)
	}

	return b
}

// ListOptions returns every "<section>.<option>" path that
// BuildInterface(name, iface) populates through "uci add_list": the
// interface's own "addresses", and each peer's "allowed_ips". The
// peer order matches BuildInterface's (sorted by peer name, see the
// package doc "Ordering").
//
// "uci add_list" appends to a list option; it does not replace one.
// A caller that reruns BuildInterface's commands after an earlier run
// already applied them once must first clear each path ListOptions
// names, or the rerun's "add_list" calls double every entry instead
// of leaving the list as BuildInterface alone describes it. See
// fetch_apply.go's clearListOptions and applyDiff's doc comment
// "Retrying a create after a successful commit".
func ListOptions(name string, iface bundle.Interface) []string {
	options := make([]string, 0, 1+len(iface.Peers))
	options = append(options, name+".addresses")
	for _, peerName := range sortedKeys(iface.Peers) {
		options = append(options, peerSectionName(name, peerName)+".allowed_ips")
	}
	return options
}

// buildRoute builds the UCI batch for one route section,
// "<iface>_r_<n>" (PLAN.md 6 "UCI layout"). n is the route's index in
// iface.Routes, in bundle order (bundle.Interface.Routes is a slice,
// already ordered; PLAN.md 6 does not ask for any other order).
func buildRoute(iface string, n int, route bundle.Route) Batch {
	section := routeSectionName(iface, n)
	var b Batch
	b = append(b, createCmd(section, routeFamily(route.CIDR)))
	b = append(b, setCmd(section, "interface", iface))
	b = append(b, setCmd(section, "target", route.CIDR))
	if route.Gateway != nil {
		b = append(b, setCmd(section, "gateway", *route.Gateway))
	}
	if route.Metric != nil {
		b = append(b, setCmd(section, "metric", strconv.FormatInt(*route.Metric, 10)))
	}
	return b
}

// buildPeer builds the UCI batch for one peer section,
// "<iface>_p_<peer>" (PLAN.md 6 "UCI layout"). routeAllowedIPs is
// "1" or "0", already resolved by the caller from
// iface.RouteAllowedIPsOrDefault() (PLAN.md 6: "from
// wg.<iface>.route_allowed_ips" -- the interface's own setting, not a
// per-peer field).
func buildPeer(iface, peer string, p bundle.Peer, routeAllowedIPs string) Batch {
	section := peerSectionName(iface, peer)
	var b Batch
	b = append(b, createCmd(section, "wireguard_"+iface))
	b = append(b, setCmd(section, "description", peer))
	b = append(b, setCmd(section, "public_key", p.PublicKey))
	if p.PresharedKey != nil {
		b = append(b, setCmd(section, "preshared_key", *p.PresharedKey))
	}
	for _, ip := range p.AllowedIPs {
		b = append(b, addListCmd(section, "allowed_ips", ip))
	}
	if p.Endpoint != nil {
		host, port, hasPort := parseEndpoint(*p.Endpoint)
		b = append(b, setCmd(section, "endpoint_host", host))
		if hasPort {
			b = append(b, setCmd(section, "endpoint_port", port))
		}
	}
	if p.PersistentKeepalive != nil {
		b = append(b, setCmd(section, "persistent_keepalive", strconv.Itoa(*p.PersistentKeepalive)))
	}
	b = append(b, setCmd(section, "route_allowed_ips", routeAllowedIPs))
	b = append(b, optionCommands(section, p.Options)...)
	return b
}

// optionCommands returns one setCmd per entry of options, sorted by
// key (see the package doc "Ordering"). A nil map and an empty,
// non-nil map both produce no commands: an interface's or a peer's
// Options presence distinguishes bundle content (PLAN.md 4.3), but
// UCI itself has no notion of an "explicitly empty" option set, so
// the two cases have nothing to tell apart once translated to UCI
// commands.
func optionCommands(section string, options map[string]string) Batch {
	var b Batch
	for _, key := range sortedKeys(options) {
		b = append(b, setCmd(section, key, options[key]))
	}
	return b
}

// sortedKeys returns m's keys, sorted lexicographically (see the
// package doc "Ordering"). It works for both a peer map
// (map[string]bundle.Peer) and an options map (map[string]string)
// because it only reads keys, never values.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// routeSectionName returns the UCI section name for the n-th route of
// iface: "<iface>_r_<n>" (PLAN.md 6 "Rules").
func routeSectionName(iface string, n int) string {
	return iface + "_r_" + strconv.Itoa(n)
}

// peerSectionName returns the UCI section name for peer on iface:
// "<iface>_p_<peer>" (PLAN.md 6 "Rules").
func peerSectionName(iface, peer string) string {
	return iface + "_p_" + peer
}

// RouteSectionNames returns the UCI route section names that
// BuildInterface(name, routes-holding-iface) creates for routes, in
// the same order buildRoute assigns them: routes[n] names
// "<name>_r_<n>", indexed by routes' own slice order (PLAN.md 6
// "Rules"). It is the record side's read of the same naming
// buildRoute already applies on the create side, so the two can never
// drift apart: both call routeSectionName, and only routeSectionName
// knows the "<iface>_r_<n>" format.
//
// A caller records this alongside PeerSectionNames to build the
// last.Sections a later apply deletes by (see internal/last's package
// doc "Schema" and PLAN.md 6 "Rules": "The agent deletes sections by
// the exact names that last.json records").
func RouteSectionNames(name string, routes []bundle.Route) []string {
	names := make([]string, len(routes))
	for n := range routes {
		names[n] = routeSectionName(name, n)
	}
	return names
}

// PeerSectionNames returns the UCI peer section names that
// BuildInterface(name, peers-holding-iface) creates for peers, sorted
// by peer name -- the same order buildPeer creates them in (see the
// package doc "Ordering"). It is the record side's read of the same
// naming buildPeer already applies on the create side, so the two can
// never drift apart: both call peerSectionName, and only
// peerSectionName knows the "<iface>_p_<peer>" format.
//
// A caller records this alongside RouteSectionNames to build the
// last.Sections a later apply deletes by (see internal/last's package
// doc "Schema" and PLAN.md 6 "Rules": "The agent deletes sections by
// the exact names that last.json records").
func PeerSectionNames(name string, peers map[string]bundle.Peer) []string {
	names := make([]string, 0, len(peers))
	for _, peer := range sortedKeys(peers) {
		names = append(names, peerSectionName(name, peer))
	}
	return names
}

// routeFamily returns "route" for an IPv4 cidr and "route6" for an
// IPv6 one (PLAN.md 6: "route6 for IPv6"). It first tries
// net.ParseCIDR, the authoritative parse. bundle.Validate does not
// check CIDR syntax (docs/format.md 5, "out of scope"), so
// BuildInterface may see a cidr net.ParseCIDR rejects; rather than
// fail the whole batch over a string this package was never asked to
// validate, routeFamily falls back to a plain substring check: an
// IPv4 address never contains ':', an IPv6 address always does. This
// fallback only changes behavior on already-invalid input; `uci`
// itself, not this package, is the backstop that ultimately rejects a
// malformed cidr when the batch runs.
func routeFamily(cidr string) string {
	if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
		if ipnet.IP.To4() != nil {
			return "route"
		}
		return "route6"
	}
	if strings.Contains(cidr, ":") {
		return "route6"
	}
	return "route"
}
