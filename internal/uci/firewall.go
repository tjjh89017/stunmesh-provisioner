package uci

// FirewallZoneName is the UCI section name for the firewall zone the
// agent creates for every stunmesh-managed WireGuard interface
// (PLAN.md 6 "Firewall zone"). Unlike an interface's own network
// sections (one set per interface, named from the interface itself),
// there is exactly one zone, shared by every managed interface.
const FirewallZoneName = "stunmesh"

// firewallZoneNetworkOption is the UCI option that holds the zone's
// member interfaces: "firewall.stunmesh.network", a list option with
// one entry per managed interface (PLAN.md 6 "Firewall zone").
const firewallZoneNetworkOption = "network"

// BuildFirewallZoneCreate returns the batch that creates the
// "stunmesh" firewall zone with an accept-everything policy (PLAN.md
// 6 "Firewall zone"): `option name 'stunmesh'`, input, output, and
// forward all `ACCEPT`, and `mss_clamp '1'`. It does not add any
// network member; the caller adds each managed interface separately
// with AddFirewallZoneNetwork.
//
// mss_clamp is on because a WireGuard tunnel's MTU is smaller than a
// normal Ethernet link's, and a peer that skips the clamp can send a
// TCP segment that comes back as an ICMP "fragmentation needed" the
// path silently drops instead of honouring (PLAN.md 6 "Firewall
// zone").
//
// It deliberately never sets `option masq`: fw4 defaults a zone's
// masq to off when the option is absent, and this batch relies on
// that default rather than setting `masq '0'` explicitly, so there is
// nothing here to accidentally flip. No NAT happens between "lan" and
// "stunmesh" in either direction -- every packet crossing the zone
// keeps its real source address, and end-to-end routing depends on
// the WireGuard allowed-ips/routes the bundle already provisions, not
// on address translation. Egress from "stunmesh" to the internet
// still gets NAT, but from the "wan" zone's own masq setting (PLAN.md
// 6 "Firewall zone" -- see BuildFirewallForwardingsCreate's "stunmesh"
// -> "wan" forwarding): that setting belongs to "wan", which this
// package never touches.
//
// The caller runs this only once, before the zone has ever been
// created (or after it -- see AddFirewallZoneNetwork/
// RemoveFirewallZoneNetwork's own doc comments -- but never onto a
// zone the agent did not create itself; see cmd/stunmesh-agent's
// fetch_apply.go for the ownership check that decides that).
func BuildFirewallZoneCreate() Batch {
	var b Batch
	b = append(b, createCmd("firewall", FirewallZoneName, "zone"))
	b = append(b, setCmd("firewall", FirewallZoneName, "name", FirewallZoneName))
	b = append(b, setCmd("firewall", FirewallZoneName, "input", "ACCEPT"))
	b = append(b, setCmd("firewall", FirewallZoneName, "output", "ACCEPT"))
	b = append(b, setCmd("firewall", FirewallZoneName, "forward", "ACCEPT"))
	b = append(b, setCmd("firewall", FirewallZoneName, "mss_clamp", "1"))
	return b
}

// Named UCI sections for the three `config forwarding` sections the
// agent creates alongside the "stunmesh" zone (PLAN.md 6 "Firewall
// zone"). Each name is fixed and descriptive of its own src/dest pair,
// so BuildDelete-style deletion by exact recorded name (PLAN.md 6
// "Rules") never has to guess: last.json records these same three
// names verbatim (see cmd/stunmesh-agent's last.FirewallState).
const (
	// ForwardingLANToZoneName is `option src 'lan'`, `option dest
	// 'stunmesh'`: the router's LAN can reach every mesh peer.
	ForwardingLANToZoneName = "stunmesh_fwd_lan_stunmesh"
	// ForwardingZoneToLANName is `option src 'stunmesh'`, `option dest
	// 'lan'`: every mesh peer can reach the router's LAN. Combined with
	// BuildFirewallZoneCreate never setting `masq`, traffic in both
	// directions between "lan" and "stunmesh" keeps real source
	// addresses -- see BuildFirewallZoneCreate's doc comment.
	ForwardingZoneToLANName = "stunmesh_fwd_stunmesh_lan"
	// ForwardingZoneToWANName is `option src 'stunmesh'`, `option dest
	// 'wan'`: a mesh peer's traffic can egress through this node's own
	// internet connection. Unlike the lan<->stunmesh pair, this
	// direction is NATed -- by "wan"'s own masq setting, the normal
	// OpenWrt default for a wan zone, not by anything this package
	// sets (BuildFirewallZoneCreate's doc comment).
	ForwardingZoneToWANName = "stunmesh_fwd_stunmesh_wan"
)

// BuildFirewallForwardingsCreate returns the batch that creates the
// three `config forwarding` sections every "stunmesh" zone gets by
// default (PLAN.md 6 "Firewall zone"): lan->stunmesh, stunmesh->lan,
// and stunmesh->wan (see the ForwardingLANToZoneName /
// ForwardingZoneToLANName / ForwardingZoneToWANName doc comments for
// what each direction means). This assumes the standard OpenWrt "lan"
// and "wan" firewall zones exist, the default on every stock image;
// if either does not, the corresponding forwarding sections are
// inert (fw4 simply has nothing matching that zone name to forward
// to or from) rather than an error -- this package does not detect or
// special-case a missing "lan"/"wan" zone.
//
// The caller runs this immediately after BuildFirewallZoneCreate's
// batch, only when creating the zone for the first time; their
// lifecycle is tied together (see DeleteFirewallForwardings).
func BuildFirewallForwardingsCreate() Batch {
	var b Batch
	b = append(b, createCmd("firewall", ForwardingLANToZoneName, "forwarding"))
	b = append(b, setCmd("firewall", ForwardingLANToZoneName, "src", "lan"))
	b = append(b, setCmd("firewall", ForwardingLANToZoneName, "dest", FirewallZoneName))
	b = append(b, createCmd("firewall", ForwardingZoneToLANName, "forwarding"))
	b = append(b, setCmd("firewall", ForwardingZoneToLANName, "src", FirewallZoneName))
	b = append(b, setCmd("firewall", ForwardingZoneToLANName, "dest", "lan"))
	b = append(b, createCmd("firewall", ForwardingZoneToWANName, "forwarding"))
	b = append(b, setCmd("firewall", ForwardingZoneToWANName, "src", FirewallZoneName))
	b = append(b, setCmd("firewall", ForwardingZoneToWANName, "dest", "wan"))
	return b
}

// DeleteFirewallForwardings returns the batch that deletes all three
// forwarding sections BuildFirewallForwardingsCreate creates, each by
// its own exact, fixed name (PLAN.md 6 "Rules"). The caller runs this
// alongside DeleteFirewallZone, only when the agent owns the zone and
// the last managed interface has just been removed: the three
// forwardings share the zone's lifecycle exactly, never created or
// deleted independently of it.
func DeleteFirewallForwardings() Batch {
	var b Batch
	b = append(b, deleteCmd("firewall", ForwardingLANToZoneName))
	b = append(b, deleteCmd("firewall", ForwardingZoneToLANName))
	b = append(b, deleteCmd("firewall", ForwardingZoneToWANName))
	return b
}

// AddFirewallZoneNetwork returns the command that adds iface to the
// "stunmesh" zone's network list: "uci add_list
// firewall.stunmesh.network=<iface>" (PLAN.md 6 "Firewall zone").
func AddFirewallZoneNetwork(iface string) Command {
	return addListCmd("firewall", FirewallZoneName, firewallZoneNetworkOption, iface)
}

// RemoveFirewallZoneNetwork returns the command that removes iface
// from the "stunmesh" zone's network list: "uci del_list
// firewall.stunmesh.network=<iface>". del_list removes only the
// named value; every other member, and the zone section itself, is
// left untouched (PLAN.md 6 "Rules": delete by the exact recorded
// name, never by pattern -- here, one exact list value).
func RemoveFirewallZoneNetwork(iface string) Command {
	return delListCmd("firewall", FirewallZoneName, firewallZoneNetworkOption, iface)
}

// DeleteFirewallZone returns the command that deletes the "stunmesh"
// zone section entirely: "uci delete firewall.stunmesh". The caller
// uses this when the last managed interface is removed and the agent
// owns the zone (PLAN.md 6 "Firewall zone"): removing the whole
// section the agent itself created is the same "delete by exact
// recorded name" rule BuildDelete already follows for a removed
// interface's network sections.
func DeleteFirewallZone() Command {
	return deleteCmd("firewall", FirewallZoneName)
}
