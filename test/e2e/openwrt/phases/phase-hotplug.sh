#!/usr/bin/env bash
# phase-hotplug.sh -- assertions D: hotplug (stage5 checklist item
# 12's "hotplug runs fetch on WAN ifup"; contrib/openwrt/README.md
# section 4).
#
# contrib/openwrt/tests/test_hotplug.sh already covers hotplug-iface's
# own guard clauses and its read-config-and-dispatch path against a
# fake $ACTION/$INTERFACE and a fake $BIN. What is untested anywhere
# is whether netifd's real hotplug call reaches the real script: this
# phase fires real "ifup"/"ifdown" through the real `ifup`/`ifdown`
# tools, on real (if minimal) netifd interfaces, and reads the real
# syslog for the fetch it should, or should not, have triggered.
#
# Firing real events, not calling /etc/hotplug.d/iface/95-stunmesh-agent
# by hand with fabricated $ACTION/$INTERFACE, is deliberate: a
# hand-called script proves the script's own logic (already covered by
# test_hotplug.sh); only a real ifup/ifdown proves netifd's hotplug
# call actually reaches it, with the environment netifd itself sets.
#
# The guest's only interface with a real NIC is "lan" (eth0, the SSH
# path this whole harness runs over) -- bringing it down to test
# "ifdown" would cut the SSH connection this phase runs over. Two
# bridge devices with no member ports ("option bridge_empty '1'") give
# netifd a real "wan" and a real "testif" logical interface it can
# bring up and down on request, hotplug included, without touching any
# real hardware or this phase's own SSH connection.
#
# Sourced by run.sh, which then calls every function named phase_*.
# Uses SSH_PORT and SSH_KEY, set by run.sh before any phase runs.
# Self-contained like every other phase (see run.sh's own doc
# comment): it adds and removes its own "wan"/"testif" UCI sections
# and does not assume any other phase already defined a "wan"
# interface (none of the others do).
set -euo pipefail

# add_bridge_iface NAME DEVICE ADDR -- defines a UCI interface NAME on
# a bridge device DEVICE with no member ports, at static address ADDR.
# An empty bridge still gets a real kernel netdev (bridge_empty '1'),
# so ifup/ifdown genuinely bring the logical interface up and down --
# and so genuinely fire hotplug -- without any physical NIC behind it.
add_bridge_iface() {
	local name="$1" device="$2" addr="$3"
	guest_exec "$SSH_PORT" "$SSH_KEY" "\
		uci set network.br_${name}=device; \
		uci set network.br_${name}.type='bridge'; \
		uci set network.br_${name}.name='${device}'; \
		uci set network.br_${name}.bridge_empty='1'; \
		uci set network.${name}=interface; \
		uci set network.${name}.device='${device}'; \
		uci set network.${name}.proto='static'; \
		uci set network.${name}.ipaddr='${addr}'; \
		uci set network.${name}.netmask='255.255.255.0'; \
		uci commit network" \
		|| die "Could not define the ${name} bridge interface."
}

# remove_bridge_iface NAME -- undoes add_bridge_iface, so this phase
# leaves no interface behind for a later phase (or the reboot phase,
# which must not have any interface come up automatically at boot and
# fire a hotplug event of its own).
remove_bridge_iface() {
	local name="$1"
	guest_exec "$SSH_PORT" "$SSH_KEY" "\
		ifdown ${name} 2>/dev/null; \
		uci -q delete network.${name}; \
		uci -q delete network.br_${name}; \
		uci commit network" \
		|| die "Could not remove the ${name} bridge interface."
}

# hotplug_fetch_count -- the number of hotplug-iface log lines that
# report a real fetch outcome (applied / no change / failed).
# hotplug-iface (contrib/openwrt/hotplug-iface) also logs two guard-
# clause lines that contain the plain substring "hotplug fetch"
# ("...; skipping hotplug fetch", when /etc/config/provd is missing or
# incomplete) without ever having run fetch at all. A plain substring
# grep for "hotplug fetch" would count those too, so this matches only
# the three lines that follow a real invocation: "hotplug fetch
# applied", "hotplug fetch: no change" and "hotplug fetch failed, exit
# code N". The guard-clause lines end in "hotplug fetch" with nothing
# after it, so none of the three patterns below can match them.
#
# guest_capture, not a plain `var=$(guest_exec ...)`: see lib.sh's
# guest_capture for why a failed read here must not abort the harness
# under `set -e` -- every caller below takes a before/after delta of
# this count, the same pattern the guard exists for. The remote `||
# true` stays: it absorbs grep's own "no match" exit so its real count
# reaches the caller unchanged. FALLBACK "0" covers guest_exec itself
# failing, with a real value the callers' arithmetic can still use.
hotplug_fetch_count() {
	guest_capture "$SSH_PORT" "$SSH_KEY" "logread | grep -cE 'hotplug fetch(: | applied| failed)' || true" 0
}

phase_hotplug_wan_ifup() {
	local before after

	add_bridge_iface wan br-wan 10.123.0.1
	add_bridge_iface testif br-testif 10.124.0.1

	before=$(hotplug_fetch_count)
	assert_ssh_ok "ifup wan exits 0" "ifup wan"
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true
	after=$(hotplug_fetch_count)
	assert_equal "a real 'ifup wan' event ran exactly one hotplug fetch" \
		"$((after - before))" "1"

	before="$after"
	assert_ssh_ok "ifdown wan exits 0" "ifdown wan"
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 2" || true
	after=$(hotplug_fetch_count)
	assert_equal "'ifdown wan' (ACTION != ifup) ran no hotplug fetch" \
		"$((after - before))" "0"

	before="$after"
	assert_ssh_ok "ifup testif exits 0" "ifup testif"
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 2" || true
	after=$(hotplug_fetch_count)
	assert_equal "'ifup testif' (INTERFACE != wan) ran no hotplug fetch" \
		"$((after - before))" "0"

	remove_bridge_iface testif
	remove_bridge_iface wan
}
