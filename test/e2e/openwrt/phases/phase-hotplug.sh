#!/usr/bin/env bash
# phase-hotplug.sh -- assertions D: hotplug restarts the daemon
# (contrib/openwrt/README.md section 4: hotplug-iface restarts
# stunmesh-agent on WAN ifup, only when the service is already
# running).
#
# contrib/openwrt/tests/test_hotplug.sh already covers hotplug-iface's
# own guard clauses and its read-config-and-dispatch path against a
# fake $ACTION/$INTERFACE and a fake $BIN. What is untested anywhere
# is whether netifd's real hotplug call reaches the real script: this
# phase fires real "ifup"/"ifdown" through the real `ifup`/`ifdown`
# tools, on real (if minimal) netifd interfaces, and reads the real
# syslog and process table for the restart it should, or should not,
# have triggered.
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
# comment): it starts and stops the daemon service itself, and adds
# and removes its own "wan"/"testif" UCI sections, not assuming any
# other phase already defined a "wan" interface or left the service
# running (none of the others do).
set -euo pipefail

HOTPLUG_LOG_LINE="wan up: restarting stunmesh-agent"

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

# hotplug_restart_count -- how many times hotplug-iface has logged its
# restart line since boot. guest_capture, not a plain
# `var=$(guest_exec ...)`: see lib.sh's guest_capture for why a failed
# read here must not abort the harness under `set -e` -- every caller
# below takes a before/after delta. No FALLBACK: "0" is itself a real,
# meaningful count, so a failed read must not be mistaken for one (see
# lib.sh's guest_capture comment on the same tradeoff).
hotplug_restart_count() {
	guest_capture "$SSH_PORT" "$SSH_KEY" "logread | grep -c '${HOTPLUG_LOG_LINE}' || true"
}

# assert_hotplug_delta DESC BEFORE AFTER EXPECTED -- asserts that AFTER
# minus BEFORE equals EXPECTED, unless either capture is
# hotplug_restart_count's failure sentinel, in which case it records
# DESC as a named failure instead of feeding the sentinel to `$(( ))`.
assert_hotplug_delta() {
	local desc="$1" before="$2" after="$3" expected="$4"
	if guest_capture_failed "$before" || guest_capture_failed "$after"; then
		assert_ok "$desc" \
			"echo 'could not read the hotplug restart count from the guest (before=${before}, after=${after})' >&2; false"
	else
		assert_equal "$desc" "$((after - before))" "$expected"
	fi
}

phase_hotplug_wan_ifup() {
	local before after pid_before pid_after

	add_bridge_iface wan br-wan 10.123.0.1
	add_bridge_iface testif br-testif 10.124.0.1

	assert_ssh_ok "start the daemon so a hotplug event has something to restart" \
		"/etc/init.d/stunmesh-agent start"
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 4" || true
	assert_ssh_ok "the daemon is running before any hotplug event" \
		"/etc/init.d/stunmesh-agent running"

	pid_before=$(guest_capture "$SSH_PORT" "$SSH_KEY" "pgrep -f /usr/sbin/stunmesh-agent" "")
	[[ -n "$pid_before" ]] || die "No stunmesh-agent pid before the hotplug event; cannot use it as restart evidence below."

	before=$(hotplug_restart_count)
	assert_ssh_ok "ifup wan exits 0" "ifup wan"
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 4" || true
	after=$(hotplug_restart_count)
	assert_hotplug_delta "a real 'ifup wan' event logged exactly one restart" \
		"$before" "$after" "1"
	pid_after=$(guest_capture "$SSH_PORT" "$SSH_KEY" "pgrep -f /usr/sbin/stunmesh-agent" "")
	assert_ssh_ok "'ifup wan' actually restarted the daemon (new pid)" \
		"[ '${pid_after}' != '${pid_before}' ] && [ -n '${pid_after}' ]"

	before="$after"
	pid_before="$pid_after"
	assert_ssh_ok "ifdown wan exits 0" "ifdown wan"
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 2" || true
	after=$(hotplug_restart_count)
	assert_hotplug_delta "'ifdown wan' (ACTION != ifup) logged no restart" \
		"$before" "$after" "0"
	pid_after=$(guest_capture "$SSH_PORT" "$SSH_KEY" "pgrep -f /usr/sbin/stunmesh-agent" "")
	assert_equal "'ifdown wan' did not actually restart the daemon (same pid)" \
		"$pid_after" "$pid_before"

	before="$after"
	assert_ssh_ok "ifup testif exits 0" "ifup testif"
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 2" || true
	after=$(hotplug_restart_count)
	assert_hotplug_delta "'ifup testif' (INTERFACE != wan) logged no restart" \
		"$before" "$after" "0"

	remove_bridge_iface testif
	remove_bridge_iface wan
	assert_ssh_ok "stop the daemon, leaving a clean state for later phases" \
		"/etc/init.d/stunmesh-agent stop"
}
