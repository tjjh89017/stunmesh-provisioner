#!/usr/bin/env bash
# phase-reboot.sh -- assertions F: the tunnel is up from UCI alone
# after a reboot, with no proxy reachable and no agent process
# involved.
#
# netifd brings up every non-disabled UCI interface at boot on its
# own, with no help from stunmesh-agent.
#
# To make "no proxy and no agent run" watertight, this phase stops the
# fake dhtproxy entirely before rebooting: with it gone, even the
# daemon service (never enabled, so it would not start at boot anyway,
# but defensively stopped below) or a stray hotplug trigger left over
# from an earlier phase cannot possibly apply anything -- every attempt
# gets connection refused. Whatever wg0 state is up right after boot is
# provably UCI's alone.
#
# Sourced by run.sh, which then calls every function named phase_*.
# Uses HERE, WORK, SSH_PORT, SSH_KEY, E2E_NAMESPACE, E2E_NODE_ID,
# E2E_FAKEPROXY_PORT and IMAGE_PATH, all set by run.sh or lib.sh before
# any phase runs.
# Self-contained: publishes its own fixture.
set -euo pipefail

# render_reboot_fixture -- renders fixtures/basic-wg0/wg.yaml.tmpl (the
# same one-interface, one-peer template phase-fetch-basic.sh uses)
# with fresh WireGuard key material into a directory under $WORK. Sets
# REBOOT_FIXTURE_DIR and REBOOT_PEER_PUBKEY. See
# phase-fetch-basic.sh's render_fetch_basic_fixture for why this is
# called plainly, never through command substitution.
render_reboot_fixture() {
	local node_priv peer_pub psk rendered_dir
	read -r node_priv _ < <(generate_wg_keypair)
	read -r _ peer_pub < <(generate_wg_keypair)
	psk=$(wg genpsk) || die "wg genpsk failed."

	rendered_dir="${WORK}/fixtures-rendered/reboot"
	mkdir -p "$rendered_dir"
	sed \
		-e "s|@NODE_PRIVATE_KEY@|${node_priv}|" \
		-e "s|@PEER_PUBLIC_KEY@|${peer_pub}|" \
		-e "s|@PEER_PSK@|${psk}|" \
		"${HERE}/fixtures/basic-wg0/wg.yaml.tmpl" >"${rendered_dir}/wg.yaml" \
		|| die "Rendering fixtures/basic-wg0/wg.yaml.tmpl failed."
	cp "${HERE}/fixtures/basic-wg0/stunmesh.yaml" "${rendered_dir}/stunmesh.yaml"

	REBOOT_FIXTURE_DIR="$rendered_dir"
	REBOOT_PEER_PUBKEY="$peer_pub"
}

phase_reboot_uci_persistence() {
	local fetch_cmd before_network_sha before_pubkey

	render_reboot_fixture
	publish_fixture "$REBOOT_FIXTURE_DIR" "$E2E_NAMESPACE" "$E2E_NODE_ID"
	fetch_cmd="/usr/sbin/stunmesh-agent --oneshot"
	assert_ssh_exit_code "a known-good bundle applies before the reboot (exit 0)" "$fetch_cmd" 0
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true
	assert_ssh_output_contains "wg0 is up before the reboot" \
		"ubus call network.interface.wg0 status" '"up": true'

	# Defensive cleanup: this phase does not know or care what an
	# earlier phase left behind (see run.sh's doc comment on phase
	# ordering), but a still-running daemon service or a leftover "wan"
	# interface would undermine "no agent run" the instant the guest
	# comes back up. Every other phase already stops its own daemon
	# service and removes its own bridge interfaces, so this is a
	# belt-and-braces check, not a dependency on it. The service is
	# never enabled (this harness never calls "enable"), so it will not
	# come back on its own at boot either way.
	guest_exec "$SSH_PORT" "$SSH_KEY" "\
		/etc/init.d/stunmesh-agent stop >/dev/null 2>&1; \
		uci -q delete network.wan; uci -q delete network.br_wan; \
		uci -q delete network.testif; uci -q delete network.br_testif; \
		uci commit network; \
		true" \
		|| true
	assert_ssh_ok "no stunmesh-agent process survives into the reboot" \
		"! pgrep -x /usr/sbin/stunmesh-agent"

	# guest_capture, not a plain `var=$(guest_exec ...)`: see lib.sh's
	# guest_capture for why a failed read here must not abort the
	# harness under `set -e`.
	before_network_sha=$(guest_capture "$SSH_PORT" "$SSH_KEY" "sha256sum /etc/config/network")
	before_pubkey=$(guest_capture "$SSH_PORT" "$SSH_KEY" "wg show wg0 public-key")

	# No proxy reachable at all during the reboot window: see this
	# file's own top comment for why this is what makes "no agent run"
	# watertight.
	stop_fake_proxy

	reboot_guest "$IMAGE_PATH" "$SSH_PORT" "$SSH_KEY" "${WORK}/boot-after-reboot.log"

	# Assert immediately: the whole point is that this is true before
	# anything could possibly have fetched, not eventually true once
	# something did.
	local after_pubkey
	after_pubkey=$(guest_capture "$SSH_PORT" "$SSH_KEY" "wg show wg0 public-key")
	assert_equal "wg0's public key survived the reboot, from UCI alone" \
		"$after_pubkey" "$before_pubkey"
	assert_ssh_output_contains "wg0 carries its peer again, from UCI alone" \
		"wg show wg0" "$REBOOT_PEER_PUBKEY"
	assert_ssh_output_contains "ubus reports wg0 up again, from UCI alone, right after boot" \
		"ubus call network.interface.wg0 status" '"up": true'

	local after_network_sha
	after_network_sha=$(guest_capture "$SSH_PORT" "$SSH_KEY" "sha256sum /etc/config/network")
	assert_equal "/etc/config/network is byte-identical across the reboot (no uci commit happened)" \
		"$after_network_sha" "$before_network_sha"

	# The guest's own syslog only holds lines logged since this boot;
	# no "stunmesh-agent" line in it is direct, positive evidence that
	# no stunmesh-agent process has run since boot -- the daemon
	# service was never enabled, and nothing else on the box invokes
	# the binary.
	assert_ssh_ok "no stunmesh-agent process is running after the reboot (no agent run)" \
		"! pgrep -x /usr/sbin/stunmesh-agent"
	assert_ssh_ok "the syslog carries no stunmesh-agent line since boot (no agent run)" \
		"! logread | grep -q stunmesh-agent"

	# Restore the fake dhtproxy for any later phase (see run.sh's doc
	# comment on phase ordering: a later phase may still need it).
	start_fake_proxy "$E2E_FAKEPROXY_PORT"
}
