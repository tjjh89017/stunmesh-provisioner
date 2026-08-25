#!/usr/bin/env bash
# phase-reboot.sh -- assertions F: reboot (stage5 checklist item 11:
# "Reboot without the proxy: the tunnel is up from UCI."; PLAN.md
# 2.6: "No boot step. UCI is persistent. The tunnel is up after a
# reboot without the proxy or the agent.").
#
# Every earlier phase proves what stunmesh-agent does when it runs.
# This phase proves the opposite claim: that the tunnel does not need
# it to run again. netifd brings up every non-disabled UCI interface
# at boot on its own; PLAN.md 2.6 says that alone is enough to bring
# wg0 back after a reboot, with no proxy reachable and no
# stunmesh-agent process involved at all. Nothing before this phase
# has rebooted the guest even once -- every other phase's "real
# netifd/uci" claim is about a *running* box.
#
# To make "no proxy and no agent run" watertight rather than a timing
# race against boot_delay (15s in this harness's /etc/config/provd),
# this phase stops the fake dhtproxy entirely before rebooting: with
# it gone, even a background boot_delay fetch (which only runs at all
# if the service was left enabled, and this harness never calls
# `enable`) or a stray cron/hotplug trigger a leftover from an earlier
# phase (defensively cleared below) cannot possibly apply anything --
# every attempt gets connection refused. Whatever wg0 state is up
# right after boot is provably UCI's alone.
#
# Sourced by run.sh, which then calls every function named phase_*.
# Uses HERE, WORK, SSH_PORT, SSH_KEY, E2E_NAMESPACE, E2E_NODE_ID,
# CONTROLLER_PUBKEY, FAKEPROXY_GUEST_URL, E2E_FAKEPROXY_PORT and
# IMAGE_PATH, all set by run.sh or lib.sh before any phase runs.
# Self-contained like every other phase (see
# run.sh's own doc comment): it establishes its own known-good wg0
# bundle before rebooting, rather than trusting whatever an earlier
# phase happened to leave behind, and restarts the fake dhtproxy
# before returning so a later phase's own publish_fixture still works.
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
	fetch_cmd="/usr/sbin/stunmesh-agent fetch --namespace ${E2E_NAMESPACE} --node-id ${E2E_NODE_ID} --controller-pubkey ${CONTROLLER_PUBKEY} --proxy ${FAKEPROXY_GUEST_URL} --identity-key /etc/stunmesh/provd/identity.key"
	assert_ssh_exit_code "a known-good bundle applies before the reboot (exit 0)" "$fetch_cmd" 0
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true
	assert_ssh_output_contains "wg0 is up before the reboot" \
		"ubus call network.interface.wg0 status" '"up": true'

	# Defensive cleanup: this phase does not know or care what an
	# earlier phase left behind (see run.sh's doc comment on phase
	# ordering), but a leftover cron line or "wan" interface would
	# undermine "no agent run" the instant the guest comes back up.
	# Every other phase already cleans up its own cron line and
	# bridge interfaces, so this is a belt-and-braces check, not a
	# dependency on it.
	guest_exec "$SSH_PORT" "$SSH_KEY" "\
		service stunmesh-agent stop >/dev/null 2>&1; \
		uci -q delete network.wan; uci -q delete network.br_wan; \
		uci -q delete network.testif; uci -q delete network.br_testif; \
		uci commit network; \
		true" \
		|| true
	assert_ssh_ok "no managed cron line survives into the reboot" \
		"! grep -q 'stunmesh-agent: managed by' /etc/crontabs/root 2>/dev/null"

	before_network_sha=$(guest_exec "$SSH_PORT" "$SSH_KEY" "sha256sum /etc/config/network")
	before_pubkey=$(guest_exec "$SSH_PORT" "$SSH_KEY" "wg show wg0 public-key")

	# No proxy reachable at all during the reboot window: see this
	# file's own top comment for why this, not just boot_delay's
	# window, is what makes "no agent run" watertight.
	stop_fake_proxy

	reboot_guest "$IMAGE_PATH" "$SSH_PORT" "$SSH_KEY" "${WORK}/boot-after-reboot.log"

	# Assert immediately: the whole point is that this is true before
	# anything could possibly have fetched, not eventually true once
	# something did.
	local after_pubkey
	after_pubkey=$(guest_exec "$SSH_PORT" "$SSH_KEY" "wg show wg0 public-key")
	assert_equal "wg0's public key survived the reboot, from UCI alone" \
		"$after_pubkey" "$before_pubkey"
	assert_ssh_output_contains "wg0 carries its peer again, from UCI alone" \
		"wg show wg0" "$REBOOT_PEER_PUBKEY"
	assert_ssh_output_contains "ubus reports wg0 up again, from UCI alone, right after boot" \
		"ubus call network.interface.wg0 status" '"up": true'

	local after_network_sha
	after_network_sha=$(guest_exec "$SSH_PORT" "$SSH_KEY" "sha256sum /etc/config/network")
	assert_equal "/etc/config/network is byte-identical across the reboot (no uci commit happened)" \
		"$after_network_sha" "$before_network_sha"

	# /tmp is tmpfs on OpenWrt: it does not survive a reboot, so the
	# stub action log this harness's stand-in writes to
	# (/tmp/stunmesh-stub-actions.log) is gone the instant the guest
	# comes back up, regardless of what ran before the reboot. That
	# makes a before/after delta meaningless here (unlike every other
	# phase's use of the same file, which never reboots in between) --
	# but it makes the post-reboot check simpler and just as strong:
	# the file's absence is direct, positive evidence that nothing
	# has called the stunmesh stand-in since boot.
	assert_ssh_ok "the stunmesh stand-in was not invoked across the reboot (no agent run)" \
		"! test -f /tmp/stunmesh-stub-actions.log"

	# Restore the fake dhtproxy for any later phase (see run.sh's doc
	# comment on phase ordering: a later phase may still need it).
	start_fake_proxy "$E2E_FAKEPROXY_PORT"
}
