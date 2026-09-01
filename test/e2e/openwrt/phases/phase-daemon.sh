#!/usr/bin/env bash
# phase-daemon.sh -- assertions D: the procd daemon service
# (contrib/openwrt/README.md section 1: stunmesh-agent.init is a
# procd-supervised daemon, not a cron-driven one-shot command).
#
# Every other phase drives the agent through a direct `--oneshot`
# invocation. This phase is the one that runs it the way a real router
# does: through /etc/init.d/stunmesh-agent, letting the init script
# (re)generate config.yaml from UCI and hand the process to procd.
#
# Sourced by run.sh, which then calls every function named phase_*.
# Uses HERE, WORK, SSH_PORT, SSH_KEY, E2E_NAMESPACE and E2E_NODE_ID,
# all set by run.sh or lib.sh before any phase runs. Self-contained
# like every other phase (see run.sh's own doc comment): it publishes
# its own fixture and always stops the service before returning, so a
# later phase's own `--oneshot` never contends with a daemon this
# phase left running.
set -euo pipefail

# render_daemon_fixture -- renders fixtures/basic-wg0/wg.yaml.tmpl (the
# same one-interface, one-peer template phase-fetch-basic.sh uses) with
# fresh WireGuard key material. Sets DAEMON_FIXTURE_DIR and
# DAEMON_PEER_PUBKEY. See phase-fetch-basic.sh's
# render_fetch_basic_fixture for why this is called plainly, never
# through command substitution.
render_daemon_fixture() {
	local node_priv peer_pub psk rendered_dir
	read -r node_priv _ < <(generate_wg_keypair)
	read -r _ peer_pub < <(generate_wg_keypair)
	psk=$(wg genpsk) || die "wg genpsk failed."

	rendered_dir="${WORK}/fixtures-rendered/daemon"
	mkdir -p "$rendered_dir"
	sed \
		-e "s|@NODE_PRIVATE_KEY@|${node_priv}|" \
		-e "s|@PEER_PUBLIC_KEY@|${peer_pub}|" \
		-e "s|@PEER_PSK@|${psk}|" \
		"${HERE}/fixtures/basic-wg0/wg.yaml.tmpl" >"${rendered_dir}/wg.yaml" \
		|| die "Rendering fixtures/basic-wg0/wg.yaml.tmpl failed."
	cp "${HERE}/fixtures/basic-wg0/stunmesh.yaml" "${rendered_dir}/stunmesh.yaml"

	DAEMON_FIXTURE_DIR="$rendered_dir"
	DAEMON_PEER_PUBKEY="$peer_pub"
}

phase_daemon() {
	local pid_after_start pid_after_reload

	render_daemon_fixture
	publish_fixture "$DAEMON_FIXTURE_DIR" "$E2E_NAMESPACE" "$E2E_NODE_ID"

	# "-x" (match by process name), not "-f" (match by full command
	# line): "-f /usr/sbin/stunmesh-agent" self-matches the very ssh
	# "sh -c '...pgrep -f /usr/sbin/stunmesh-agent...'" invocation
	# running the check, since that shell's own cmdline contains the
	# pattern as a substring. That false match makes every one of
	# these checks fail unconditionally, whether or not the daemon is
	# actually running.
	assert_ssh_ok "no stunmesh-agent process is running before the test" \
		"! pgrep -x stunmesh-agent"

	assert_ssh_ok "/etc/init.d/stunmesh-agent start exits 0" \
		"/etc/init.d/stunmesh-agent start"
	# start_service hands the process to procd, which forks it; the
	# daemon's own first cycle (fetch, decrypt, apply) then needs a
	# moment to reach the kernel. wait_for_pgrep polls for the pid
	# instead of sleeping a fixed amount and reading once, since procd
	# gives no fixed deadline for "forked and past its first cycle"
	# (lib.sh's wait_for_pgrep doc comment).
	pid_after_start=$(wait_for_pgrep "$SSH_PORT" "$SSH_KEY" "stunmesh-agent")

	assert_ssh_ok "procd reports the service running" \
		"/etc/init.d/stunmesh-agent running"

	# config.yaml was regenerated from UCI, not just left over from
	# run.sh's own direct injection (lib.sh's inject_guest_files writes
	# both, with the same values, precisely so this phase cannot pass
	# by accident against the wrong file's content).
	assert_ssh_output_contains "regenerated config.yaml carries the UCI namespace" \
		"cat /etc/stunmesh/agent/config.yaml" "$E2E_NAMESPACE"
	assert_ssh_output_contains "config.yaml is mode 0600 after regeneration" \
		"ls -l /etc/stunmesh/agent/config.yaml" "-rw-------"

	# The daemon's own first cycle applied the published fixture, the
	# same way phase-fetch-basic.sh's direct `--oneshot` does.
	assert_ssh_output_contains "the daemon's first cycle brought wg0's peer up" \
		"wg show wg0" "$DAEMON_PEER_PUBKEY"

	assert_ssh_ok "/etc/init.d/stunmesh-agent reload exits 0" \
		"/etc/init.d/stunmesh-agent reload"
	pid_after_reload=$(wait_for_pgrep "$SSH_PORT" "$SSH_KEY" "stunmesh-agent" 10 1 "$pid_after_start")
	assert_ssh_ok "procd reports the service running after reload" \
		"/etc/init.d/stunmesh-agent running"
	assert_ssh_ok "reload restarted the daemon (new pid)" \
		"[ '${pid_after_reload}' != '${pid_after_start}' ] && [ -n '${pid_after_reload}' ]"

	assert_ssh_ok "/etc/init.d/stunmesh-agent stop exits 0" \
		"/etc/init.d/stunmesh-agent stop"
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 1" || true
	assert_ssh_ok "no stunmesh-agent process is running after stop" \
		"! pgrep -x stunmesh-agent"
}
