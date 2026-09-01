#!/usr/bin/env bash
# phase-daemon.sh -- assertions D: the procd daemon service
# (contrib/openwrt/README.md section 1). Every other phase drives the
# agent via a direct `--oneshot`; this one goes through
# /etc/init.d/stunmesh-agent, the real UCI-to-config.yaml and procd
# path.
#
# Sourced by run.sh. Uses HERE, WORK, SSH_PORT, SSH_KEY,
# E2E_NAMESPACE, E2E_NODE_ID. Self-contained: publishes its own
# fixture and always stops the service before returning, so it never
# leaves a daemon running for a later phase's `--oneshot` to contend
# with.
set -euo pipefail

# render_daemon_fixture -- renders fixtures/basic-wg0/wg.yaml.tmpl with
# fresh WireGuard key material. Sets DAEMON_FIXTURE_DIR and
# DAEMON_PEER_PUBKEY. Called plainly, not via command substitution, so
# a rendering failure's `die` still aborts the run (see
# phase-fetch-basic.sh's render_fetch_basic_fixture).
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

	# "-x" against the full path, not the short name: this guest's
	# BusyBox pgrep -x matches argv[0] exactly as invoked (procd always
	# launches by full path), not the kernel `comm` field GNU pgrep -x
	# uses (see lib.sh's wait_for_pgrep). "-f" is avoided because it
	# self-matches the ssh command running the check.
	assert_ssh_ok "no stunmesh-agent process is running before the test" \
		"! pgrep -x /usr/sbin/stunmesh-agent"

	assert_ssh_ok "/etc/init.d/stunmesh-agent start exits 0" \
		"/etc/init.d/stunmesh-agent start"
	# procd forks the instance asynchronously; poll instead of a fixed
	# sleep (lib.sh's wait_for_pgrep).
	pid_after_start=$(wait_for_pgrep "$SSH_PORT" "$SSH_KEY" "/usr/sbin/stunmesh-agent")

	assert_ssh_ok "procd reports the service running" \
		"/etc/init.d/stunmesh-agent running"

	# Proves config.yaml was regenerated from UCI, not just left over
	# from run.sh's own direct injection (same values either way).
	assert_ssh_output_contains "regenerated config.yaml carries the UCI namespace" \
		"cat /etc/stunmesh/agent/config.yaml" "$E2E_NAMESPACE"
	assert_ssh_output_contains "config.yaml is mode 0600 after regeneration" \
		"ls -l /etc/stunmesh/agent/config.yaml" "-rw-------"

	assert_ssh_output_contains "the daemon's first cycle brought wg0's peer up" \
		"wg show wg0" "$DAEMON_PEER_PUBKEY"

	assert_ssh_ok "/etc/init.d/stunmesh-agent reload exits 0" \
		"/etc/init.d/stunmesh-agent reload"
	pid_after_reload=$(wait_for_pgrep "$SSH_PORT" "$SSH_KEY" "/usr/sbin/stunmesh-agent" 10 1 "$pid_after_start")
	assert_ssh_ok "procd reports the service running after reload" \
		"/etc/init.d/stunmesh-agent running"
	assert_ssh_ok "reload restarted the daemon (new pid)" \
		"[ '${pid_after_reload}' != '${pid_after_start}' ] && [ -n '${pid_after_reload}' ]"

	assert_ssh_ok "/etc/init.d/stunmesh-agent stop exits 0" \
		"/etc/init.d/stunmesh-agent stop"
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 1" || true
	assert_ssh_ok "no stunmesh-agent process is running after stop" \
		"! pgrep -x /usr/sbin/stunmesh-agent"
}
