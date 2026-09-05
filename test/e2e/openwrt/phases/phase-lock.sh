#!/usr/bin/env bash
# phase-lock.sh -- assertions D: the lock prevents overlap.
#
# Two real `stunmesh-agent --oneshot` processes, in the guest, contend
# for the same flock(2) at the same time. This phase starts a second,
# dedicated fakeproxy instance (lib.sh's start_delayed_fake_proxy) that
# delays every GET by lockGetDelay, publishes one bundle to it, and
# points both racing runs at it with an explicit --config flag naming
# a config.yaml pointed at the delayed proxy.
#
# Sourced by run.sh, which then calls every function named phase_*.
# Uses HERE, WORK, SSH_PORT, SSH_KEY, E2E_NAMESPACE, E2E_NODE_ID,
# FAKEPROXY_HOST_URL and FAKEPROXY_BIN, all set by run.sh or lib.sh
# before any phase runs.
# Self-contained: publishes its own fixture.
set -euo pipefail

# lockGetDelay must comfortably exceed the stagger between launching
# the two racing runs (1s, in phase_lock_overlap) so the second
# one always starts while the first still holds the lock, and must
# stay comfortably under fetch.go's fetchTimeout (30s) so the
# winner's own GET does not time out waiting on itself.
LOCK_GET_DELAY="3s"
LOCK_FAKEPROXY_PORT="${E2E_LOCK_FAKEPROXY_PORT:-8788}"

# render_lock_fixture -- renders fixtures/lock/wg.yaml.tmpl with fresh
# WireGuard key material into a directory under $WORK. Sets
# LOCK_FIXTURE_DIR and LOCK_PEER_PUBKEY (the peer public key later
# assertions check the winner actually applied). Called plainly, never
# through command substitution, so the variables it sets stay visible
# to the caller.
render_lock_fixture() {
	local node_priv peer_pub rendered_dir
	read -r node_priv _ < <(generate_wg_keypair)
	read -r _ peer_pub < <(generate_wg_keypair)

	rendered_dir="${WORK}/fixtures-rendered/lock"
	mkdir -p "$rendered_dir"
	sed \
		-e "s|@NODE_PRIVATE_KEY@|${node_priv}|" \
		-e "s|@PEER_PUBLIC_KEY@|${peer_pub}|" \
		"${HERE}/fixtures/lock/wg.yaml.tmpl" >"${rendered_dir}/wg.yaml" \
		|| die "Rendering fixtures/lock/wg.yaml.tmpl failed."
	cp "${HERE}/fixtures/lock/stunmesh.yaml" "${rendered_dir}/stunmesh.yaml"

	LOCK_FIXTURE_DIR="$rendered_dir"
	LOCK_PEER_PUBKEY="$peer_pub"
}

phase_lock_overlap() {
	local delayed_fetch_cmd lock_config locked_count

	render_lock_fixture
	start_delayed_fake_proxy "$LOCK_FAKEPROXY_PORT" "$LOCK_GET_DELAY"

	# Publish only to the delayed proxy: point_proxies_at overwrites
	# provd.yaml's whole proxy list, so publish here, then restore it
	# to the main fakeproxy immediately after -- every later phase's
	# publish_fixture call needs the fast one back, and this call runs
	# before that restore, not after.
	point_proxies_at "$E2E_NAMESPACE" "$DELAYED_FAKEPROXY_HOST_URL"
	publish_fixture "$LOCK_FIXTURE_DIR" "$E2E_NAMESPACE" "$E2E_NODE_ID"
	point_proxies_at "$E2E_NAMESPACE" "$FAKEPROXY_HOST_URL"

	lock_config="/etc/stunmesh/agent/config-lock.yaml"
	write_guest_config "$lock_config" "$DELAYED_FAKEPROXY_GUEST_URL"
	delayed_fetch_cmd="/usr/sbin/stunmesh-agent --oneshot --config ${lock_config}"

	# The real overlap: one guest_exec, one shell, one fetch backgrounded
	# and a second launched 1s later while the first is still asleep
	# inside its delayed GET -- not two separate ssh invocations, whose
	# own connection-setup jitter would undermine the deterministic
	# stagger this needs. Both processes' stdout+stderr are captured to
	# separate files so the assertions below can tell which one the
	# kernel handed the flock to. A whole second, not a fraction: this
	# image's busybox sleep rejects a fractional argument outright
	# ("sleep: invalid number"), and 1s is still comfortably inside
	# LOCK_GET_DELAY's 3s window.
	guest_exec "$SSH_PORT" "$SSH_KEY" "\
		rm -f /tmp/lock-a.out /tmp/lock-b.out; \
		( ${delayed_fetch_cmd} >/tmp/lock-a.out 2>&1 ) & \
		a_pid=\$!; \
		sleep 1; \
		${delayed_fetch_cmd} >/tmp/lock-b.out 2>&1; \
		wait \"\$a_pid\"" \
		|| die "Constructing the real fetch overlap failed outright (not a lock-contention failure; see the guest for /tmp/lock-a.out and /tmp/lock-b.out)."

	# guest_capture, not a plain `var=$(guest_exec ...)`: see lib.sh's
	# guest_capture for why a failed read here must not abort the
	# harness under `set -e`. FALLBACK "0": this is a count, and 0 is
	# the real, meaningful "no lockout observed" value -- the
	# assert_equal below then reports it as a count that is wrong (0
	# instead of 1), not as a silent abort. The remote pipeline itself
	# needs no `|| true`:
	# its last command is awk, which exits 0 whether or not grep found
	# a match, so guest_exec's own exit status already never reflects
	# grep's "no match" case.
	locked_count=$(guest_capture "$SSH_PORT" "$SSH_KEY" \
		"grep -c 'already locked by another instance, exiting' /tmp/lock-a.out /tmp/lock-b.out | awk -F: '{s+=\$2} END {print s}'" 0)
	assert_equal "exactly one of the two overlapping fetches was locked out" \
		"$locked_count" "1"

	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true
	assert_ssh_output_contains "the winner's own bundle reached the kernel (the loser never got this far)" \
		"wg show wg0" "$LOCK_PEER_PUBKEY"

	stop_delayed_fake_proxy
}
