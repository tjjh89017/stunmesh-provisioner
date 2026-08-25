#!/usr/bin/env bash
# phase-lock.sh -- assertions D: the lock (stage5 checklist item 12's
# "lock prevents overlap"; PLAN.md section 5: "A second fetch while
# one runs exits 0 at once with a log line").
#
# contrib/openwrt/tests/ already covers that both shipped scripts
# never add their own locking on top of --lock (README.md section 4's
# last paragraph). What is untested anywhere is the lock itself under
# a real race: two real `stunmesh-agent fetch` processes, in the
# guest, actually contending for the same flock(2) at the same time.
#
# Constructing a real overlap deterministically needs the winner to
# hold the lock for long enough that a second process, launched
# moments later, reliably arrives while the first still holds it. A
# plain local round trip to the fake dhtproxy is too fast to trust for
# that (a flaky, sometimes-overlaps race would prove nothing on the
# run where it did not overlap). This phase starts a second, dedicated
# fakeproxy instance (lib.sh's start_delayed_fake_proxy) that delays
# every GET by lockGetDelay, publishes one bundle to it, and points
# both racing fetches at it with an explicit --proxy flag -- the main
# fakeproxy instance every other phase uses stays fast throughout.
#
# Sourced by run.sh, which then calls every function named phase_*.
# Uses HERE, WORK, SSH_PORT, SSH_KEY, E2E_NAMESPACE, E2E_NODE_ID,
# CONTROLLER_PUBKEY, FAKEPROXY_HOST_URL and FAKEPROXY_BIN, all set by
# run.sh or lib.sh before any phase runs. Self-contained like every
# other phase (see run.sh's own doc comment): it does not assume any
# other phase already ran or already applied wg0.
set -euo pipefail

# lockGetDelay must comfortably exceed the stagger between launching
# the two racing fetches (0.5s, in phase_lock_overlap) so the second
# one always starts while the first still holds the lock, and must
# stay comfortably under fetch_cmd.go's fetchTimeout (30s) so the
# winner's own GET does not time out waiting on itself.
LOCK_GET_DELAY="3s"
LOCK_FAKEPROXY_PORT="${E2E_LOCK_FAKEPROXY_PORT:-8788}"

# render_lock_fixture -- renders fixtures/lock/wg.yaml.tmpl with fresh
# WireGuard key material into a directory under $WORK. Sets
# LOCK_FIXTURE_DIR and LOCK_PEER_PUBKEY (the peer public key later
# assertions check the winner actually applied), the same pattern
# phase-fetch-basic.sh's render_fetch_basic_fixture uses, including
# the same "call plainly, never through command substitution" rule
# (see that function's own comment for why).
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
	local delayed_fetch_cmd before_actions after_actions locked_count

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

	delayed_fetch_cmd="/usr/sbin/stunmesh-agent fetch --namespace ${E2E_NAMESPACE} --node-id ${E2E_NODE_ID} --controller-pubkey ${CONTROLLER_PUBKEY} --proxy ${DELAYED_FAKEPROXY_GUEST_URL} --identity-key /etc/stunmesh/provd/identity.key"

	before_actions=$(guest_exec "$SSH_PORT" "$SSH_KEY" "wc -l < /tmp/stunmesh-stub-actions.log 2>/dev/null || echo 0")

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

	locked_count=$(guest_exec "$SSH_PORT" "$SSH_KEY" \
		"grep -c 'already locked by another instance, exiting' /tmp/lock-a.out /tmp/lock-b.out | awk -F: '{s+=\$2} END {print s}'")
	assert_equal "exactly one of the two overlapping fetches was locked out" \
		"$locked_count" "1"

	after_actions=$(guest_exec "$SSH_PORT" "$SSH_KEY" "wc -l < /tmp/stunmesh-stub-actions.log 2>/dev/null || echo 0")
	assert_equal "only the winner reached apply: the stunmesh stand-in ran exactly once, not twice" \
		"$((after_actions - before_actions))" "1"

	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true
	assert_ssh_output_contains "the winner's own bundle reached the kernel (the loser never got this far)" \
		"wg show wg0" "$LOCK_PEER_PUBKEY"

	stop_delayed_fake_proxy
}
