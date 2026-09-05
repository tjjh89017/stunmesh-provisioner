#!/usr/bin/env bash
# phase-fetch-basic.sh -- assertions A: basic apply of one WireGuard
# interface.
#
# This phase publishes a realistic bundle -- one WireGuard interface,
# one peer, generated key material -- and runs the real
# `stunmesh-agent --oneshot` in the guest, checking what its uci and
# ubus calls actually produced on real netifd.
#
# "Changes nothing" is proven by comparing two things captured before
# and after the second fetch: a sha256sum of /etc/config/network (the
# file `uci commit` would have rewritten) and a sha256sum of last.json
# (the file a real apply would have rewritten). Both must be
# identical, or the second fetch touched something it should not
# have. `--oneshot` always exits 0, so the file comparisons are the
# evidence.
#
# Deliberately out of scope here: removing an interface, tearing down
# stunmesh, and more than one interface.
#
# Sourced by run.sh, which then calls every function named phase_*.
# Uses HERE, WORK, SSH_PORT, SSH_KEY, E2E_NAMESPACE and E2E_NODE_ID,
# all set by run.sh or lib.sh before any phase runs.
set -euo pipefail

# render_fetch_basic_fixture -- renders fixtures/basic-wg0/wg.yaml.tmpl
# with freshly generated WireGuard key material into a directory under
# $WORK. Sets FETCH_BASIC_FIXTURE_DIR (that directory's path),
# FETCH_BASIC_NODE_PUBKEY and FETCH_BASIC_PEER_PUBKEY, the two public
# keys later assertions check for -- the private key and the preshared
# key are used once, here, to build the fixture, and never captured
# into a variable a later step could accidentally print.
#
# Called plainly, never through command substitution ($(...)): a
# command substitution runs its command in a subshell, and a subshell
# cannot set a variable its caller can still see -- exactly the
# mistake this function's own first version made.
render_fetch_basic_fixture() {
	local node_priv node_pub peer_pub psk rendered_dir
	read -r node_priv node_pub < <(generate_wg_keypair)
	# Only the peer's public half is ever real key material a real
	# remote node would share; its private key is generated only to
	# derive that public key, never captured into a variable, and
	# discarded immediately.
	read -r _ peer_pub < <(generate_wg_keypair)
	psk=$(wg genpsk) || die "wg genpsk failed."

	rendered_dir="${WORK}/fixtures-rendered/basic-wg0"
	mkdir -p "$rendered_dir"
	sed \
		-e "s|@NODE_PRIVATE_KEY@|${node_priv}|" \
		-e "s|@PEER_PUBLIC_KEY@|${peer_pub}|" \
		-e "s|@PEER_PSK@|${psk}|" \
		"${HERE}/fixtures/basic-wg0/wg.yaml.tmpl" >"${rendered_dir}/wg.yaml" \
		|| die "Rendering fixtures/basic-wg0/wg.yaml.tmpl failed."
	cp "${HERE}/fixtures/basic-wg0/stunmesh.yaml" "${rendered_dir}/stunmesh.yaml"

	FETCH_BASIC_FIXTURE_DIR="$rendered_dir"
	FETCH_BASIC_NODE_PUBKEY="$node_pub"
	FETCH_BASIC_PEER_PUBKEY="$peer_pub"
}

phase_fetch_basic() {
	local fetch_cmd
	render_fetch_basic_fixture
	publish_fixture "$FETCH_BASIC_FIXTURE_DIR" "$E2E_NAMESPACE" "$E2E_NODE_ID"

	fetch_cmd="/usr/sbin/stunmesh-agent --oneshot"

	assert_ssh_exit_code "first fetch applies the bundle (exit 0)" "$fetch_cmd" 0

	# "ubus call network reload" only asks netifd to reconfigure; netifd
	# brings the new interface up asynchronously.
	# Give it a moment before asking wg/ubus what actually happened.
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true

	assert_ssh_output_contains "wg0's public key matches the bundle's private key" \
		"wg show wg0 public-key" "$FETCH_BASIC_NODE_PUBKEY"
	assert_ssh_output_contains "wg0 carries the bundle's peer" \
		"wg show wg0" "$FETCH_BASIC_PEER_PUBKEY"
	assert_ssh_output_contains "wg0 carries the bundle's peer allowed-ips" \
		"wg show wg0 allowed-ips" "10.99.0.2/32"

	assert_ssh_output_contains "ubus network.interface.wg0 status reports the bundle's address" \
		"ubus call network.interface.wg0 status" "10.99.0.1"
	assert_ssh_output_contains "ubus network.interface.wg0 status reports up" \
		"ubus call network.interface.wg0 status" '"up": true'

	assert_ssh_ok "uci section wg0 exists as an interface" \
		"[ \"\$(uci -q get network.wg0)\" = interface ]"
	assert_ssh_ok "uci wg0 uses proto wireguard" \
		"[ \"\$(uci -q get network.wg0.proto)\" = wireguard ]"
	assert_ssh_ok "uci peer section wg0_p_peer1 exists as wireguard_wg0" \
		"[ \"\$(uci -q get network.wg0_p_peer1)\" = wireguard_wg0 ]"
	assert_ssh_output_contains "uci peer section wg0_p_peer1 carries the peer's public key" \
		"uci -q get network.wg0_p_peer1.public_key" "$FETCH_BASIC_PEER_PUBKEY"

	# The fixture generates a preshared key for peer1 (fixtures/basic-wg0/
	# wg.yaml.tmpl) and internal/uci/interface.go writes it as
	# `option preshared_key`. Checking that UCI option would only prove the
	# agent wrote a string; it would not prove netifd's WireGuard proto
	# handler ever read it back out and pushed it into the kernel. "wg show
	# ... preshared-keys" asks the kernel directly, so it is the one check
	# that actually closes the loop this harness exists to close. Presence
	# only, never the value: printing or comparing the key itself would put
	# real key material in the harness's own output.
	assert_ssh_ok "wg0 peer1's preshared key reached the kernel (wg show, not just uci)" \
		"wg show wg0 preshared-keys | awk -v peer='${FETCH_BASIC_PEER_PUBKEY}' '\$1 == peer && \$2 != \"(none)\" { f=1 } END { exit !f }'"

	assert_ssh_ok "last.json exists at the documented path" \
		"test -f /etc/stunmesh/agent/last.json"
	assert_ssh_output_contains "last.json is mode 0600" \
		"ls -l /etc/stunmesh/agent/last.json" "-rw-------"

	# guest_capture, not a plain `var=$(guest_exec ...)`: if an earlier
	# assertion in this phase already failed and left one of these files
	# missing, a plain read would abort the whole harness under `set -e`
	# instead of letting assert_equal below report the mismatch and the
	# run continue (see lib.sh's guest_capture for why).
	local before_network_sha before_last_sha
	before_network_sha=$(guest_capture "$SSH_PORT" "$SSH_KEY" "sha256sum /etc/config/network")
	before_last_sha=$(guest_capture "$SSH_PORT" "$SSH_KEY" "sha256sum /etc/stunmesh/agent/last.json")

	assert_ssh_exit_code "second fetch with the same bundle exits 0 (no change)" "$fetch_cmd" 0

	local after_network_sha after_last_sha
	after_network_sha=$(guest_capture "$SSH_PORT" "$SSH_KEY" "sha256sum /etc/config/network")
	after_last_sha=$(guest_capture "$SSH_PORT" "$SSH_KEY" "sha256sum /etc/stunmesh/agent/last.json")

	assert_equal "second fetch left /etc/config/network byte-identical" \
		"$after_network_sha" "$before_network_sha"
	assert_equal "second fetch left last.json byte-identical" \
		"$after_last_sha" "$before_last_sha"
}
