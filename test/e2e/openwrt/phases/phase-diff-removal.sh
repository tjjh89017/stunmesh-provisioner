#!/usr/bin/env bash
# phase-diff-removal.sh -- assertions B: diff and removal (stage goal
# item 8; stage5 checklist items 8, 9, 13, 14, 15).
#
# phase-fetch-basic.sh proved a first apply of one interface. This
# phase is the one that can send findings back to production code
# (PLAN.md 6's open assumption): it publishes and fetches four bundle
# revisions in sequence, on the same guest, and reads real netifd and
# kernel state after each one.
#
#   v1  wg0 + wg1, both up (baseline).
#   v2  wg0 byte-identical to v1; wg1's peer public key changed, and
#       nothing else about wg1. This is the exact case PLAN.md 6
#       flagged: "Assumption: network reload also restarts a WireGuard
#       interface when only its wireguard_<iface> peer sections
#       changed." The apply procedure itself still deletes and
#       recreates the whole wg1 *section* (PLAN.md 6's change table:
#       "any change inside an interface... delete every section...
#       create all sections again"), but wg1's own option values
#       (private_key, addresses) come out byte-identical to v1's --
#       only the wireguard_wg1 peer section's content actually
#       differs. This phase is what found the assumption false: a
#       plain `ubus call network reload` did not push the new peer
#       into the running kernel interface. That finding sent
#       fetch_apply.go's applyDiff an explicit "ifup <iface>" step for
#       every new or changed interface, run right after the reload
#       (see ifupChangedInterfaces). v2's checks below read
#       `wg show wg1` after a fetch that runs both steps, confirming
#       the full apply pipeline -- reload, then ifup -- delivers wg1's
#       new peer and drops its old one.
#   v3  wg1 removed from the bundle; wg0 unchanged. Checks that
#       `network reload` actually tears the kernel interface down
#       (not just the UCI section), and that wg0 is not touched at
#       all -- proven by wg0's netdev ifindex, which only changes if
#       the kernel interface was deleted and recreated.
#   v4  wg: {} and empty stunmesh (fixtures/empty): the teardown case.
#       Everything the agent created is gone, the stunmesh stand-in
#       recorded "stop", and a UCI section this phase adds by hand
#       right before v4 -- something the agent never created --
#       survives untouched (PLAN.md 2.6's claim, never tested before
#       this).
#
# "Not restarted" evidence: a WireGuard netdev's ifindex
# (/sys/class/net/<if>/ifindex) is assigned by the kernel when the
# device is created and never changes while the device lives. If
# netifd tears an interface down and recreates it -- the definition of
# "restarted" this phase uses -- the new device gets a new ifindex.
# wg show's own counters (handshakes, transfer) do not work here: no
# real remote peer ever completes a handshake against a fixture
# address, so they would read zero whether or not the interface
# restarted, proving nothing. ifindex is available on every reload,
# needs no traffic, and answers exactly the question asked: did the
# kernel device get replaced.
#
# Sourced by run.sh, which then calls every function named phase_*.
# Uses HERE, WORK, SSH_PORT, SSH_KEY, E2E_NAMESPACE and E2E_NODE_ID,
# all set by run.sh or lib.sh before any phase runs.
set -euo pipefail

# render_two_iface_bundle OUT_DIR WG1_PEER_PUBKEY -- writes a two-
# interface bundle (wg0 + wg1) to OUT_DIR/wg.yaml, substituting
# WG1_PEER_PUBKEY for wg1's peer's public key. wg0's key material
# (DIFF_REMOVAL_WG0_PRIV/PUB and DIFF_REMOVAL_WG0_PEER_PUBKEY) and
# wg1's own key (DIFF_REMOVAL_WG1_PRIV) are read from variables set
# once by phase_diff_removal, so every render of this bundle carries
# byte-identical wg0 content and a byte-identical wg1 interface key --
# only the substituted peer key varies between calls.
render_two_iface_bundle() {
	local out_dir="$1" wg1_peer_pubkey="$2"
	mkdir -p "$out_dir"
	sed \
		-e "s|@WG0_PRIVATE_KEY@|${DIFF_REMOVAL_WG0_PRIV}|" \
		-e "s|@WG0_PEER_PUBLIC_KEY@|${DIFF_REMOVAL_WG0_PEER_PUBKEY}|" \
		-e "s|@WG1_PRIVATE_KEY@|${DIFF_REMOVAL_WG1_PRIV}|" \
		-e "s|@WG1_PEER_PUBLIC_KEY@|${wg1_peer_pubkey}|" \
		"${HERE}/fixtures/reload-removal/two-iface.yaml.tmpl" >"${out_dir}/wg.yaml" \
		|| die "Rendering fixtures/reload-removal/two-iface.yaml.tmpl failed."
	cp "${HERE}/fixtures/reload-removal/stunmesh.yaml" "${out_dir}/stunmesh.yaml"
}

# render_wg0_only_bundle OUT_DIR -- writes a one-interface bundle
# (wg0 only, byte-identical to render_two_iface_bundle's wg0) to
# OUT_DIR/wg.yaml. Used for the "wg1 removed" step.
render_wg0_only_bundle() {
	local out_dir="$1"
	mkdir -p "$out_dir"
	sed \
		-e "s|@WG0_PRIVATE_KEY@|${DIFF_REMOVAL_WG0_PRIV}|" \
		-e "s|@WG0_PEER_PUBLIC_KEY@|${DIFF_REMOVAL_WG0_PEER_PUBKEY}|" \
		"${HERE}/fixtures/reload-removal/wg0-only.yaml.tmpl" >"${out_dir}/wg.yaml" \
		|| die "Rendering fixtures/reload-removal/wg0-only.yaml.tmpl failed."
	cp "${HERE}/fixtures/reload-removal/stunmesh.yaml" "${out_dir}/stunmesh.yaml"
}

# ifindex_of IFACE -- prints the guest kernel's ifindex for IFACE, or
# the literal string "absent" when the netdev does not exist. Used
# both as "not restarted" evidence (unchanged ifindex across a reload
# that should not have touched this interface) and as "torn down"
# evidence (ifindex becomes "absent").
#
# guest_capture, not a plain `var=$(guest_exec ...)`: see lib.sh's
# guest_capture for why a failed read here must not abort the harness
# under `set -e`. No FALLBACK: "absent" is already a real, meaningful
# answer this function returns (the netdev is genuinely gone), so
# using it to also mean "the ssh read itself failed" would make an
# infrastructure failure read as a passing "torn down" check. The
# per-call sentinel guest_capture falls back to instead never equals
# "absent" or a real ifindex, so a failed read shows up as itself in
# the assertion output, not as a plausible-looking value.
ifindex_of() {
	local iface="$1"
	guest_capture "$SSH_PORT" "$SSH_KEY" \
		"cat /sys/class/net/${iface}/ifindex 2>/dev/null || echo absent"
}

phase_diff_removal() {
	local fetch_cmd
	fetch_cmd="/usr/sbin/stunmesh-agent --oneshot"

	read -r DIFF_REMOVAL_WG0_PRIV _ < <(generate_wg_keypair)
	read -r _ DIFF_REMOVAL_WG0_PEER_PUBKEY < <(generate_wg_keypair)
	read -r DIFF_REMOVAL_WG1_PRIV _ < <(generate_wg_keypair)
	read -r _ diff_removal_wg1_peer_a_pubkey < <(generate_wg_keypair)
	read -r _ diff_removal_wg1_peer_b_pubkey < <(generate_wg_keypair)

	local rendered="${WORK}/fixtures-rendered/reload-removal"

	# --- v1: baseline, wg0 + wg1 both up ------------------------------
	render_two_iface_bundle "$rendered" "$diff_removal_wg1_peer_a_pubkey"
	publish_fixture "$rendered" "$E2E_NAMESPACE" "$E2E_NODE_ID"
	assert_ssh_exit_code "v1: fetch applies the two-interface bundle (exit 0)" "$fetch_cmd" 0
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true

	assert_ssh_output_contains "v1: wg0 carries its peer" \
		"wg show wg0" "$DIFF_REMOVAL_WG0_PEER_PUBKEY"
	assert_ssh_output_contains "v1: wg1 carries peer A" \
		"wg show wg1" "$diff_removal_wg1_peer_a_pubkey"
	assert_ssh_output_contains "v1: ubus reports wg0 up" \
		"ubus call network.interface.wg0 status" '"up": true'
	assert_ssh_output_contains "v1: ubus reports wg1 up" \
		"ubus call network.interface.wg1 status" '"up": true'

	# The bundle's non-empty stunmesh text (fixtures/reload-removal/
	# stunmesh.yaml) makes applyStunmeshConfig write this file
	# (fetch_apply.go); the embedded stunmesh-go app is not under test
	# here (its own package covers that), only whether the agent wrote
	# and later removed its config file at the right steps.
	assert_ssh_ok "v1: the stunmesh config file exists" \
		"test -f /etc/stunmesh/config.yaml"

	local wg0_ifindex_v1
	wg0_ifindex_v1=$(ifindex_of wg0)
	[[ "$wg0_ifindex_v1" != "absent" ]] || die "wg0 has no netdev right after v1's apply; cannot use ifindex as evidence."

	# --- v2: only wg1's peer changes; wg0 is untouched byte-for-byte --
	render_two_iface_bundle "$rendered" "$diff_removal_wg1_peer_b_pubkey"
	publish_fixture "$rendered" "$E2E_NAMESPACE" "$E2E_NODE_ID"
	assert_ssh_exit_code "v2: fetch applies wg1's changed peer (exit 0)" "$fetch_cmd" 0
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true

	# Check 1 (stage5 checklist item 8, PLAN.md 6): does the apply
	# pipeline -- "ubus call network reload" followed by an explicit
	# "ifup wg1" (fetch_apply.go's applyDiff step 4,
	# ifupChangedInterfaces) -- make the kernel pick up wg1's new
	# peer? The SSH command above runs "stunmesh-agent fetch" once,
	# which always performs both steps together; it cannot isolate the
	# reload from the ifup that follows it. This is read straight off
	# wg show, not inferred from exit codes: fetch_apply.go's reload
	# call always exits 0 regardless of what netifd/wg actually did
	# with it (PLAN.md 6 step 5 has no wg-side check built in), so a
	# passing "exit 0" above is not, by itself, evidence that either
	# step had a real effect on wg1's peer.
	assert_ssh_output_contains "check 1: apply (reload + ifup) applies wg1's new peer to the kernel" \
		"wg show wg1" "$diff_removal_wg1_peer_b_pubkey"
	assert_ssh_ok "check 1: apply (reload + ifup) drops wg1's old peer from the kernel" \
		"! wg show wg1 | grep -q '${diff_removal_wg1_peer_a_pubkey}'"

	# Check 3 (stage5 checklist item 13): wg0's kernel netdev must be
	# the exact same device as before -- same ifindex -- proving
	# netifd did not restart it just because a sibling interface's
	# config changed.
	local wg0_ifindex_v2
	wg0_ifindex_v2=$(ifindex_of wg0)
	assert_equal "check 3: wg0's ifindex is unchanged after wg1's peer changes (wg0 was not restarted)" \
		"$wg0_ifindex_v2" "$wg0_ifindex_v1"
	assert_ssh_output_contains "check 3: wg0 still carries its own peer, undisturbed" \
		"wg show wg0" "$DIFF_REMOVAL_WG0_PEER_PUBKEY"

	# --- v3: wg1 removed from the bundle; wg0 untouched ---------------
	render_wg0_only_bundle "$rendered"
	publish_fixture "$rendered" "$E2E_NAMESPACE" "$E2E_NODE_ID"
	assert_ssh_exit_code "v3: fetch applies wg1's removal (exit 0)" "$fetch_cmd" 0
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true

	# Check 2 (stage5 checklist item 9): the deleted UCI section must
	# actually take the kernel interface down, not just vanish from
	# /etc/config/network.
	assert_ssh_ok "check 2: wg1's UCI interface section is gone" \
		"! uci -q get network.wg1"
	assert_ssh_ok "check 2: wg1's UCI peer section is gone" \
		"! uci -q get network.wg1_p_peer1"
	assert_equal "check 2: wg1's kernel netdev is gone (network reload tore it down)" \
		"$(ifindex_of wg1)" "absent"

	# Check 4 (stage5 checklist item 14): wg0 survives, byte-for-byte,
	# the same kernel device as before -- proven the same way check 3
	# proved it: an unchanged ifindex.
	local wg0_ifindex_v3
	wg0_ifindex_v3=$(ifindex_of wg0)
	assert_equal "check 4: wg0's ifindex is unchanged after wg1's removal (wg0 was not restarted)" \
		"$wg0_ifindex_v3" "$wg0_ifindex_v1"
	assert_ssh_output_contains "check 4: wg0 still carries its own peer after wg1's removal" \
		"wg show wg0" "$DIFF_REMOVAL_WG0_PEER_PUBKEY"
	assert_ssh_ok "check 4: wg0's UCI interface section still exists" \
		"[ \"\$(uci -q get network.wg0)\" = interface ]"

	# --- sentinel: a UCI section the agent never created --------------
	# PLAN.md 2.6 claims the agent only ever touches the sections it
	# recorded in last.json; nothing before this phase has tested that
	# claim against a section outside the agent's own state.
	guest_exec "$SSH_PORT" "$SSH_KEY" \
		"uci set network.diffremovalsentinel=interface && uci set network.diffremovalsentinel.proto=none && uci commit network" \
		|| die "Could not create the sentinel UCI section."

	# --- v4: teardown (wg: {}, empty stunmesh) -------------------------
	publish_fixture "${HERE}/fixtures/empty" "$E2E_NAMESPACE" "$E2E_NODE_ID"
	assert_ssh_exit_code "v4: fetch applies the teardown (exit 0)" "$fetch_cmd" 0
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true

	# Check 5 (stage5 checklist item 15): everything the agent created
	# is gone, from the kernel as well as UCI.
	assert_ssh_ok "check 5: wg0's UCI interface section is gone after teardown" \
		"! uci -q get network.wg0"
	assert_ssh_ok "check 5: wg0's UCI peer section is gone after teardown" \
		"! uci -q get network.wg0_p_peer0"
	assert_equal "check 5: wg0's kernel netdev is gone after teardown" \
		"$(ifindex_of wg0)" "absent"
	assert_ssh_ok "check 5: the stunmesh config file is gone" \
		"! test -f /etc/stunmesh/config.yaml"

	# The sentinel section this phase created by hand, moments ago,
	# must survive: the agent's last.json never recorded it, so
	# PLAN.md 6's "delete by exact recorded name, never by pattern"
	# rule must leave it alone.
	assert_ssh_ok "check 5: a UCI section the agent never created survives teardown" \
		"[ \"\$(uci -q get network.diffremovalsentinel)\" = interface ]"
}
