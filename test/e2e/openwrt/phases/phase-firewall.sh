#!/usr/bin/env bash
# phase-firewall.sh -- assertions E: the firewall zone survives
# (stage5 checklist item 17; PLAN.md 2.7: "Firewall zones and rules.
# The operator adds list network '<iface>' to a zone once by hand.
# The interface name is stable."; PLAN.md section 6's "Rules": "The
# agent touches only sections that it created... It never touches
# other sections.").
#
# Nothing before this item ever tested that claim against a section
# the agent has every opportunity to disturb: PLAN.md 6's own change
# table says any change inside an interface deletes and recreates
# every section *of that interface*, by exact name, from last.json.
# A firewall zone is never one of those sections, but the only way to
# be sure an apply that really did delete-and-recreate wg0 left it
# alone is to add one by hand and read it back after.
#
# Sourced by run.sh, which then calls every function named phase_*.
# Uses HERE, WORK, SSH_PORT, SSH_KEY, E2E_NAMESPACE, E2E_NODE_ID,
# CONTROLLER_PUBKEY and FAKEPROXY_GUEST_URL, all set by run.sh or
# lib.sh before any phase runs. Self-contained like every other phase
# (see run.sh's own doc comment): it publishes its own two-revision
# fixture and does not assume any other phase's wg0 state.
set -euo pipefail

# render_firewall_fixture VERSION PEER_PUBKEY -- renders
# fixtures/firewall-survive/wg-VERSION.yaml.tmpl ("v1" or "v2") with
# NODE_PRIV/NODE_PUB (shared across both versions, set once by
# phase_firewall_survives) and PEER_PUBKEY into a directory under
# $WORK. wg-v1 and wg-v2 share the interface's own key and address;
# only the peer's public key differs, which is enough to force
# PLAN.md 6's "any change inside an interface: delete every section,
# create all sections again" path onto wg0's own sections, without
# firewall.wgzone ever being named in either bundle.
render_firewall_fixture() {
	local version="$1" peer_pubkey="$2" rendered_dir
	rendered_dir="${WORK}/fixtures-rendered/firewall-survive-${version}"
	mkdir -p "$rendered_dir"
	sed \
		-e "s|@NODE_PRIVATE_KEY@|${FIREWALL_NODE_PRIV}|" \
		-e "s|@PEER_PUBLIC_KEY_${version^^}@|${peer_pubkey}|" \
		"${HERE}/fixtures/firewall-survive/wg-${version}.yaml.tmpl" >"${rendered_dir}/wg.yaml" \
		|| die "Rendering fixtures/firewall-survive/wg-${version}.yaml.tmpl failed."
	cp "${HERE}/fixtures/firewall-survive/stunmesh.yaml" "${rendered_dir}/stunmesh.yaml"
	echo "$rendered_dir"
}

phase_firewall_survives() {
	local fetch_cmd v1_dir v2_dir peer1_pub peer2_pub

	read -r FIREWALL_NODE_PRIV _ < <(generate_wg_keypair)
	read -r _ peer1_pub < <(generate_wg_keypair)
	read -r _ peer2_pub < <(generate_wg_keypair)

	fetch_cmd="/usr/sbin/stunmesh-agent fetch --namespace ${E2E_NAMESPACE} --node-id ${E2E_NODE_ID} --controller-pubkey ${CONTROLLER_PUBKEY} --proxy ${FAKEPROXY_GUEST_URL} --identity-key /etc/stunmesh/agent/identity.key"

	v1_dir=$(render_firewall_fixture v1 "$peer1_pub")
	publish_fixture "$v1_dir" "$E2E_NAMESPACE" "$E2E_NODE_ID"
	assert_ssh_exit_code "v1: fetch applies the baseline bundle (exit 0)" "$fetch_cmd" 0
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true
	assert_ssh_ok "v1: wg0's UCI interface section exists" \
		"[ \"\$(uci -q get network.wg0)\" = interface ]"

	# The operator's own one-time step (PLAN.md 2.7): a firewall zone
	# naming wg0, added entirely by hand -- the agent never writes to
	# /etc/config/firewall.
	guest_exec "$SSH_PORT" "$SSH_KEY" "\
		uci set firewall.wgzone=zone; \
		uci set firewall.wgzone.name='wgzone'; \
		uci set firewall.wgzone.input='ACCEPT'; \
		uci set firewall.wgzone.output='ACCEPT'; \
		uci set firewall.wgzone.forward='ACCEPT'; \
		uci add_list firewall.wgzone.network='wg0'; \
		uci commit firewall" \
		|| die "Could not add the firewall zone by hand."
	assert_ssh_output_contains "the hand-added firewall zone names wg0 before any further apply" \
		"uci show firewall.wgzone" "wg0"

	v2_dir=$(render_firewall_fixture v2 "$peer2_pub")
	publish_fixture "$v2_dir" "$E2E_NAMESPACE" "$E2E_NODE_ID"
	assert_ssh_exit_code "v2: fetch applies the changed bundle, forcing wg0's sections to be recreated (exit 0)" "$fetch_cmd" 0
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true

	assert_ssh_output_contains "v2: wg0 now carries the new peer, proving the apply really ran" \
		"wg show wg0" "$peer2_pub"
	assert_ssh_output_contains "the firewall zone still names wg0 after the apply" \
		"uci show firewall.wgzone" "wg0"
	assert_ssh_ok "the firewall zone section itself still exists" \
		"[ \"\$(uci -q get firewall.wgzone)\" = zone ]"
}
