#!/usr/bin/env bash
# phase-routes.sh -- assertions E: route_allowed_ips: false (stage5
# checklist item 16: "route_allowed_ips: false plus routes gives
# exactly the listed routes").
#
# internal/uci's golden tests already prove BuildInterface emits the
# right *UCI* commands for routes[] and route_allowed_ips. What is
# untested anywhere is what netifd actually does with those commands
# once "ubus call network reload" runs against them: whether the
# kernel's real routing table ends up with exactly the routes named in
# the bundle, and nothing derived from a peer's allowed_ips.
#
# Sourced by run.sh, which then calls every function named phase_*.
# Uses HERE, WORK, SSH_PORT, SSH_KEY, E2E_NAMESPACE, E2E_NODE_ID,
# CONTROLLER_PUBKEY and FAKEPROXY_GUEST_URL, all set by run.sh or
# lib.sh before any phase runs. Self-contained like every other phase
# (see run.sh's own doc comment): it publishes its own fixture and
# does not assume any other phase's wg0 state.
set -euo pipefail

# render_routes_fixture -- renders fixtures/routes/wg.yaml.tmpl with
# fresh WireGuard key material into a directory under $WORK. Sets
# ROUTES_FIXTURE_DIR. See phase-fetch-basic.sh's
# render_fetch_basic_fixture for why this is called plainly, never
# through command substitution.
render_routes_fixture() {
	local node_priv peer_pub rendered_dir
	read -r node_priv _ < <(generate_wg_keypair)
	read -r _ peer_pub < <(generate_wg_keypair)

	rendered_dir="${WORK}/fixtures-rendered/routes"
	mkdir -p "$rendered_dir"
	sed \
		-e "s|@NODE_PRIVATE_KEY@|${node_priv}|" \
		-e "s|@PEER_PUBLIC_KEY@|${peer_pub}|" \
		"${HERE}/fixtures/routes/wg.yaml.tmpl" >"${rendered_dir}/wg.yaml" \
		|| die "Rendering fixtures/routes/wg.yaml.tmpl failed."
	cp "${HERE}/fixtures/routes/stunmesh.yaml" "${rendered_dir}/stunmesh.yaml"

	ROUTES_FIXTURE_DIR="$rendered_dir"
}

phase_routes() {
	local fetch_cmd route_count

	render_routes_fixture
	publish_fixture "$ROUTES_FIXTURE_DIR" "$E2E_NAMESPACE" "$E2E_NODE_ID"

	fetch_cmd="/usr/sbin/stunmesh-agent fetch --namespace ${E2E_NAMESPACE} --node-id ${E2E_NODE_ID} --controller-pubkey ${CONTROLLER_PUBKEY} --proxy ${FAKEPROXY_GUEST_URL} --identity-key /etc/stunmesh/provd/identity.key"
	assert_ssh_exit_code "fetch applies the route_allowed_ips: false bundle (exit 0)" "$fetch_cmd" 0
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 3" || true

	assert_ssh_ok "uci peer route_allowed_ips is 0" \
		"[ \"\$(uci -q get network.wg0_p_peer1.route_allowed_ips)\" = 0 ]"

	# The interface address is a /32 (fixtures/routes/wg.yaml.tmpl's own
	# comment explains why): the main routing table for wg0 should hold
	# only the two routes[] entries, nothing implicit from the address
	# itself.
	route_count=$(guest_exec "$SSH_PORT" "$SSH_KEY" "ip route show dev wg0 | wc -l")
	assert_equal "the main table holds exactly the two routes[] entries for wg0" \
		"$route_count" "2"

	assert_ssh_output_contains "the first routes[] entry is in the main table" \
		"ip route show dev wg0" "10.88.0.0/24"
	assert_ssh_output_contains "the second routes[] entry is in the main table, with its metric" \
		"ip route show dev wg0" "10.89.0.0/24"
	assert_ssh_ok "the second routes[] entry's metric (50) is in the main table" \
		"ip route show dev wg0 | grep '10.89.0.0/24' | grep -q 'metric 50'"

	# route_allowed_ips: false means the peer's own allowed_ips
	# (10.95.0.0/16, deliberately a third, distinct subnet -- see the
	# fixture) must never appear as a route: this is the negative half
	# of "exactly the listed routes".
	assert_ssh_ok "the peer's allowed_ips is not a route (route_allowed_ips: false)" \
		"! ip route show dev wg0 | grep -q '10.95.0.0/16'"
}
