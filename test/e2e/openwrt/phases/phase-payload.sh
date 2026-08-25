#!/usr/bin/env bash
# phase-payload.sh -- asserts the stunmesh-agent payload landed correctly.
#
# This does NOT test a fetch: no bundle exists yet (the controller side is
# the next item), so nothing here asserts anything about fetching,
# decrypting, or applying config. It only claims the guest looks like a
# freshly flashed device an operator has just finished the manual key
# exchange on: the right files, at the right paths, at the right modes, and
# the stunmesh-go stand-in records what it is asked to do.
#
# Sourced by run.sh, which then calls every function named phase_*. Uses
# REPO_ROOT and CONTRIB_DIR (set by run.sh) to compare the guest's init and
# hotplug scripts against the real files in contrib/openwrt/, so a phase
# failure here means the injected copy actually drifted, not that this
# phase's own expectation is stale.
#
# This phase checks the VALUE of every option contrib/openwrt/README.md
# section 2 marks "Required: yes" -- namespace, node_id,
# controller_pubkey, private_key_file -- not just that uci can read it.
# "proxy" is deliberately left out: README.md section 2 marks it
# "Required: no", both scripts fall back to stunmesh-agent's own default
# proxy list when the section has none, and no other phase reads it from
# UCI either -- every fetch phase passes --proxy explicitly from the
# host-side FAKEPROXY_GUEST_URL/DELAYED_FAKEPROXY_GUEST_URL, so a wrong
# UCI proxy value would never be exercised by anything in this harness. A
# value assertion on an option nothing reads would test the injection
# code, not the payload's fitness for the scripts that consume it.
set -euo pipefail

phase_payload() {
	assert_ssh_output_contains "stunmesh-agent runs in the guest" \
		"/usr/sbin/stunmesh-agent --version" "stunmesh-agent"

	assert_ssh_ok "init script is installed and executable" \
		"test -x /etc/init.d/stunmesh-agent"
	assert_ssh_ok "hotplug script is installed and executable" \
		"test -x /etc/hotplug.d/iface/95-stunmesh-agent"

	local init_sha hotplug_sha
	init_sha=$(sha256sum "${CONTRIB_DIR}/stunmesh-agent.init" | awk '{print $1}')
	hotplug_sha=$(sha256sum "${CONTRIB_DIR}/hotplug-iface" | awk '{print $1}')
	assert_ssh_output_contains "init script is byte-identical to contrib/openwrt/stunmesh-agent.init" \
		"sha256sum /etc/init.d/stunmesh-agent" "$init_sha"
	assert_ssh_output_contains "hotplug script is byte-identical to contrib/openwrt/hotplug-iface" \
		"sha256sum /etc/hotplug.d/iface/95-stunmesh-agent" "$hotplug_sha"

	# BusyBox on this image has no "stat" applet; "ls -l"'s permission
	# string is always available and unambiguous for a plain file: owner
	# read+write, nothing else.
	assert_ssh_output_contains "identity key is mode 0600" \
		"ls -l /etc/stunmesh/provd/identity.key" "-rw-------"

	# The four options both shipped scripts refuse to run without
	# (contrib/openwrt/README.md section 2). A readable-but-wrong value
	# -- a swapped variable, a quoting bug in the heredoc that writes
	# this file -- would still pass a plain "is it set" check, so each
	# one is compared against the exact value run.sh injected, not just
	# probed for presence. controller_pubkey is a public key and
	# private_key_file is only a path, so neither is secret and both are
	# safe to print in a FAIL line.
	assert_ssh_output_contains "/etc/config/provd namespace matches what run.sh injected" \
		"uci -q get provd.main.namespace" "$E2E_NAMESPACE"
	assert_ssh_output_contains "/etc/config/provd node_id matches what run.sh injected" \
		"uci -q get provd.main.node_id" "$E2E_NODE_ID"
	assert_ssh_output_contains "/etc/config/provd controller_pubkey matches what run.sh injected" \
		"uci -q get provd.main.controller_pubkey" "$CONTROLLER_PUBKEY"
	assert_ssh_output_contains "/etc/config/provd private_key_file matches the identity key's guest path" \
		"uci -q get provd.main.private_key_file" "/etc/stunmesh/provd/identity.key"

	assert_ssh_ok "stunmesh stand-in runs and exits 0" \
		"/etc/init.d/stunmesh reload"
	assert_ssh_output_contains "stunmesh stand-in recorded the reload action" \
		"cat /tmp/stunmesh-stub-actions.log" "reload"
}
