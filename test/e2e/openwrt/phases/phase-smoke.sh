#!/usr/bin/env bash
# phase-smoke.sh -- placeholder phase proving the harness skeleton works.
#
# This is NOT a stunmesh-agent test. It injects no payload and checks no
# bundle; it only claims two things about a freshly booted, unmodified
# guest: ubus answers, and uci show network names the lan interface (the
# lan section this harness's own injection wrote before boot). A later item
# replaces this file with the real stunmesh-agent assertions; this one
# exists only to prove boot -> inject -> SSH -> assert works end to end.
#
# Sourced by run.sh, which then calls every function named phase_*.
set -euo pipefail

phase_smoke() {
	assert_ssh_ok "ubus answers" "ubus list"
	assert_ssh_output_contains "uci show network names the lan interface" \
		"uci show network" "network.lan"
}
