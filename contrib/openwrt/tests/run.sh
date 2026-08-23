#!/bin/sh
# run.sh -- runs every contrib/openwrt shell test under every
# interpreter available that approximates the scripts' target dialect
# (contrib/openwrt/README.md sec 5: BusyBox ash, no bashisms).
#
# It always runs under "sh" -- dash on Debian/Ubuntu, including the
# GitHub Actions ubuntu-latest runner this project's CI uses, since
# dash is close to the POSIX subset these scripts are written in.
#
# It also runs under "busybox ash" when a busybox binary is on PATH,
# since that is the actual interpreter these scripts run under on an
# OpenWrt device. When busybox is not installed -- true for a stock
# ubuntu-latest runner -- that pass is skipped with a message, and
# only the sh (dash) pass runs.
#
# Neither pass proves BusyBox utility *behaviour* (its awk, sed,
# mktemp, etc. are separate from bash/coreutils and can differ in
# edge cases); it proves the scripts' own control flow and shell
# syntax under an ash-family shell. See contrib/openwrt/README.md for
# the full statement of what these tests do and do not cover.

set -u

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
status=0

run_pass() {
	label="$1"
	shift
	echo "=== running contrib/openwrt tests under: $label ==="
	# test_hotplug.sh shells out to run hotplug-iface itself; tell it
	# which interpreter to use so that sub-invocation matches this
	# pass too, not just the test file's own interpreter.
	TEST_HOTPLUG_INTERP="$*"
	export TEST_HOTPLUG_INTERP
	for t in "$SELF_DIR"/test_*.sh; do
		echo "--- $t ---"
		if "$@" "$t"; then
			:
		else
			status=1
		fi
	done
}

run_pass "sh" sh

if command -v busybox >/dev/null 2>&1; then
	run_pass "busybox ash" busybox ash
else
	echo "busybox not found on PATH: skipping the busybox-ash pass." >&2
	echo "The sh (dash) pass above still ran, but proves nothing about BusyBox-specific behaviour." >&2
fi

exit "$status"
