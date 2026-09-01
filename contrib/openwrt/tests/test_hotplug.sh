#!/bin/sh
# test_hotplug.sh -- tests for contrib/openwrt/hotplug-iface.
#
# hotplug-iface is a straight-line script, not a set of functions: it
# runs from top to bottom the moment it is invoked. Its first two
# lines are the property that matters most (README.md sec 4): react
# only to ACTION=ifup on INTERFACE=wan, and do nothing -- exit 0,
# never touch anything -- for every other event OpenWrt's hotplug
# system fires. Those two guard lines run before the script ever
# touches /etc/init.d/stunmesh-agent, so the guard tests below run the
# real, unmodified script directly: no filtering needed.
#
# The dispatch tests filter one line (the $INIT path) to point at a
# fake /etc/init.d/stunmesh-agent stand-in this file writes, so the
# "only restart when running" logic can be exercised off an OpenWrt
# device (no real procd, no real "running" command). This proves
# hotplug-iface calls "running" before "restart" and never restarts a
# stopped/not-provisioned service; it does not prove OpenWrt's real
# rc.common "running" command behaves this way.

set -u

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HOTPLUG_SCRIPT="$SELF_DIR/../hotplug-iface"

. "$SELF_DIR/lib.sh"

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/stunmesh-hotplug-test.XXXXXX") || exit 1
trap 'rm -rf "$WORKDIR"' EXIT

INTERP="${TEST_HOTPLUG_INTERP:-sh}"

run_hotplug() {
	# $1 ACTION, $2 INTERFACE
	act="$1"
	iface="$2"
	ACTION="$act" INTERFACE="$iface" $INTERP "$HOTPLUG_SCRIPT"
}

test_ignores_ifdown() {
	run_hotplug ifdown wan
	assert_eq "$?" "0" "exit code for ACTION=ifdown"
}

test_ignores_ifupdate() {
	run_hotplug ifupdate wan
	assert_eq "$?" "0" "exit code for ACTION=ifupdate"
}

test_ignores_non_wan_interface() {
	run_hotplug ifup lan
	assert_eq "$?" "0" "exit code for INTERFACE=lan"
}

test_ignores_wan6() {
	run_hotplug ifup wan6
	assert_eq "$?" "0" "exit code for INTERFACE=wan6"
}

test_ignores_missing_action() {
	ACTION= INTERFACE=wan $INTERP "$HOTPLUG_SCRIPT"
	assert_eq "$?" "0" "exit code for empty ACTION"
}

# --- restart dispatch, with a fake /etc/init.d/stunmesh-agent ---------

dispatch_scratch() {
	d="$WORKDIR/d$TESTS_RUN"
	mkdir -p "$d"
	echo "$d"
}

# write_fake_init writes a fake init script to $1/stunmesh-agent whose
# "running" subcommand exits with $2 (0 = running, 1 = not running) and
# whose "restart" subcommand appends "restart" to $1/calls.
write_fake_init() {
	d="$1"
	running_rc="$2"
	cat > "$d/stunmesh-agent" <<EOF
#!/bin/sh
echo "\$1" >> "$d/calls"
case "\$1" in
	running) exit $running_rc ;;
	restart) exit 0 ;;
esac
exit 0
EOF
	chmod +x "$d/stunmesh-agent"
}

# run_hotplug_dispatch runs a filtered copy of hotplug-iface with
# $INIT pointed at the fake init script in d.
run_hotplug_dispatch() {
	d="$1"
	filtered="$d/hotplug-filtered"
	sed -e "s#^INIT=\"/etc/init.d/stunmesh-agent\"\$#INIT=\"$d/stunmesh-agent\"#" \
		"$HOTPLUG_SCRIPT" > "$filtered"
	chmod +x "$filtered"
	ACTION=ifup INTERFACE=wan $INTERP "$filtered"
}

test_restarts_when_running() {
	d=$(dispatch_scratch)
	write_fake_init "$d" 0

	run_hotplug_dispatch "$d"
	rc=$?

	assert_eq "$rc" "0" "exit code when service is running" || return 1
	[ -f "$d/calls" ] || { echo "  init script was never invoked" >&2; return 1; }
	calls=$(tr '\n' ' ' < "$d/calls" | sed 's/ $//')
	assert_eq "$calls" "running restart" "call sequence when running"
}

test_does_not_restart_when_not_running() {
	d=$(dispatch_scratch)
	write_fake_init "$d" 1

	run_hotplug_dispatch "$d"
	rc=$?

	assert_eq "$rc" "0" "exit code when service is not running" || return 1
	calls=$(tr '\n' ' ' < "$d/calls" 2>/dev/null | sed 's/ $//')
	assert_eq "$calls" "running" "call sequence when not running (no restart)"
}

test_does_nothing_when_init_missing() {
	d=$(dispatch_scratch)
	# No fake init script written at all: $INIT is not executable.
	filtered="$d/hotplug-filtered"
	sed -e "s#^INIT=\"/etc/init.d/stunmesh-agent\"\$#INIT=\"$d/stunmesh-agent\"#" \
		"$HOTPLUG_SCRIPT" > "$filtered"
	chmod +x "$filtered"

	rc=$(ACTION=ifup INTERFACE=wan $INTERP "$filtered"; echo $?)
	assert_eq "$rc" "0" "exit code when init script does not exist" || return 1
	[ -f "$d/calls" ] && { echo "  init script was somehow invoked" >&2; return 1; }
	return 0
}

run_test "hotplug-iface: ignores ACTION=ifdown" test_ignores_ifdown
run_test "hotplug-iface: ignores ACTION=ifupdate" test_ignores_ifupdate
run_test "hotplug-iface: ignores INTERFACE=lan" test_ignores_non_wan_interface
run_test "hotplug-iface: ignores INTERFACE=wan6" test_ignores_wan6
run_test "hotplug-iface: ignores empty ACTION" test_ignores_missing_action
run_test "hotplug-iface: restarts stunmesh-agent when it is running" test_restarts_when_running
run_test "hotplug-iface: does not restart a stopped service" test_does_not_restart_when_not_running
run_test "hotplug-iface: does nothing when the init script is missing" test_does_nothing_when_init_missing

report_and_exit
