#!/bin/sh
# test_hotplug.sh -- tests for contrib/openwrt/hotplug-iface.
#
# hotplug-iface is a straight-line script, not a set of functions: it
# runs from top to bottom the moment it is invoked. Its first two
# lines are the property that matters most (README.md sec 4): react
# only to ACTION=ifup on INTERFACE=wan, and do nothing -- exit 0,
# never touch the network stack or the config -- for every other
# event OpenWrt's hotplug system fires. Those two guard lines run
# before the script ever sources /lib/functions.sh, so the guard
# tests below run the real, unmodified script directly: no filtering
# needed, unlike test_init.sh.
#
# What this file does not prove: the ACTION=ifup/INTERFACE=wan path
# itself sources /lib/functions.sh (OpenWrt's UCI shell library) to
# read /etc/config/provd. That library does not exist off an OpenWrt
# device, so exercising the full read-config-and-fetch path needs a
# stand-in for it; see test_hotplug_dispatch below, which supplies a
# minimal fake config_load/config_get pair sufficient to check the
# argument-building and dispatch logic, not real UCI parsing.

set -u

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HOTPLUG_SCRIPT="$SELF_DIR/../hotplug-iface"

. "$SELF_DIR/lib.sh"

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/stunmesh-hotplug-test.XXXXXX") || exit 1
trap 'rm -rf "$WORKDIR"' EXIT

INTERP="${TEST_HOTPLUG_INTERP:-sh}"

run_hotplug() {
	# $1 ACTION, $2 INTERFACE, remaining args passed through as-is.
	act="$1"
	iface="$2"
	shift 2
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

# --- full dispatch path, with a fake UCI library -----------------------
#
# This section stands in a fake /lib/functions.sh-equivalent so the
# ACTION=ifup/INTERFACE=wan path can run at all off an OpenWrt device.
# config_load/config_get here are a deliberately narrow stand-in: they
# understand only the "option"/"list" lines this test writes, not real
# UCI syntax. They prove hotplug-iface reads the right option names,
# builds the right --proxy repeats, and both invokes and skips $BIN
# correctly -- not that OpenWrt's real config_load/config_get behave
# this way, which is out of scope for a test that runs off-device.

dispatch_scratch() {
	d="$WORKDIR/d$TESTS_RUN"
	mkdir -p "$d/lib" "$d/bin"
	echo "$d"
}

# write_fake_uci_lib writes a fake /lib/functions.sh into $1/lib that
# reads UCI-style "option"/"list" lines from the file named by
# $UCI_CONFIG_FILE (set by each test before running hotplug-iface).
write_fake_uci_lib() {
	d="$1"
	cat > "$d/lib/functions.sh" <<'EOF'
config_load() {
	[ -n "${UCI_CONFIG_FILE:-}" ] && [ -f "$UCI_CONFIG_FILE" ]
}
config_get() {
	varname="$1"
	optname="$3"
	def="${4:-}"
	val=$(awk -v opt="$optname" '
		($1 == "option" || $1 == "list") && $2 == opt { print $3; found=1 }
		END { if (!found) exit 1 }
	' "$UCI_CONFIG_FILE" | tr '\n' ' ' | sed 's/ $//')
	if [ -z "$val" ]; then
		val="$def"
	fi
	eval "$varname=\"\$val\""
}
EOF
}

# run_hotplug_dispatch runs a filtered copy of hotplug-iface that
# sources the fake UCI lib above instead of the real, absent one, and
# that resolves $BIN to a fake, recording binary instead of the real
# /usr/sbin/stunmesh-agent.
run_hotplug_dispatch() {
	d="$1"
	fake_lib="$d/lib/functions.sh"
	fake_bin="$d/bin/stunmesh-agent"
	filtered="$d/hotplug-filtered"

	sed \
		-e "s#^\. /lib/functions\.sh\$#. $fake_lib#" \
		-e "s#^BIN=\"/usr/sbin/stunmesh-agent\"\$#BIN=\"$fake_bin\"#" \
		"$HOTPLUG_SCRIPT" > "$filtered"
	chmod +x "$filtered"

	ACTION=ifup INTERFACE=wan $INTERP "$filtered"
}

test_hotplug_dispatch_builds_expected_args() {
	d=$(dispatch_scratch)
	write_fake_uci_lib "$d"
	fake_bin="$d/bin/stunmesh-agent"
	record="$d/bin/invoked-with"
	cat > "$fake_bin" <<EOF
#!/bin/sh
echo "\$@" > "$record"
exit 0
EOF
	chmod +x "$fake_bin"

	UCI_CONFIG_FILE="$d/provd.conf"
	cat > "$UCI_CONFIG_FILE" <<'EOF'
option namespace mymesh
option node_id alpha
option controller_pubkey pk123
option private_key_file /etc/stunmesh/provd/identity.key
list proxy https://dhtproxy2.jami.net
list proxy https://dhtproxy3.jami.net
EOF

	UCI_CONFIG_FILE="$UCI_CONFIG_FILE" run_hotplug_dispatch "$d"
	rc=$?

	assert_eq "$rc" "0" "hotplug-iface exit code on full dispatch" || return 1
	[ -f "$record" ] || { echo "  \$BIN was never invoked" >&2; return 1; }
	invoked=$(cat "$record")
	expected="fetch --namespace mymesh --node-id alpha --controller-pubkey pk123 --identity-key /etc/stunmesh/provd/identity.key --lock /var/lock/stunmesh-agent.lock --proxy https://dhtproxy2.jami.net --proxy https://dhtproxy3.jami.net"
	assert_eq "$invoked" "$expected" "arguments passed to \$BIN"
}

test_hotplug_dispatch_skips_incomplete_config() {
	d=$(dispatch_scratch)
	write_fake_uci_lib "$d"
	fake_bin="$d/bin/stunmesh-agent"
	record="$d/bin/invoked-with"
	cat > "$fake_bin" <<EOF
#!/bin/sh
echo "\$@" > "$record"
exit 0
EOF
	chmod +x "$fake_bin"

	UCI_CONFIG_FILE="$d/provd.conf"
	cat > "$UCI_CONFIG_FILE" <<'EOF'
option namespace mymesh
option node_id alpha
EOF

	UCI_CONFIG_FILE="$UCI_CONFIG_FILE" run_hotplug_dispatch "$d"
	rc=$?

	assert_eq "$rc" "0" "hotplug-iface exit code on incomplete config" || return 1
	[ -f "$record" ] && { echo "  \$BIN was invoked despite incomplete config" >&2; return 1; }
	return 0
}

run_test "hotplug-iface: ignores ACTION=ifdown" test_ignores_ifdown
run_test "hotplug-iface: ignores ACTION=ifupdate" test_ignores_ifupdate
run_test "hotplug-iface: ignores INTERFACE=lan" test_ignores_non_wan_interface
run_test "hotplug-iface: ignores INTERFACE=wan6" test_ignores_wan6
run_test "hotplug-iface: ignores empty ACTION" test_ignores_missing_action
run_test "hotplug-iface: builds expected fetch args and invokes \$BIN" test_hotplug_dispatch_builds_expected_args
run_test "hotplug-iface: skips \$BIN when config is incomplete" test_hotplug_dispatch_skips_incomplete_config

report_and_exit
