#!/bin/sh
# test_init.sh -- tests for contrib/openwrt/stunmesh-agent.init: the
# cron-management functions (remove_cron, install_cron, stop_service)
# and the fetch-invocation functions (build_fetch_args, read_config,
# run_fetch, start_service).
#
# How the functions under test are loaded:
#
# stunmesh-agent.init starts with ". /lib/functions.sh" at its top
# level, to pull in OpenWrt's UCI helpers (config_load/config_get).
# Those helpers do not exist off an OpenWrt device, so sourcing the
# file as-is aborts here before any function is even defined (BusyBox
# ash and dash both treat a failed "." on a missing file as fatal). So
# this file sources a filtered copy of the real script with just that
# one line removed. Every function body below is the real, unmodified
# script text; only the UCI-loading line is skipped.
#
# read_config and (through it) start_service do call config_load and
# config_get, which the filtered copy above no longer provides. Rather
# than invent a second technique, this file reuses test_hotplug.sh's:
# fake_uci_config_load/fake_uci_config_get, defined below, stand in
# for OpenWrt's real UCI helpers. They understand only the
# "option"/"list" line shapes this file writes to $UCI_CONFIG_FILE,
# not real UCI syntax -- see test_hotplug.sh's write_fake_uci_lib for
# the same scope note. They are installed with "stub" (below), the
# same mechanism used for mktemp/cp/mv/awk/mkdir.
#
# CRONTAB is reassigned per test to a scratch file, the same way a
# caller would point the script at a different crontab; the script's
# own logic is never edited.
#
# One real side effect cannot be avoided without editing the script:
# install_cron and remove_cron both call "/etc/init.d/cron reload" by
# its absolute path, so it cannot be intercepted the way
# mktemp/cp/mv/awk/mkdir are below (a shell function only shadows a
# bare command name; a path containing "/" is always executed
# directly, function or no function -- see the "stub" comment below).
# On a host that has that path (this dev machine does), it harmlessly
# reloads the real system cron daemon's already-unrelated config; on a
# host that does not (most CI runners), the shell reports "not found"
# on stderr, which the script already redirects to /dev/null, and its
# exit status is never checked. Neither case touches this test's
# scratch crontab files.

set -u

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INIT_SCRIPT="$SELF_DIR/../stunmesh-agent.init"

. "$SELF_DIR/lib.sh"

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/stunmesh-init-test.XXXXXX") || exit 1
trap 'rm -rf "$WORKDIR"' EXIT

FILTERED="$WORKDIR/init-filtered.sh"
grep -vF '. /lib/functions.sh' "$INIT_SCRIPT" > "$FILTERED"
. "$FILTERED"

# scratch_dir returns a fresh, empty directory for the current test.
scratch_dir() {
	d="$WORKDIR/t$TESTS_RUN"
	mkdir -p "$d"
	echo "$d"
}

# stub overrides the command named $1 with a shell function whose body
# is $2, for the rest of the current test's subshell (run_test already
# runs every test in "( "$fn" )", so the function never leaks into the
# next test).
#
# This used to install a fake executable ahead of the real one on
# PATH. That does not work under a BusyBox ash built with the
# standalone-shell feature (CONFIG_FEATURE_SH_STANDALONE): with it
# enabled, ash resolves applet names like mktemp/cp/awk/mv/mkdir
# internally and never consults PATH at all, so a PATH stub is
# silently bypassed and the real applet runs instead -- see the note
# at the top of this file for how that was diagnosed. A shell function
# does not have this problem: POSIX's command lookup order is special
# builtins, then functions, then everything else (regular builtins and
# PATH, and -- for BusyBox -- its internal applet dispatch too), so a
# function always shadows the command whether or not the shell honors
# PATH for it. This has been verified directly: `busybox ash -c
# 'mkdir() { ...; }; mkdir -p /etc/...'` runs the function even though
# `mkdir` is a BusyBox-internal applet with no separate file on PATH
# at all -- there is no PATH lookup for the function-override path to
# bypass in the first place.
#
# Body must use "return", not "exit": most of these commands are
# called directly (not inside a command substitution), and "exit"
# inside a function called directly would exit the whole test
# subshell instead of just failing that one command.
stub() {
	cmdname="$1"
	body="$2"
	eval "
$cmdname() {
	$body
}
"
}

# fake_uci_config_load / fake_uci_config_get stand in for OpenWrt's real
# config_load/config_get (normally pulled in by ". /lib/functions.sh",
# filtered out above) so read_config and start_service can be exercised
# off-device. They read only from $UCI_CONFIG_FILE, using the same
# narrow "option"/"list" parsing as test_hotplug.sh's write_fake_uci_lib.
# install_fake_uci installs both via "stub", so they are scoped to the
# current test's subshell like every other stubbed command.
#
# The awk logic lives in its own file (written once, below) rather
# than inline in the stubbed body: "stub" already routes the body
# through one "eval", and nesting a quote-heavy awk program inside
# that would need a second, error-prone layer of backslash-escaping.
# A real file sidesteps that entirely -- "awk -f" needs no embedded
# quoting at all.
FAKE_CONFIG_GET_AWK="$WORKDIR/fake-config-get.awk"
cat > "$FAKE_CONFIG_GET_AWK" <<'EOF'
($1 == "option" || $1 == "list") && $2 == opt { print $3; found=1 }
END { if (!found) exit 1 }
EOF

fake_uci_config_load_body='[ -n "${UCI_CONFIG_FILE:-}" ] && [ -f "$UCI_CONFIG_FILE" ]'
fake_uci_config_get_body='
	varname="$1"
	optname="$3"
	def="${4:-}"
	val=$(awk -v opt="$optname" -f "$FAKE_CONFIG_GET_AWK" "$UCI_CONFIG_FILE" | tr "\n" " " | sed "s/ $//")
	if [ -z "$val" ]; then
		val="$def"
	fi
	eval "$varname=\"\$val\""
'
install_fake_uci() {
	stub config_load "$fake_uci_config_load_body"
	stub config_get "$fake_uci_config_get_body"
}

# --- remove_cron -----------------------------------------------------

test_remove_cron_missing_crontab() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"

	remove_cron
	rc=$?

	assert_eq "$rc" "0" "remove_cron rc on missing crontab" || return 1
	[ ! -e "$CRONTAB" ] || { echo "  remove_cron created a crontab that did not exist" >&2; return 1; }
	assert_no_stray_temp "$d" "crontab"
}

test_remove_cron_keeps_other_entries_and_mode() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	printf '%s\n%s\n' \
		"* * * * * /usr/bin/other-thing" \
		"*/5 * * * * /usr/sbin/stunmesh-agent fetch $CRON_TAG" \
		> "$CRONTAB"
	chmod 640 "$CRONTAB"
	before_mode=$(stat -c %a "$CRONTAB")

	remove_cron
	rc=$?

	assert_eq "$rc" "0" "remove_cron rc" || return 1
	grep -qF "$CRON_TAG" "$CRONTAB" && { echo "  managed line still present" >&2; return 1; }
	grep -qF "other-thing" "$CRONTAB" || { echo "  unrelated line was lost" >&2; return 1; }
	after_mode=$(stat -c %a "$CRONTAB")
	assert_eq "$after_mode" "$before_mode" "crontab file mode preserved" || return 1
	assert_no_stray_temp "$d" "crontab"
}

test_remove_cron_unreadable_crontab() {
	if [ "$(id -u)" = "0" ]; then
		echo "  skipped: running as root, permission bits do not block reads" >&2
		return 0
	fi

	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	printf '%s\n' "*/5 * * * * /usr/sbin/stunmesh-agent fetch $CRON_TAG" > "$CRONTAB"
	chmod 000 "$CRONTAB"
	before_size=$(stat -c %s "$CRONTAB")

	remove_cron
	rc=$?

	assert_eq "$rc" "1" "remove_cron rc on unreadable crontab" || return 1
	after_size=$(stat -c %s "$CRONTAB")
	after_mode=$(stat -c %a "$CRONTAB")
	assert_eq "$after_mode" "0" "crontab mode untouched" || return 1
	assert_eq "$after_size" "$before_size" "crontab content untouched" || return 1
	assert_no_stray_temp "$d" "crontab"
}

test_remove_cron_temp_file_create_failure() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	printf '%s\n' "*/5 * * * * /usr/sbin/stunmesh-agent fetch $CRON_TAG" > "$CRONTAB"
	original=$(cat "$CRONTAB")
	stub mktemp 'return 1'

	remove_cron
	rc=$?

	assert_eq "$rc" "1" "remove_cron rc when mktemp fails" || return 1
	current=$(cat "$CRONTAB")
	assert_eq "$current" "$original" "crontab untouched when mktemp fails" || return 1
	assert_no_stray_temp "$d" "crontab"
}

test_remove_cron_temp_file_write_failure() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	printf '%s\n' "*/5 * * * * /usr/sbin/stunmesh-agent fetch $CRON_TAG" > "$CRONTAB"
	original=$(cat "$CRONTAB")
	# cp succeeds (real cp); awk -- the step that writes the filtered
	# content into the temp file -- fails.
	stub awk 'return 1'

	remove_cron
	rc=$?

	assert_eq "$rc" "1" "remove_cron rc when awk fails" || return 1
	current=$(cat "$CRONTAB")
	assert_eq "$current" "$original" "crontab untouched when awk fails" || return 1
	assert_no_stray_temp "$d" "crontab"
}

test_remove_cron_copy_failure() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	printf '%s\n' "*/5 * * * * /usr/sbin/stunmesh-agent fetch $CRON_TAG" > "$CRONTAB"
	original=$(cat "$CRONTAB")
	stub cp 'return 1'

	remove_cron
	rc=$?

	assert_eq "$rc" "1" "remove_cron rc when cp fails" || return 1
	current=$(cat "$CRONTAB")
	assert_eq "$current" "$original" "crontab untouched when cp fails" || return 1
	assert_no_stray_temp "$d" "crontab"
}

test_remove_cron_rename_failure() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	printf '%s\n' "*/5 * * * * /usr/sbin/stunmesh-agent fetch $CRON_TAG" > "$CRONTAB"
	original=$(cat "$CRONTAB")
	stub mv 'return 1'

	remove_cron
	rc=$?

	assert_eq "$rc" "1" "remove_cron rc when mv fails" || return 1
	current=$(cat "$CRONTAB")
	assert_eq "$current" "$original" "crontab untouched when mv fails" || return 1
	assert_no_stray_temp "$d" "crontab"
}

# --- install_cron ------------------------------------------------------

test_install_cron_writes_expected_line() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	BIN="/usr/sbin/stunmesh-agent"
	args="fetch --namespace test --node-id n1"
	fetch_interval=7
	stub mkdir 'return 0'

	install_cron
	rc=$?

	assert_eq "$rc" "0" "install_cron rc" || return 1
	expected="*/7 * * * * $BIN $args >/dev/null 2>&1 $CRON_TAG"
	actual=$(cat "$CRONTAB")
	assert_eq "$actual" "$expected" "installed cron line" || return 1
	assert_no_stray_temp "$d" "crontab"
}

test_install_cron_repeated_start_no_duplicates() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	BIN="/usr/sbin/stunmesh-agent"
	args="fetch --namespace test"
	fetch_interval=5
	stub mkdir 'return 0'

	install_cron >/dev/null
	rc1=$?
	install_cron >/dev/null
	rc2=$?
	install_cron >/dev/null
	rc3=$?

	assert_eq "$rc1" "0" "1st install_cron rc" || return 1
	assert_eq "$rc2" "0" "2nd install_cron rc" || return 1
	assert_eq "$rc3" "0" "3rd install_cron rc" || return 1
	count=$(grep -cF "$CRON_TAG" "$CRONTAB")
	assert_eq "$count" "1" "managed lines after three starts" || return 1
	lines=$(wc -l < "$CRONTAB")
	assert_eq "$lines" "1" "total crontab lines after three starts" || return 1
	assert_no_stray_temp "$d" "crontab"
}

test_install_cron_returns_1_when_removal_unconfirmed() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	printf '%s\n' "*/5 * * * * /usr/sbin/stunmesh-agent fetch $CRON_TAG" > "$CRONTAB"
	original=$(cat "$CRONTAB")
	BIN="/usr/sbin/stunmesh-agent"
	args="fetch --namespace test"
	fetch_interval=5
	stub mktemp 'return 1'

	install_cron
	rc=$?

	assert_eq "$rc" "1" "install_cron rc when remove_cron cannot confirm removal" || return 1
	current=$(cat "$CRONTAB")
	assert_eq "$current" "$original" "crontab untouched when install_cron bails out" || return 1
	assert_no_stray_temp "$d" "crontab"
}

# --- stop_service --------------------------------------------------------

test_stop_service_leaves_no_managed_line() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	printf '%s\n%s\n' \
		"* * * * * /usr/bin/other-thing" \
		"*/5 * * * * /usr/sbin/stunmesh-agent fetch $CRON_TAG" \
		> "$CRONTAB"

	stop_service
	rc=$?

	assert_eq "$rc" "0" "stop_service rc" || return 1
	grep -qF "$CRON_TAG" "$CRONTAB" && { echo "  managed line survived stop_service" >&2; return 1; }
	grep -qF "other-thing" "$CRONTAB" || { echo "  unrelated line was lost by stop_service" >&2; return 1; }
	assert_no_stray_temp "$d" "crontab"
}

test_stop_service_returns_1_when_removal_unconfirmed() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	printf '%s\n' "*/5 * * * * /usr/sbin/stunmesh-agent fetch $CRON_TAG" > "$CRONTAB"
	original=$(cat "$CRONTAB")
	stub mv 'return 1'

	stop_service
	rc=$?

	assert_eq "$rc" "1" "stop_service rc when remove_cron cannot confirm removal" || return 1
	current=$(cat "$CRONTAB")
	assert_eq "$current" "$original" "crontab untouched when stop_service cannot confirm removal" || return 1
	assert_no_stray_temp "$d" "crontab"
}

# --- build_fetch_args ----------------------------------------------------
#
# Pins the exact "fetch"-and-flags argument list PLAN.md section 3
# requires, so a renamed/dropped/reordered flag or a broken proxy loop
# fails the test instead of shipping silently.

test_build_fetch_args_full_option_set() {
	namespace="mymesh-7f3a"
	node_id="alpha"
	controller_pubkey="pk123"
	private_key_file="/etc/stunmesh/provd/identity.key"
	lock_file="/var/lock/stunmesh-agent.lock"
	proxies="https://dhtproxy2.jami.net https://dhtproxy3.jami.net"

	args="$(build_fetch_args)"

	expected="fetch --namespace mymesh-7f3a --node-id alpha --controller-pubkey pk123 --identity-key /etc/stunmesh/provd/identity.key --lock /var/lock/stunmesh-agent.lock --proxy https://dhtproxy2.jami.net --proxy https://dhtproxy3.jami.net"
	assert_eq "$args" "$expected" "build_fetch_args output with every option set and two proxies"
}

test_build_fetch_args_no_proxies() {
	namespace="mymesh-7f3a"
	node_id="alpha"
	controller_pubkey="pk123"
	private_key_file="/etc/stunmesh/provd/identity.key"
	lock_file="/var/lock/stunmesh-agent.lock"
	proxies=""

	args="$(build_fetch_args)"

	expected="fetch --namespace mymesh-7f3a --node-id alpha --controller-pubkey pk123 --identity-key /etc/stunmesh/provd/identity.key --lock /var/lock/stunmesh-agent.lock"
	assert_eq "$args" "$expected" "build_fetch_args emits no --proxy flags when the section has none"
}

# --- read_config -----------------------------------------------------------

test_read_config_missing_file() {
	d=$(scratch_dir)
	UCI_CONFIG_FILE="$d/provd.conf"
	install_fake_uci

	read_config
	rc=$?

	assert_eq "$rc" "1" "read_config rc when /etc/config/provd is missing"
}

test_read_config_missing_required_field() {
	d=$(scratch_dir)
	UCI_CONFIG_FILE="$d/provd.conf"
	cat > "$UCI_CONFIG_FILE" <<'EOF'
option namespace mymesh
option node_id alpha
option private_key_file /etc/stunmesh/provd/identity.key
EOF
	install_fake_uci

	read_config
	rc=$?

	assert_eq "$rc" "1" "read_config rc when controller_pubkey is missing"
}

test_read_config_applies_defaults() {
	d=$(scratch_dir)
	UCI_CONFIG_FILE="$d/provd.conf"
	cat > "$UCI_CONFIG_FILE" <<'EOF'
option namespace mymesh
option node_id alpha
option controller_pubkey pk123
option private_key_file /etc/stunmesh/provd/identity.key
EOF
	install_fake_uci

	read_config
	rc=$?

	assert_eq "$rc" "0" "read_config rc on a complete minimal config" || return 1
	assert_eq "$boot_delay" "$DEFAULT_BOOT_DELAY" "boot_delay falls back to its default" || return 1
	assert_eq "$fetch_interval" "$DEFAULT_FETCH_INTERVAL" "fetch_interval falls back to its default" || return 1
	assert_eq "$lock_file" "$DEFAULT_LOCK_FILE" "lock_file falls back to its default" || return 1
	assert_eq "$proxies" "" "proxies is empty when the section has no proxy entries"
}

test_read_config_reads_all_fields() {
	d=$(scratch_dir)
	UCI_CONFIG_FILE="$d/provd.conf"
	cat > "$UCI_CONFIG_FILE" <<'EOF'
option namespace mymesh-7f3a
option node_id alpha
option controller_pubkey pk123
list proxy https://dhtproxy2.jami.net
list proxy https://dhtproxy3.jami.net
option private_key_file /etc/stunmesh/provd/identity.key
option boot_delay 30
option fetch_interval 10
option lock_file /tmp/custom.lock
EOF
	install_fake_uci

	read_config
	rc=$?

	assert_eq "$rc" "0" "read_config rc on a fully populated config" || return 1
	assert_eq "$namespace" "mymesh-7f3a" "namespace" || return 1
	assert_eq "$node_id" "alpha" "node_id" || return 1
	assert_eq "$controller_pubkey" "pk123" "controller_pubkey" || return 1
	assert_eq "$private_key_file" "/etc/stunmesh/provd/identity.key" "private_key_file" || return 1
	assert_eq "$proxies" "https://dhtproxy2.jami.net https://dhtproxy3.jami.net" "proxies" || return 1
	assert_eq "$boot_delay" "30" "boot_delay" || return 1
	assert_eq "$fetch_interval" "10" "fetch_interval" || return 1
	assert_eq "$lock_file" "/tmp/custom.lock" "lock_file"
}

# --- run_fetch -------------------------------------------------------------
#
# PLAN.md section 5: exit 0 (applied) and exit 3 (no change) are both
# success for the caller; run_fetch always returns 0 so cron/hotplug
# retry on their own schedule instead of treating a failed fetch as an
# init-script failure. Pins the log line for each case, so a mis-mapped
# exit code is caught even though the return code alone would not show
# it.

fake_bin_exiting() {
	# $1 destination path, $2 exit code.
	cat > "$1" <<EOF
#!/bin/sh
exit $2
EOF
	chmod +x "$1"
}

test_run_fetch_exit_0_logs_applied() {
	d=$(scratch_dir)
	fake_bin_exiting "$d/stunmesh-agent" 0
	BIN="$d/stunmesh-agent"
	args="fetch --namespace test"
	logfile="$d/log"
	stub log "echo \"\$1\" >> \"$logfile\""

	run_fetch
	rc=$?

	assert_eq "$rc" "0" "run_fetch returns 0 when the fetch applied" || return 1
	assert_eq "$(cat "$logfile")" "fetch applied" "log line for exit code 0"
}

test_run_fetch_exit_3_logs_no_change_and_succeeds() {
	d=$(scratch_dir)
	fake_bin_exiting "$d/stunmesh-agent" 3
	BIN="$d/stunmesh-agent"
	args="fetch --namespace test"
	logfile="$d/log"
	stub log "echo \"\$1\" >> \"$logfile\""

	run_fetch
	rc=$?

	assert_eq "$rc" "0" "run_fetch treats exit 3 (no change) as success, not failure" || return 1
	assert_eq "$(cat "$logfile")" "fetch: no change" "log line for exit code 3"
}

test_run_fetch_exit_failure_logs_error() {
	d=$(scratch_dir)
	fake_bin_exiting "$d/stunmesh-agent" 7
	BIN="$d/stunmesh-agent"
	args="fetch --namespace test"
	logfile="$d/log"
	stub log "echo \"\$1\" >> \"$logfile\""

	run_fetch
	rc=$?

	assert_eq "$rc" "0" "run_fetch still returns 0 on a failing fetch (caller retries later)" || return 1
	assert_eq "$(cat "$logfile")" "fetch failed, exit code 7" "log line for a failing exit code"
}

# --- start_service (integration) --------------------------------------------
#
# Ties read_config, build_fetch_args, and run_fetch together through
# start_service, the way the real config -> args -> invocation path
# actually runs, rather than only exercising each function alone.
# Reuses test_hotplug.sh's technique: a fake UCI library (here,
# install_fake_uci) and a fake $BIN that records how it was called.

test_start_service_builds_args_runs_fetch_and_installs_cron() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	UCI_CONFIG_FILE="$d/provd.conf"
	cat > "$UCI_CONFIG_FILE" <<'EOF'
option namespace mymesh-7f3a
option node_id alpha
option controller_pubkey pk123
list proxy https://dhtproxy2.jami.net
list proxy https://dhtproxy3.jami.net
option private_key_file /etc/stunmesh/provd/identity.key
option lock_file /var/lock/stunmesh-agent.lock
EOF
	install_fake_uci

	record="$d/invoked-with"
	cat > "$d/stunmesh-agent" <<EOF
#!/bin/sh
echo "\$@" > "$record"
exit 0
EOF
	chmod +x "$d/stunmesh-agent"
	BIN="$d/stunmesh-agent"
	boot_delay=0
	fetch_interval=5
	stub mkdir 'return 0'

	start_service
	rc=$?
	wait

	assert_eq "$rc" "0" "start_service rc" || return 1
	[ -f "$record" ] || { echo "  \$BIN was never invoked by the boot-time fetch" >&2; return 1; }
	invoked=$(cat "$record")
	expected="fetch --namespace mymesh-7f3a --node-id alpha --controller-pubkey pk123 --identity-key /etc/stunmesh/provd/identity.key --lock /var/lock/stunmesh-agent.lock --proxy https://dhtproxy2.jami.net --proxy https://dhtproxy3.jami.net"
	assert_eq "$invoked" "$expected" "arguments passed to \$BIN by the boot-time fetch" || return 1
	expected_cron="*/5 * * * * $BIN $expected >/dev/null 2>&1 $CRON_TAG"
	assert_eq "$(cat "$CRONTAB")" "$expected_cron" "installed cron line matches the args built from config"
}

test_start_service_skips_when_config_incomplete() {
	d=$(scratch_dir)
	CRONTAB="$d/crontab"
	UCI_CONFIG_FILE="$d/provd.conf"
	printf '%s\n' "option namespace mymesh-7f3a" > "$UCI_CONFIG_FILE"
	install_fake_uci

	record="$d/invoked-with"
	cat > "$d/stunmesh-agent" <<EOF
#!/bin/sh
echo "\$@" > "$record"
exit 0
EOF
	chmod +x "$d/stunmesh-agent"
	BIN="$d/stunmesh-agent"
	boot_delay=0
	fetch_interval=5

	start_service
	rc=$?
	wait

	assert_eq "$rc" "0" "start_service rc when config is incomplete" || return 1
	[ -f "$record" ] && { echo "  \$BIN was invoked despite incomplete config" >&2; return 1; }
	[ -f "$CRONTAB" ] && { echo "  a cron line was installed despite incomplete config" >&2; return 1; }
	return 0
}

run_test "remove_cron: missing crontab is a no-op success" test_remove_cron_missing_crontab
run_test "remove_cron: keeps other entries and file mode" test_remove_cron_keeps_other_entries_and_mode
run_test "remove_cron: unreadable crontab fails without touching it" test_remove_cron_unreadable_crontab
run_test "remove_cron: mktemp failure fails without touching crontab" test_remove_cron_temp_file_create_failure
run_test "remove_cron: awk failure fails without touching crontab" test_remove_cron_temp_file_write_failure
run_test "remove_cron: cp failure fails without touching crontab" test_remove_cron_copy_failure
run_test "remove_cron: mv failure fails without touching crontab" test_remove_cron_rename_failure
run_test "install_cron: writes the expected cron line" test_install_cron_writes_expected_line
run_test "install_cron: repeated start does not duplicate the line" test_install_cron_repeated_start_no_duplicates
run_test "install_cron: returns 1 when removal cannot be confirmed" test_install_cron_returns_1_when_removal_unconfirmed
run_test "stop_service: leaves no managed line" test_stop_service_leaves_no_managed_line
run_test "stop_service: returns 1 when removal cannot be confirmed" test_stop_service_returns_1_when_removal_unconfirmed
run_test "build_fetch_args: full option set, exact argument list" test_build_fetch_args_full_option_set
run_test "build_fetch_args: no --proxy flags when none configured" test_build_fetch_args_no_proxies
run_test "read_config: rc 1 when /etc/config/provd is missing" test_read_config_missing_file
run_test "read_config: rc 1 when a required field is missing" test_read_config_missing_required_field
run_test "read_config: applies boot_delay/fetch_interval/lock_file defaults" test_read_config_applies_defaults
run_test "read_config: reads every field from a full config" test_read_config_reads_all_fields
run_test "run_fetch: exit 0 logs applied and returns 0" test_run_fetch_exit_0_logs_applied
run_test "run_fetch: exit 3 logs no-change and returns 0 (success)" test_run_fetch_exit_3_logs_no_change_and_succeeds
run_test "run_fetch: other exit code logs failure and still returns 0" test_run_fetch_exit_failure_logs_error
run_test "start_service: builds args, runs fetch, and installs cron" test_start_service_builds_args_runs_fetch_and_installs_cron
run_test "start_service: skips fetch and cron when config is incomplete" test_start_service_skips_when_config_incomplete

report_and_exit
