#!/bin/sh
# test_init.sh -- tests for the cron-management functions in
# contrib/openwrt/stunmesh-agent.init: remove_cron, install_cron, and
# stop_service.
#
# How the functions under test are loaded:
#
# stunmesh-agent.init starts with ". /lib/functions.sh" at its top
# level, to pull in OpenWrt's UCI helpers (config_load/config_get).
# Those helpers do not exist off an OpenWrt device, so sourcing the
# file as-is aborts here before any function is even defined (BusyBox
# ash and dash both treat a failed "." on a missing file as fatal).
# remove_cron, install_cron, and stop_service never call config_load
# or config_get -- only read_config does, and this file does not test
# read_config -- so this file sources a filtered copy of the real
# script with just that one line removed. Every function body below is
# the real, unmodified script text; only the UCI-loading line is
# skipped.
#
# CRONTAB is reassigned per test to a scratch file, the same way a
# caller would point the script at a different crontab; the script's
# own logic is never edited.
#
# One real side effect cannot be avoided without editing the script:
# install_cron and remove_cron both call "/etc/init.d/cron reload" by
# its absolute path, so it cannot be intercepted via PATH stubbing the
# way mktemp/cp/mv/awk/mkdir are below. On a host that has that path
# (this dev machine does), it harmlessly reloads the real system cron
# daemon's already-unrelated config; on a host that does not (most CI
# runners), the shell reports "not found" on stderr, which the script
# already redirects to /dev/null, and its exit status is never
# checked. Neither case touches this test's scratch crontab files.

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

# stub installs a fake executable named $2 in a fresh stub directory
# under $1, running body $3, and prepends that directory to PATH so
# the next lookup of $2 finds it instead of the real command.
stub() {
	dir="$1"
	cmdname="$2"
	body="$3"
	stubdir="$dir/stub"
	mkdir -p "$stubdir"
	{
		echo "#!/bin/sh"
		echo "$body"
	} > "$stubdir/$cmdname"
	chmod +x "$stubdir/$cmdname"
	PATH="$stubdir:$PATH"
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
	stub "$d" mktemp 'exit 1'

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
	stub "$d" awk 'exit 1'

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
	stub "$d" cp 'exit 1'

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
	stub "$d" mv 'exit 1'

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
	stub "$d" mkdir 'exit 0'

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
	stub "$d" mkdir 'exit 0'

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
	stub "$d" mktemp 'exit 1'

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
	stub "$d" mv 'exit 1'

	stop_service
	rc=$?

	assert_eq "$rc" "1" "stop_service rc when remove_cron cannot confirm removal" || return 1
	current=$(cat "$CRONTAB")
	assert_eq "$current" "$original" "crontab untouched when stop_service cannot confirm removal" || return 1
	assert_no_stray_temp "$d" "crontab"
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

report_and_exit
