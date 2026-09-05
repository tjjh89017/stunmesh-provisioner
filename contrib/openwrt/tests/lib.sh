#!/bin/sh
# lib.sh -- a small, dependency-free assertion framework for the
# contrib/openwrt shell tests.
#
# It works under BusyBox ash and under dash: no arrays, no "local"
# outside of what both shells support, no bashisms. Each test_*.sh
# file sources this, calls run_test once per case, then calls
# report_and_exit at the end.

TESTS_RUN=0
TESTS_FAILED=0

# run_test runs one test case function in a subshell, so a test's
# variable and PATH changes never leak into the next test, and prints
# one result line for it.
#
# Usage: run_test <name> <function>
run_test() {
	name="$1"
	fn="$2"
	TESTS_RUN=$((TESTS_RUN + 1))
	if ( "$fn" ); then
		echo "ok - $name"
	else
		echo "FAIL - $name"
		TESTS_FAILED=$((TESTS_FAILED + 1))
	fi
}

# assert_eq compares two values. It prints both values and fails when
# they differ. Callers use it as: assert_eq "$actual" "$expected" \
# "label" || return 1
assert_eq() {
	actual="$1"
	expected="$2"
	label="$3"
	if [ "$actual" != "$expected" ]; then
		echo "  $label: expected [$expected], got [$actual]" >&2
		return 1
	fi
	return 0
}

# assert_no_stray_temp fails when the directory $1 holds any file
# matching the mktemp template "$2.??????" (the six-character XXXXXX
# suffix mktemp appends).
assert_no_stray_temp() {
	dir="$1"
	base="$2"
	stray=$(find "$dir" -maxdepth 1 -name "$base.??????" 2>/dev/null)
	if [ -n "$stray" ]; then
		echo "  stray temp file left behind: $stray" >&2
		return 1
	fi
	return 0
}

# report_and_exit prints the pass/fail totals and exits nonzero if any
# test failed, so run.sh can tell pass from fail from the exit code.
report_and_exit() {
	echo "$TESTS_RUN run, $((TESTS_RUN - TESTS_FAILED)) passed, $TESTS_FAILED failed"
	[ "$TESTS_FAILED" -eq 0 ]
}
