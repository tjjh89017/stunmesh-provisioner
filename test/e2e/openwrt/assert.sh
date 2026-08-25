#!/usr/bin/env bash
# assert.sh -- the assertion vocabulary phase scripts use.
#
# Sourced by run.sh alongside lib.sh. It gives a phase script (phases/*.sh) a
# small set of claims to make about the guest, instead of hand-rolled ssh
# calls and if/else plumbing: assert_ssh_ok and assert_ssh_output_contains.
# assert_ok and assert_output_contains are their host-side counterparts,
# for claims about the controller and the fake dhtproxy that need no guest
# at all. Each assertion prints one pass/fail line and records the
# outcome; it never stops the run early, so one failed claim does not hide
# the next one. report_assertions decides the run's exit status once every
# phase has had a chance to run.
#
# Depends on lib.sh's guest_exec, and on SSH_PORT/SSH_KEY being exported by
# run.sh before any assert_ssh_* call runs.
set -euo pipefail

ASSERTIONS_RUN=0
ASSERTIONS_FAILED=0

# assert_ssh_ok DESC CMD -- passes when CMD exits 0 in the guest.
assert_ssh_ok() {
	local desc="$1" cmd="$2"
	ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
	if guest_exec "$SSH_PORT" "$SSH_KEY" "$cmd" >/dev/null 2>&1; then
		echo "ok - ${desc}"
	else
		echo "FAIL - ${desc} (command: ${cmd})"
		ASSERTIONS_FAILED=$((ASSERTIONS_FAILED + 1))
	fi
}

# assert_ssh_output_contains DESC CMD PATTERN -- passes when CMD's combined
# stdout+stderr in the guest contains PATTERN as a literal substring.
assert_ssh_output_contains() {
	local desc="$1" cmd="$2" pattern="$3" output
	ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
	if output=$(guest_exec "$SSH_PORT" "$SSH_KEY" "$cmd" 2>&1) && [[ "$output" == *"$pattern"* ]]; then
		echo "ok - ${desc}"
	else
		echo "FAIL - ${desc} (command: ${cmd}, expected to contain: ${pattern})"
		echo "  got: ${output:-<no output>}" >&2
		ASSERTIONS_FAILED=$((ASSERTIONS_FAILED + 1))
	fi
}

# assert_ssh_exit_code DESC CMD CODE -- passes when CMD's exit status
# in the guest equals CODE exactly. assert_ssh_ok only tells zero from
# nonzero apart, which is not enough for fetch's exit-code contract
# (PLAN.md 5: 0 applied or nothing to do, 3 no change, 1 failure) --
# a claim like "the second fetch exits 3" needs the exact code.
assert_ssh_exit_code() {
	local desc="$1" cmd="$2" want="$3" got=0
	ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
	guest_exec "$SSH_PORT" "$SSH_KEY" "$cmd" >/dev/null 2>&1 || got=$?
	if [[ "$got" -eq "$want" ]]; then
		echo "ok - ${desc}"
	else
		echo "FAIL - ${desc} (command: ${cmd}, expected exit ${want}, got ${got})"
		ASSERTIONS_FAILED=$((ASSERTIONS_FAILED + 1))
	fi
}

# assert_equal DESC ACTUAL EXPECTED -- passes when ACTUAL equals
# EXPECTED as a literal string. For a claim that compares two values
# a phase script already captured (for example, a checksum taken
# before and after an action that should change nothing), instead of
# round-tripping both back through a shell command string just to
# compare them.
assert_equal() {
	local desc="$1" actual="$2" expected="$3"
	ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
	if [[ "$actual" == "$expected" ]]; then
		echo "ok - ${desc}"
	else
		echo "FAIL - ${desc} (expected: ${expected}, got: ${actual})"
		ASSERTIONS_FAILED=$((ASSERTIONS_FAILED + 1))
	fi
}

# assert_ok DESC CMD -- like assert_ssh_ok, but runs CMD on the host
# (via bash -c) instead of in the guest over SSH. For claims about the
# host side of the harness -- the controller and the fake dhtproxy --
# which involve no guest at all.
assert_ok() {
	local desc="$1" cmd="$2"
	ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
	if bash -c "$cmd" >/dev/null 2>&1; then
		echo "ok - ${desc}"
	else
		echo "FAIL - ${desc} (command: ${cmd})"
		ASSERTIONS_FAILED=$((ASSERTIONS_FAILED + 1))
	fi
}

# assert_output_contains DESC CMD PATTERN -- like
# assert_ssh_output_contains, but runs CMD on the host instead of in the
# guest over SSH.
assert_output_contains() {
	local desc="$1" cmd="$2" pattern="$3" output
	ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
	if output=$(bash -c "$cmd" 2>&1) && [[ "$output" == *"$pattern"* ]]; then
		echo "ok - ${desc}"
	else
		echo "FAIL - ${desc} (command: ${cmd}, expected to contain: ${pattern})"
		echo "  got: ${output:-<no output>}" >&2
		ASSERTIONS_FAILED=$((ASSERTIONS_FAILED + 1))
	fi
}

# report_assertions -- prints the pass/fail totals. Returns nonzero if any
# assertion failed, so run.sh's own exit status reflects the run's outcome.
report_assertions() {
	echo "${ASSERTIONS_RUN} assertion(s) run, $((ASSERTIONS_RUN - ASSERTIONS_FAILED)) passed, ${ASSERTIONS_FAILED} failed"
	[[ "$ASSERTIONS_FAILED" -eq 0 ]]
}
