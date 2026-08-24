#!/usr/bin/env bash
# assert.sh -- the assertion vocabulary phase scripts use.
#
# Sourced by run.sh alongside lib.sh. It gives a phase script (phases/*.sh) a
# small set of claims to make about the guest, instead of hand-rolled ssh
# calls and if/else plumbing: assert_ssh_ok and assert_ssh_output_contains.
# Each assertion prints one pass/fail line and records the outcome; it never
# stops the run early, so one failed claim does not hide the next one.
# report_assertions decides the run's exit status once every phase has had a
# chance to run.
#
# Depends on lib.sh's guest_exec, and on SSH_PORT/SSH_KEY being exported by
# run.sh before any assertion runs.
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

# report_assertions -- prints the pass/fail totals. Returns nonzero if any
# assertion failed, so run.sh's own exit status reflects the run's outcome.
report_assertions() {
	echo "${ASSERTIONS_RUN} assertion(s) run, $((ASSERTIONS_RUN - ASSERTIONS_FAILED)) passed, ${ASSERTIONS_FAILED} failed"
	[[ "$ASSERTIONS_FAILED" -eq 0 ]]
}
