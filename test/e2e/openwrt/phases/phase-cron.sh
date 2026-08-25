#!/usr/bin/env bash
# phase-cron.sh -- assertions D: the cron line (stage5 checklist item
# 12's "cron line present with fetch_interval"; PLAN.md section 5,
# contrib/openwrt/README.md section 3).
#
# contrib/openwrt/tests/test_init.sh already covers install_cron and
# remove_cron's own control flow -- awk/mktemp/cp/mv failure paths,
# against a fake crontab file. What is untested anywhere is whether a
# real crond, on a real device, actually accepts the line this script
# writes: this phase runs the real `service stunmesh-agent start` and
# `stop` (rc.common's dispatcher for /etc/init.d/stunmesh-agent) and
# reads the real /etc/crontabs/root and the real crond process crond
# reload leaves running.
#
# Sourced by run.sh, which then calls every function named phase_*.
# Uses SSH_PORT and SSH_KEY, set by run.sh before any phase runs.
# Self-contained like every other phase (see run.sh's own doc
# comment): it plants its own foreign crontab line and does not
# assume any other phase already touched /etc/crontabs/root.
set -euo pipefail

CRON_TAG="# stunmesh-agent: managed by /etc/init.d/stunmesh-agent, do not edit"
FOREIGN_CRON_LINE="* * * * * echo not-stunmesh-agent # a foreign line, not managed by stunmesh-agent"

phase_cron_line() {
	local mode_before mode_after tag_count crond_log_before crond_log_after

	# Plant a foreign line by hand, mode 0600 -- the mode remove_cron's
	# "cp -p" must carry through every rewrite untouched.
	guest_exec "$SSH_PORT" "$SSH_KEY" \
		"mkdir -p /etc/crontabs && echo '${FOREIGN_CRON_LINE}' > /etc/crontabs/root && chmod 0600 /etc/crontabs/root" \
		|| die "Could not plant the foreign crontab line."
	# guest_capture, not a plain `var=$(guest_exec ...)`: see lib.sh's
	# guest_capture for why a failed read here must not abort the
	# harness under `set -e` -- this phase's own mode_before/mode_after
	# is exactly the before/after capture pattern that guards.
	mode_before=$(guest_capture "$SSH_PORT" "$SSH_KEY" "ls -l /etc/crontabs/root" | awk '{print $1}')

	# Count, not assume: another phase's own cron activity (this
	# phase does not know or care what ran before it -- see run.sh's
	# doc comment on phase ordering) may already have logged a
	# "crond (busybox" line before this one runs.
	# guest_capture, not a plain `var=$(guest_exec ...)`, same as
	# mode_before above: this is a count, and the `|| true` inside the
	# remote command already absorbs grep's own "no match" exit so its
	# real count reaches the caller unchanged (see lib.sh's guest_capture
	# comment on why FALLBACK cannot substitute for that). FALLBACK "0"
	# here covers the other failure mode, guest_exec itself failing, with
	# a real "no crond activity seen" value the later subtraction can
	# still do arithmetic on.
	crond_log_before=$(guest_capture "$SSH_PORT" "$SSH_KEY" "logread | grep -c 'crond (busybox' || true" 0)

	assert_ssh_ok "service stunmesh-agent start exits 0" \
		"service stunmesh-agent start"

	assert_ssh_output_contains "the cron line uses fetch_interval from /etc/config/provd (5)" \
		"cat /etc/crontabs/root" "*/5 * * * *"
	assert_ssh_output_contains "the cron line is tagged as managed" \
		"cat /etc/crontabs/root" "$CRON_TAG"
	assert_ssh_output_contains "start left the foreign crontab line alone" \
		"cat /etc/crontabs/root" "not-stunmesh-agent"

	# crond only proves it "accepts" the file by staying up and having
	# actually (re)started against it -- busybox crond logs this one
	# line, with its own version, to syslog every time /etc/init.d/cron
	# reload runs it. Absence of a running crond, or absence of this
	# line, means the reload never really landed.
	assert_ssh_ok "crond is running after the reload install_cron triggers" \
		"pgrep crond"
	crond_log_after=$(guest_capture "$SSH_PORT" "$SSH_KEY" "logread | grep -c 'crond (busybox' || true" 0)
	assert_ssh_ok "crond logged that it (re)started against the new crontab" \
		"[ $((crond_log_after - crond_log_before)) -ge 1 ]"

	# A repeated start (README.md section 3: "a repeated start()...
	# removes any cron line it installed before adding the new one")
	# must not leave two managed lines.
	assert_ssh_ok "a repeated service start exits 0" \
		"service stunmesh-agent start"
	# `|| true` inside the guest command, not a guest_capture FALLBACK:
	# `grep -c` already prints the real count (0, on a genuine
	# zero-managed-lines regression) before it exits 1 for "no match".
	# guest_capture only ever appends its FALLBACK after CMD's own
	# stdout, never replaces it, so a FALLBACK of "0" here would land
	# after grep's own "0" and read as "0\n0", not a clean "0" (see
	# lib.sh's guest_capture comment). Absorbing the exit with `|| true`
	# keeps grep's own count as the only output, at the cost of no
	# longer distinguishing "zero matches" from "the read itself
	# failed" -- both cases here would just be a wrong tag_count, which
	# assert_equal reports; phase-lock.sh's `wc -l < file` case is
	# different: wc's own exit code never fails on an empty file, so its
	# nonzero exit means the read itself failed, which its "0" FALLBACK
	# is correct to report as-is.
	tag_count=$(guest_capture "$SSH_PORT" "$SSH_KEY" \
		"grep -c -F '${CRON_TAG}' /etc/crontabs/root || true")
	assert_equal "a repeated start left exactly one managed cron line, not two" \
		"$tag_count" "1"

	assert_ssh_ok "service stunmesh-agent stop exits 0" \
		"service stunmesh-agent stop"
	assert_ssh_ok "stop removed the managed cron line" \
		"! grep -q -F '${CRON_TAG}' /etc/crontabs/root"
	assert_ssh_output_contains "stop left the foreign crontab line alone" \
		"cat /etc/crontabs/root" "not-stunmesh-agent"

	mode_after=$(guest_capture "$SSH_PORT" "$SSH_KEY" "ls -l /etc/crontabs/root" | awk '{print $1}')
	assert_equal "the crontab file's mode survived every rewrite" \
		"$mode_after" "$mode_before"

	# Each of the two "service start" calls above also scheduled its
	# own "(sleep boot_delay; run_fetch) &" background job
	# (stunmesh-agent.init's start_service); "stop" only removes the
	# cron trigger, not those two already-running, already-orphaned
	# jobs. boot_delay is 15s (this harness's /etc/config/provd); wait
	# past it here so both jobs have fired and finished before this
	# phase hands control back, instead of leaving them to race a
	# later phase's own stub-action-log or last.json bookkeeping
	# (phase-lock.sh counts stub actions by exact delta, and would
	# misattribute a stray boot_delay fetch landing mid-race).
	guest_exec "$SSH_PORT" "$SSH_KEY" "sleep 16" || true
}
