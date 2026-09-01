#!/usr/bin/env bash
# run.sh -- the realnet e2e leg: a real round trip against the real
# Jami dhtproxy instances, and the measurements stage5-openwrt-device.md
# checklist item 7 asks for.
#
# preflight.sh (a separate composite-action step, see its own header)
# already proved both proxies answer HTTP requests before this script
# ever runs. Everything this script fails on afterward is therefore
# treated as a stunmesh-provisioner contract problem, not a proxy
# outage -- see fail_contract and fail_network below for how a reader
# tells the two apart without opening the log.
#
# What this proves, in order:
#
#   1. `stunmesh-provd init` (random namespace), `node add`, and
#      `publish --once` really put a real, encrypted bundle to
#      dhtproxy2.jami.net and dhtproxy3.jami.net.
#   2. A raw `curl GET /{key}` against both proxies returns the shape
#      internal/dhtproxy assumes: newline-delimited JSON, a "data"
#      field, base64. That shape is recorded verbatim in the job
#      summary and the job log.
#   3. The real `stunmesh-agent --oneshot` binary -- not a
#      re-implementation -- gets and decrypts that value with the real
#      dhtkey/crypto/dhtproxy packages, using its own built-in default
#      proxy list (cmd/stunmesh-agent/config.go's defaultProxies), never
#      an overridden one. The published bundle is the smallest
#      legitimate one ("wg": {}, empty "stunmesh"). --oneshot always
#      forces a full apply (fetch.go's runFetchApply, forceAll=true),
#      so applyDiff still runs its two unconditional steps, "uci commit
#      network" and "ubus call network reload" (fetch_apply.go); with
#      no WG interfaces in this bundle neither "ifup" nor a firewall
#      command runs. This script puts stub uci/ubus ahead of PATH for
#      that call, so it can exercise the real fetch/decrypt/diff/apply
#      path end to end on a plain Ubuntu runner, without mocking out
#      the OpenWrt-only pieces those two commands themselves are (the
#      VM e2e harness covers the real uci/ubus behaviour).
#   4. A few PUT probes of increasing size against dhtproxy3 alone
#      record how large a value the proxy actually accepts, bracketing
#      the maxDHTValueSize placeholder in
#      cmd/stunmesh-provd/build_bundle.go.
#
# Every DHT key this script ever touches is either derived from a
# freshly random namespace (`init`'s own randomNamespace, run with no
# namespace argument) or a fresh sha1 of /dev/urandom bytes (the size
# probes): two runs never collide, and nothing accumulates under a
# predictable key. No proxy list is ever passed as a flag or read from
# an environment variable here -- see the header comment in
# preflight.sh for why that is a hard constraint, not an oversight.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${HERE}/../../.." && pwd)

# The two proxies stunmesh-agent and stunmesh-provd default to.
# Hardcoded, not a variable: see preflight.sh's header.
readonly PROXY2="https://dhtproxy2.jami.net"
readonly PROXY3="https://dhtproxy3.jami.net"

log() {
	echo "[e2e-realnet] $*"
}

# summary_line writes one line to both the job log and
# $GITHUB_STEP_SUMMARY (a no-op locally, where that variable is unset),
# so the measurements this script exists to produce are never stranded
# in a place the CLI cannot read (a plain job-log line always survives;
# the step summary is the nicer rendering of the same content).
summary_line() {
	echo "$*"
	if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
		echo "$*" >>"$GITHUB_STEP_SUMMARY"
	fi
}

# fail_contract MESSAGE [GUIDANCE] -- the run got a real answer from a
# proxy, and that answer (or the real agent's handling of it) did not
# match what internal/dhtproxy or docs/format.md assumes. This is the
# case preflight.sh already ruled out an outage for: it is OUR bug to
# fix, not a reason to re-run. The "CONTRACT VIOLATION" tag in both the
# ::error:: annotation (visible on the run summary page without
# opening any log) and the step summary is what lets a reader tell
# this apart from fail_network below.
#
# GUIDANCE, when given, replaces the default "do not just re-run"
# closing line. The retry loop in fetch_and_measure passes a softer
# closing line when the proxy's answer CHANGED across its 3 attempts: a
# heterogeneous sequence is evidence of a flapping proxy, not of a
# deterministic mismatch, and the strong default would send a reader
# hunting for a code bug that one re-run might disprove. Every uniform
# sequence keeps the strong default.
fail_contract() {
	local msg="$1"
	local guidance="${2:-}"
	if [[ -z "$guidance" ]]; then
		guidance="preflight.sh already confirmed both proxies were reachable moments before this ran. This is a mismatch between what stunmesh-provisioner's code assumes and what the real proxy actually did -- fix the code or the docs, do not just re-run."
	fi
	summary_line ""
	summary_line "## e2e-realnet: CONTRACT VIOLATION"
	summary_line ""
	summary_line "$msg"
	summary_line ""
	summary_line "$guidance"
	echo "::error::e2e-realnet: CONTRACT VIOLATION -- ${msg}"
	exit 1
}

# fail_network MESSAGE -- a request that ran after preflight.sh already
# passed still could not complete. preflight.sh checked seconds before
# this script started building binaries; a proxy can still drop between
# then and now. This is reported distinctly from fail_contract because
# it is still most likely a transient third-party issue, not a proven
# contract mismatch -- but it is reported as a failure, not silently
# swallowed, because the round trip this leg exists to prove did not
# complete.
fail_network() {
	local msg="$1"
	summary_line ""
	summary_line "## e2e-realnet: NETWORK FAILURE (possibly transient)"
	summary_line ""
	summary_line "$msg"
	summary_line ""
	summary_line "preflight.sh confirmed reachability just before this ran. Re-run the job; if it fails again the same way, treat it like a CONTRACT VIOLATION."
	echo "::error::e2e-realnet: NETWORK FAILURE (possibly transient) -- ${msg}"
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "[e2e-realnet] ERROR: missing dependency: $1" >&2
		exit 1
	}
}

for cmd in curl make go sha1sum base64 mktemp; do
	need_cmd "$cmd"
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/stunmesh-e2e-realnet.XXXXXX")
cleanup() {
	local exit_code=$?
	if [[ "${E2E_KEEP_WORK:-0}" == 1 ]]; then
		log "Kept working directory: ${WORK}"
	else
		rm -rf "$WORK"
	fi
	exit "$exit_code"
}
trap cleanup EXIT INT TERM

# --- 1. build the real binaries and stand up a real controller -------

log "Building stunmesh-provd and stunmesh-agent (make provd agent)..."
make -C "$REPO_ROOT" provd DIST="${WORK}/dist" VERSION="e2e-realnet" >/dev/null
make -C "$REPO_ROOT" agent DIST="${WORK}/dist" VERSION="e2e-realnet" >/dev/null
PROVD_BIN="${WORK}/dist/stunmesh-provd"
AGENT_BIN="${WORK}/dist/stunmesh-agent"
[[ -x "$PROVD_BIN" && -x "$AGENT_BIN" ]] || fail_contract "make provd/agent did not produce ${PROVD_BIN} and ${AGENT_BIN}."

log "Generating the node identity key (stunmesh-agent keygen)..."
IDENTITY_KEY_PATH="${WORK}/identity.key"
IDENTITY_PUBKEY=$("$AGENT_BIN" keygen --config-dir "$WORK")
[[ -n "$IDENTITY_PUBKEY" ]] || fail_contract "stunmesh-agent keygen produced no public key on stdout."

PROVD_ROOT="${WORK}/provd-root"
log "Running stunmesh-provd init (random namespace)..."
INIT_OUTPUT=$("$PROVD_BIN" --dir "$PROVD_ROOT" init) || fail_contract "stunmesh-provd init failed: ${INIT_OUTPUT}"
NAMESPACE=$(echo "$INIT_OUTPUT" | grep -oE '^namespace [0-9a-f]+:' | head -1 | awk '{print $2}' | tr -d ':')
[[ -n "$NAMESPACE" ]] || fail_contract "Could not find the generated namespace in init output: ${INIT_OUTPUT}"
log "Namespace: ${NAMESPACE} (fresh random value, this run only)"

NODE_ID="realnet-node"
log "Running stunmesh-provd node add ${NAMESPACE} ${NODE_ID}..."
"$PROVD_BIN" --dir "$PROVD_ROOT" node add "$NAMESPACE" "$NODE_ID" "$IDENTITY_PUBKEY" >/dev/null \
	|| fail_contract "stunmesh-provd node add failed."

CONTROLLER_PUBKEY=$(cat "${PROVD_ROOT}/${NAMESPACE}/controller.pub")
[[ -n "$CONTROLLER_PUBKEY" ]] || fail_contract "${PROVD_ROOT}/${NAMESPACE}/controller.pub is empty."

# provd.yaml is left exactly as `init` wrote it: the real
# dhtproxy2/dhtproxy3 default (cmd/stunmesh-provd/init_cmd.go's
# defaultProvdYAML). This script never edits it.

# The smallest legitimate bundle: no interfaces, no stunmesh-go config.
# This is deliberate -- see the file header, point 3 -- and it is the
# real fixtures/empty shape test/e2e/openwrt/fixtures/empty already
# uses for the same reason there.
NODE_DIR="${PROVD_ROOT}/${NAMESPACE}/nodes/${NODE_ID}"
printf '{}\n' >"${NODE_DIR}/wg.yaml"
printf '' >"${NODE_DIR}/stunmesh.yaml"

log "Publishing the bundle (stunmesh-provd publish --once)..."
PUBLISH_OUTPUT=$("$PROVD_BIN" --dir "$PROVD_ROOT" publish --namespace "$NAMESPACE" --once) \
	|| fail_contract "stunmesh-provd publish --once failed against the real proxies: ${PUBLISH_OUTPUT}"
PUBLISHED_KEY=$(echo "$PUBLISH_OUTPUT" | grep -oE 'key=[0-9a-f]{40}' | head -1 | cut -d= -f2)
[[ -n "$PUBLISHED_KEY" ]] || fail_contract "Could not find a DHT key in publish output: ${PUBLISH_OUTPUT}"
log "Published. DHT key: ${PUBLISHED_KEY}"

# --- 2. measure the real GET /{key} response shape --------------------

summary_line ""
summary_line "## e2e-realnet: GET /{key} response shape"
summary_line ""
summary_line "DHT key for this run (freshly random namespace, never reused): \`${PUBLISHED_KEY}\`"
summary_line ""
summary_line "| Proxy | HTTP status | Content-Type | Lines | Every line has a base64 \`data\` field |"
summary_line "|---|---|---|---|---|"

# join_seq VALUE... -- joins per-attempt observations into one readable
# sequence ("attempt 1: HTTP 500; attempt 2: HTTP 503; attempt 3: HTTP
# 502") for a failure message. The failure messages below quote the
# sequence actually observed instead of claiming the last attempt's
# value held "on all 3 attempts" -- a claim this script never verified,
# and one that would make a flapping proxy read as a reproducible,
# deterministic defect. Semicolon-separated and attempt-numbered
# because a shape verdict can itself contain commas.
join_seq() {
	local out="" v n=0
	for v in "$@"; do
		n=$((n + 1))
		out+="${out:+; }attempt ${n}: ${v}"
	done
	printf '%s' "$out"
}

# all_same VALUE... -- succeeds when every observation is identical,
# i.e. when "on all 3 attempts" is actually true and the strong
# not-transient wording is earned.
all_same() {
	local first="$1" v
	for v in "$@"; do
		[[ "$v" == "$first" ]] || return 1
	done
}

# fetch_and_measure PROXY -- GETs PUBLISHED_KEY from PROXY, up to 3
# attempts with a 3s fixed backoff, and prints one summary table row
# plus the raw body to the job log.
#
# All 3 attempts share one retry budget, whatever kind of "not a good
# answer yet" the previous attempt hit: a connection failure, a
# non-2xx status, or a 2xx with no usable value. 3 attempts and a 3s
# sleep are not new numbers invented for this loop: they are the exact
# numbers this same function already used for its connection-level
# retry, and that preflight.sh (in this same directory) already uses
# for its own reachability retries. Reusing them keeps one retry idiom
# for the whole leg instead of a second, separately-justified one.
#
# Why a non-2xx or an empty 2xx gets retried at all: internal/dhtproxy's
# package doc says a 404, a 5xx, and a connection error are all
# treated the same way when reading a key -- none of them is trusted as
# the final answer, because Put can partially fail and a later proxy
# (or a later moment, here, against the same proxy) may still have the
# value. preflight.sh's header makes the same point for a single 5xx:
# "still proves the host is up". publish --once already succeeded
# before this function ever runs, which only happens once both
# proxies accepted the value -- so a non-2xx or empty GET right after
# is far more likely to be replication lag than a real defect.
#
# What turns a retry into a real finding: a bad answer 3 times in a
# row, 6 seconds apart, right after our own publish to this same proxy
# succeeded. preflight.sh already ruled out "proxy is down" moments
# earlier, and a value that still is not visible 6+ seconds after a
# successful PUT to the very host being asked is not the kind of
# transient blip the production client was built to shrug off -- it is
# reported via fail_contract, not fail_network. A last-attempt
# connection failure, by contrast, never got an answer to judge at all
# -- that stays fail_network, unchanged from before.
#
# The failure message reports the sequence of per-attempt observations
# actually recorded (see `observed` below), never a blanket "on all 3
# attempts" inferred from the last attempt alone. When the 3
# observations are identical the message keeps the strong "this is
# not transient, do not just re-run" guidance; when they differ, the
# closing guidance is softened, because a proxy that answers 500, then
# 503, then 502 is flapping, and one re-run to check reproducibility
# is cheaper than hunting for a deterministic bug that may not exist.
fetch_and_measure() {
	local proxy="$1" attempt headers body status content_type lines shape_ok line data_field decoded_len
	# One entry per attempt, recording what that attempt actually
	# observed ("no connection", "HTTP 503", "HTTP 200, shape no
	# (...)"). The attempt-3 failure messages report this real sequence.
	local -a observed=()

	headers="${WORK}/headers-$(basename "$proxy")"
	body="${WORK}/body-$(basename "$proxy")"

	for attempt in 1 2 3; do
		if ! status=$(curl -sS -D "$headers" -o "$body" -w '%{http_code}' -m 20 "${proxy}/${PUBLISHED_KEY}" 2>"${WORK}/curl-err"); then
			observed+=("no connection")
			if [[ "$attempt" == 3 ]]; then
				if all_same "${observed[@]}"; then
					fail_network "GET ${proxy}/<key> did not connect on any of the 3 attempts (3s apart): $(cat "${WORK}/curl-err")"
				else
					fail_network "GET ${proxy}/<key> never completed: the 3 attempts (3s apart) observed $(join_seq "${observed[@]}"), and the last attempt did not connect: $(cat "${WORK}/curl-err")"
				fi
			fi
			log "GET ${proxy}: attempt ${attempt}/3 did not connect, retrying in 3s..."
			sleep 3
			continue
		fi

		content_type=$(grep -i '^content-type:' "$headers" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')
		lines=$(grep -c . "$body" || true)

		log "GET ${proxy}/${PUBLISHED_KEY} -> HTTP ${status}, Content-Type: ${content_type:-<none>}, ${lines} line(s) (attempt ${attempt}/3)"
		log "Raw body from ${proxy}:"
		log "$(cat "$body")"

		if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
			observed+=("HTTP ${status}")
			if [[ "$attempt" == 3 ]]; then
				if all_same "${observed[@]}"; then
					fail_contract "GET ${proxy}/<key> returned HTTP ${status} on all 3 attempts (3s apart) right after a successful publish. internal/dhtproxy treats a single non-2xx as transient and moves on, but the same non-2xx 3 times in a row this soon after our own publish succeeded to this same proxy is not that -- it is a real mismatch between what we assume the proxy does and what it actually did."
				else
					fail_contract "GET ${proxy}/<key> never returned a usable answer right after a successful publish: the 3 attempts (3s apart) observed $(join_seq "${observed[@]}"). internal/dhtproxy treats a single bad answer as transient and moves on; 3 in a row this soon after our own publish succeeded to this same proxy exceeds that tolerance, which is why this is reported instead of retried forever." \
						"preflight.sh already confirmed both proxies were reachable moments before this ran, but the answer CHANGED between attempts -- a heterogeneous sequence is evidence of a flapping proxy, not of a deterministic mismatch. One re-run to check reproducibility is reasonable here; if it fails again, treat it as a mismatch between what stunmesh-provisioner's code assumes and what the real proxy actually does, and fix the code or the docs rather than re-running further."
				fi
			fi
			log "GET ${proxy}: attempt ${attempt}/3 returned HTTP ${status}, retrying in 3s (a single non-2xx is treated as transient, same as internal/dhtproxy does)..."
			sleep 3
			continue
		fi

		# A 2xx with no non-blank lines is an empty body: no values at
		# all for a key this run just published. That is a real,
		# distinct failure from a malformed line (checked below), so it
		# is detected before the line loop instead of being silently
		# skipped by a loop that never runs.
		if [[ "$lines" == 0 ]]; then
			shape_ok="no (2xx with an empty body -- no values for a key this run just published)"
		else
			shape_ok="yes"
			while IFS= read -r line; do
				[[ -z "$line" ]] && continue
				data_field=$(echo "$line" | grep -oE '"data" *: *"[A-Za-z0-9+/=]*"' | sed -E 's/.*"([A-Za-z0-9+\/=]*)"$/\1/')
				if [[ -z "$data_field" ]]; then
					shape_ok="no (line has no base64 \`data\` field)"
					break
				fi
				if ! decoded_len=$(printf '%s' "$data_field" | base64 -d 2>/dev/null | wc -c); then
					shape_ok="no (\`data\` field does not decode as base64)"
					break
				fi
				log "  line data field: ${#data_field} base64 chars, decodes to ${decoded_len} bytes"
			done <"$body"
		fi

		if [[ "$shape_ok" != "yes" ]]; then
			observed+=("HTTP ${status}, shape ${shape_ok}")
			if [[ "$attempt" == 3 ]]; then
				summary_line "| ${proxy} | ${status} | ${content_type:-<none>} | ${lines} | ${shape_ok} |"
				if all_same "${observed[@]}"; then
					fail_contract "${proxy}/<key>'s response does not match internal/dhtproxy's assumed shape on all 3 attempts (3s apart): ${shape_ok}. A shape mismatch this soon after our own publish succeeded to this same proxy, and repeated identically 3 times, is not replication lag -- it is a real mismatch between what internal/dhtproxy assumes and what the proxy actually returned."
				else
					fail_contract "${proxy}/<key> never returned the shape internal/dhtproxy assumes right after a successful publish: the 3 attempts (3s apart) observed $(join_seq "${observed[@]}"). 3 unusable answers in a row this soon after our own publish succeeded to this same proxy is beyond the single-blip replication lag the retry budget allows for, which is why this is reported instead of retried forever." \
						"preflight.sh already confirmed both proxies were reachable moments before this ran, but the answer CHANGED between attempts -- a heterogeneous sequence is evidence of a flapping proxy, not of a deterministic mismatch. One re-run to check reproducibility is reasonable here; if it fails again, treat it as a mismatch between what stunmesh-provisioner's code assumes and what the real proxy actually does, and fix the code or the docs rather than re-running further."
				fi
			fi
			log "GET ${proxy}: attempt ${attempt}/3 got HTTP ${status} but ${shape_ok}, retrying in 3s (could still be replication lag right after publish)..."
			sleep 3
			continue
		fi

		summary_line "| ${proxy} | ${status} | ${content_type:-<none>} | ${lines} | ${shape_ok} |"
		return 0
	done
}

fetch_and_measure "$PROXY2"
fetch_and_measure "$PROXY3"

# --- 3. the strongest proof: the real stunmesh-agent decrypts it -----

# stunmesh-agent has no per-run flags for namespace/node_id/proxies any
# more -- every setting lives in config.yaml (this repository's
# top-level CLAUDE.md). No "proxies" key here at all: config.go's
# buildConfig only resolves a backend from config.yaml when
# use_plugin or plugins is set, and leaving both out is exactly how an
# operator gets the built-in default proxy list this leg means to
# exercise.
AGENT_CONFIG="${WORK}/agent-config.yaml"
cat >"$AGENT_CONFIG" <<EOF
namespace: "${NAMESPACE}"
node_id: "${NODE_ID}"
controller_pubkey: "${CONTROLLER_PUBKEY}"
identity_key: "${IDENTITY_KEY_PATH}"
last: "${WORK}/last.json"
lock: "${WORK}/agent.lock"
EOF

# --oneshot always forceAll=true (fetch.go's runFetchApply doc comment:
# the CLI dropped its "no change" exit code), so applyDiff always runs,
# even for this run's empty bundle (fetch_diff.go's diffStunmesh: an
# empty stunmesh text classifies as StunmeshEmpty, never Unchanged).
# applyDiff unconditionally runs "uci commit network" and "ubus call
# network reload" (fetch_apply.go); with no WG interfaces in this
# bundle it never runs "ifup" or a firewall command. A plain Ubuntu
# runner has no real "uci"/"ubus", so a stub bin dir ahead of PATH
# gives applyDiff something to call -- this leg proves the real
# decrypt-and-diff path, not OpenWrt's own uci/ubus (the VM e2e harness
# already covers that).
STUB_BIN="${WORK}/stub-bin"
mkdir -p "$STUB_BIN"
for stub in uci ubus; do
	cat >"${STUB_BIN}/${stub}" <<'STUB'
#!/bin/sh
exit 0
STUB
	chmod +x "${STUB_BIN}/${stub}"
done

log "Running the real stunmesh-agent --oneshot (its own built-in default proxies, no override)..."
FETCH_STDERR="${WORK}/fetch-stderr"
set +e
PATH="${STUB_BIN}:${PATH}" "$AGENT_BIN" --oneshot --config "$AGENT_CONFIG" 2>"$FETCH_STDERR"
FETCH_EXIT=$?
set -e

log "stunmesh-agent --oneshot exited ${FETCH_EXIT}. stderr:"
log "$(cat "$FETCH_STDERR")"

summary_line ""
summary_line "## e2e-realnet: real stunmesh-agent --oneshot"
summary_line ""
summary_line "Exit code: ${FETCH_EXIT} (0 is the expected, successful outcome: --oneshot always exits 0 on a clean run -- cli.go's ExitOK doc comment. The real run got the real value from the real proxies, decrypted it with the real identity key against the real controller key, validated namespace/node_id/version, and applied it: --oneshot always forces a full apply (fetch.go), which for this empty bundle means only the unconditional \"uci commit network\" and \"ubus call network reload\" steps ran, against this script's stub uci/ubus, not real ones)."
summary_line ""
summary_line "\`\`\`"
summary_line "$(cat "$FETCH_STDERR")"
summary_line "\`\`\`"

if [[ "$FETCH_EXIT" != 0 ]]; then
	fail_contract "the real stunmesh-agent --oneshot exited ${FETCH_EXIT}, not the expected 0. It did not cleanly get-and-decrypt the bundle this run just published. See the fetch stderr above."
fi
log "Real stunmesh-agent --oneshot decrypted the real bundle from the real proxies. Round trip proven."

# --- 4. how large a value does the proxy accept? ----------------------
#
# Probed against dhtproxy3 alone, to keep this leg's load on the real
# service to a minimum: the round trip above already exercised both.
# Each probe uses its own fresh, random key (sha1 of /dev/urandom), so
# no probe can collide with another run's key or with PUBLISHED_KEY.
#
# The three sizes below are not an arbitrary sweep: an interactive
# binary search against the real proxy (recorded in this item's PR)
# found the boundary sits between 65530 and 65535 raw bytes -- a
# 5-byte window right at 64 KiB (65536 bytes), the same MAX_VALUE_SIZE
# OpenDHT itself documents. 32768 is a clearly-accepted sanity point;
# 65530 and 65535 reproduce the accept/reject boundary itself on every
# run, in 3 requests instead of the dozen-plus the original search
# took. A rejection past the boundary takes the real proxy up to ~50s
# to answer (a 502, not a fast 4xx) -- curl's timeout below is set well
# above that, and a size probe failing to connect at all is reported
# and skipped, not fatal: it is a secondary measurement, not the
# round-trip proof above.

summary_line ""
summary_line "## e2e-realnet: maximum accepted value size (dhtproxy3 only)"
summary_line ""
summary_line "cmd/stunmesh-provd/build_bundle.go's \`maxDHTValueSize\` placeholder is 56 KiB (56 * 1024 = 57344 bytes) of base64-encoded DHT value. This section tests raw (pre-base64) payload sizes bracketing the real accept/reject boundary this item's own investigation found: 65530 raw bytes accepted, 65535 raw bytes rejected (HTTP 502, after up to ~50s) -- 64 KiB (65536 bytes) of raw value, matching OpenDHT's own documented MAX_VALUE_SIZE."
summary_line ""
summary_line "| Raw payload | PUT status | Accepted |"
summary_line "|---|---|---|"

probe_size() {
	local raw_bytes="$1" key payload_file b64 status

	key=$(head -c 64 /dev/urandom | sha1sum | awk '{print $1}')
	payload_file="${WORK}/probe-payload"
	head -c "$raw_bytes" /dev/urandom | base64 -w0 >"$payload_file"
	b64=$(cat "$payload_file")

	printf '{"data":"%s"}' "$b64" >"${WORK}/probe-body.json"

	if ! status=$(curl -sS -o /dev/null -w '%{http_code}' -m 60 \
		-H 'Content-Type: application/json' \
		--data-binary "@${WORK}/probe-body.json" \
		-X POST "${PROXY3}/${key}" 2>"${WORK}/probe-curl-err"); then
		log "Size probe at ${raw_bytes} raw bytes: PUT did not connect (${WORK}/probe-curl-err); skipping this data point."
		summary_line "| ${raw_bytes} bytes (~${#b64} base64 chars) | <no connection> | inconclusive |"
		return 1
	fi

	if [[ "$status" -ge 200 && "$status" -lt 300 ]]; then
		log "Size probe at ${raw_bytes} raw bytes (${#b64} base64 chars): accepted (HTTP ${status})."
		summary_line "| ${raw_bytes} bytes (${#b64} base64 chars) | ${status} | yes |"
		return 0
	fi

	log "Size probe at ${raw_bytes} raw bytes (${#b64} base64 chars): rejected (HTTP ${status})."
	summary_line "| ${raw_bytes} bytes (${#b64} base64 chars) | ${status} | no |"
	return 2
}

for size in 32768 65530 65535; do
	rc=0
	probe_size "$size" || rc=$?
	if [[ "$rc" == 2 ]]; then
		log "Stopping the size probe: ${size} raw bytes was rejected, no point trying anything larger."
		break
	fi
done

# --- 5. expiry: what this leg can and cannot observe ------------------
#
# A CI job runs for minutes, not the days or weeks a real DHT value
# might live for. This leg cannot measure a real expiry time: doing so
# would mean holding a runner (or scheduling a follow-up one) far
# longer than this job's own budget. What it CAN honestly report is
# that the value it just published was retrievable immediately after
# the publish -- proven above -- and nothing more.

summary_line ""
summary_line "## e2e-realnet: value expiry"
summary_line ""
summary_line "Not measured. A CI job's runtime (minutes) cannot observe a DHT value's real expiry (plausibly hours to days). This run only proves the value is retrievable immediately after publish (section above). Measuring real expiry needs a separate, long-running probe outside this job's scope."

summary_line ""
summary_line "## e2e-realnet: PASS"
summary_line ""
summary_line "The real stunmesh-provd published a real encrypted bundle to \`${PROXY2}\` and \`${PROXY3}\`, and the real stunmesh-agent fetched and decrypted it back."

log "e2e-realnet: PASS"
