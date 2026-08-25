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
#   3. The real `stunmesh-agent fetch` binary -- not a re-implementation
#      -- gets and decrypts that value with the real dhtkey/crypto/
#      dhtproxy packages, using its own built-in default proxy list
#      (cmd/stunmesh-agent/config.go's defaultProxies), never an
#      overridden one. The published bundle is the smallest legitimate
#      one ("wg": {}, empty "stunmesh"), which is exactly the content a
#      fresh node's absent last.json already represents (internal/last's
#      "Missing file" doc): a correct decrypt-and-compare exits
#      ExitNoChange (3) without ever calling uci or ubus. That is what
#      makes this leg practical without a VM: it proves the real
#      decrypt-and-validate path end to end, on a plain Ubuntu runner,
#      by construction rather than by mocking out the OpenWrt-only
#      apply step.
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

# fail_contract MESSAGE -- the run got a real answer from a proxy, and
# that answer (or the real agent's handling of it) did not match what
# internal/dhtproxy or docs/format.md assumes. This is the case
# preflight.sh already ruled out an outage for: it is OUR bug to fix,
# not a reason to re-run. The "CONTRACT VIOLATION" tag in both the
# ::error:: annotation (visible on the run summary page without
# opening any log) and the step summary is what lets a reader tell
# this apart from fail_network below.
fail_contract() {
	local msg="$1"
	summary_line ""
	summary_line "## e2e-realnet: CONTRACT VIOLATION"
	summary_line ""
	summary_line "$msg"
	summary_line ""
	summary_line "preflight.sh already confirmed both proxies were reachable moments before this ran. This is a mismatch between what stunmesh-provisioner's code assumes and what the real proxy actually did -- fix the code or the docs, do not just re-run."
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
IDENTITY_PUBKEY=$("$AGENT_BIN" keygen --identity-key "$IDENTITY_KEY_PATH")
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

# fetch_and_measure PROXY -- GETs PUBLISHED_KEY from PROXY, retrying a
# curl-level (connection) failure up to 3 times, and prints one summary
# table row plus the raw body to the job log. Exits via fail_network on
# a persistent connection failure, or fail_contract when the body does
# not match the newline-delimited-JSON-with-base64-data shape
# internal/dhtproxy's package doc describes.
fetch_and_measure() {
	local proxy="$1" attempt headers body status content_type lines shape_ok line data_field decoded_len

	headers="${WORK}/headers-$(basename "$proxy")"
	body="${WORK}/body-$(basename "$proxy")"

	for attempt in 1 2 3; do
		if status=$(curl -sS -D "$headers" -o "$body" -w '%{http_code}' -m 20 "${proxy}/${PUBLISHED_KEY}" 2>"${WORK}/curl-err"); then
			break
		fi
		if [[ "$attempt" == 3 ]]; then
			fail_network "GET ${proxy}/<key> did not connect after 3 attempts: $(cat "${WORK}/curl-err")"
		fi
		log "GET ${proxy}: attempt ${attempt}/3 did not connect, retrying in 3s..."
		sleep 3
	done

	content_type=$(grep -i '^content-type:' "$headers" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')
	lines=$(grep -c . "$body" || true)

	log "GET ${proxy}/${PUBLISHED_KEY} -> HTTP ${status}, Content-Type: ${content_type:-<none>}, ${lines} line(s)"
	log "Raw body from ${proxy}:"
	log "$(cat "$body")"

	if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
		fail_contract "GET ${proxy}/<key> returned HTTP ${status} right after a successful publish; internal/dhtproxy expects 2xx for a key that was just PUT."
	fi

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

	summary_line "| ${proxy} | ${status} | ${content_type:-<none>} | ${lines} | ${shape_ok} |"

	if [[ "$shape_ok" != "yes" ]]; then
		fail_contract "${proxy}/<key>'s response does not match internal/dhtproxy's assumed shape: ${shape_ok}."
	fi
}

fetch_and_measure "$PROXY2"
fetch_and_measure "$PROXY3"

# --- 3. the strongest proof: the real stunmesh-agent decrypts it -----

log "Running the real stunmesh-agent fetch (its own built-in default proxies, no override)..."
FETCH_STDERR="${WORK}/fetch-stderr"
set +e
"$AGENT_BIN" fetch \
	--namespace "$NAMESPACE" \
	--node-id "$NODE_ID" \
	--controller-pubkey "$CONTROLLER_PUBKEY" \
	--identity-key "$IDENTITY_KEY_PATH" \
	--last "${WORK}/last.json" \
	--lock "${WORK}/agent.lock" \
	--stunmesh-config "${WORK}/stunmesh-config.yaml" \
	2>"$FETCH_STDERR"
FETCH_EXIT=$?
set -e

log "stunmesh-agent fetch exited ${FETCH_EXIT}. stderr:"
log "$(cat "$FETCH_STDERR")"

summary_line ""
summary_line "## e2e-realnet: real stunmesh-agent fetch"
summary_line ""
summary_line "Exit code: ${FETCH_EXIT} (3 = ExitNoChange is the expected, successful outcome: the real fetch got the real value from the real proxies, decrypted it with the real identity key against the real controller key, validated namespace/node_id/version, and found it identical to the empty state a fresh node's absent last.json already represents -- so it changed nothing and never called uci or ubus)."
summary_line ""
summary_line "\`\`\`"
summary_line "$(cat "$FETCH_STDERR")"
summary_line "\`\`\`"

if [[ "$FETCH_EXIT" != 3 ]]; then
	fail_contract "the real stunmesh-agent fetch exited ${FETCH_EXIT}, not the expected 3 (ExitNoChange). It did not cleanly get-and-decrypt the bundle this run just published. See the fetch stderr above."
fi
log "Real stunmesh-agent fetch decrypted the real bundle from the real proxies. Round trip proven."

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
