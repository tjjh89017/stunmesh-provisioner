#!/usr/bin/env bash
# preflight.sh -- confirms both real Jami dhtproxy instances answer HTTP
# requests before run.sh spends a build and a publish round on them.
#
# This is a separate script, run as its own composite-action step
# (.github/actions/e2e-realnet/action.yml), on purpose. A reader looking
# at a red run in the GitHub UI sees the failed *step name* without
# opening the log. "Check the real Jami proxies are reachable" failing
# means the third-party service is down. "Publish and fetch a real
# bundle" failing (run.sh) means OUR contract assumption about it is
# wrong. Folding both checks into one step would erase that distinction
# exactly where it matters most: a reader deciding whether to re-run the
# job or open an issue.
#
# Only the two proxies stunmesh-agent itself defaults to
# (cmd/stunmesh-agent/config.go's defaultProxies) are ever contacted.
# This is not a parameter: a caller must not be able to point this
# check at a different host, because the whole point is to test exactly
# what a real node talks to.
set -euo pipefail

log() {
	echo "[e2e-realnet] $*"
}

die() {
	echo "[e2e-realnet] ERROR: $*" >&2
	exit 1
}

# The two proxies stunmesh-agent and stunmesh-provd default to. Hardcoded,
# not a variable a caller could override -- see the file header.
readonly PROXIES=(
	"https://dhtproxy2.jami.net"
	"https://dhtproxy3.jami.net"
)

# A syntactically valid dhtkey (40 lowercase hex characters) that is
# certainly never published: run.sh always publishes under a key derived
# from a freshly random namespace, never all zeros.
readonly PROBE_KEY="0000000000000000000000000000000000000000"

# retry_curl URL -- retries a GET against URL up to 4 times with a fixed
# backoff, and prints the HTTP status code on success. Any status code
# counts as "reachable": a 404 for PROBE_KEY is the expected answer from
# a healthy proxy, and even a 5xx still proves the host is up and
# speaking HTTP, which is more than this check claims. Only a curl-level
# failure (no connection, TLS failure, timeout) counts as unreachable.
retry_curl() {
	local url="$1" attempt code
	for attempt in 1 2 3 4; do
		if code=$(curl -fsS -o /dev/null -w '%{http_code}' -m 15 "$url" 2>/dev/null); then
			echo "$code"
			return 0
		fi
		# curl -f turns a 4xx/5xx into a non-zero exit too, which would
		# otherwise be misread as "unreachable". Retry once without -f to
		# tell the two apart: any HTTP response at all is reachable.
		if code=$(curl -sS -o /dev/null -w '%{http_code}' -m 15 "$url" 2>/dev/null); then
			echo "$code"
			return 0
		fi
		log "attempt ${attempt}/4 against ${url} did not connect, retrying in 3s..."
		sleep 3
	done
	return 1
}

summary() {
	echo "$*"
	if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
		echo "$*" >>"$GITHUB_STEP_SUMMARY"
	fi
}

unreachable=()
for proxy in "${PROXIES[@]}"; do
	log "Probing ${proxy}/${PROBE_KEY}..."
	if code=$(retry_curl "${proxy}/${PROBE_KEY}"); then
		log "${proxy}: reachable (HTTP ${code})"
	else
		unreachable+=("$proxy")
		log "${proxy}: did not answer after 4 attempts"
	fi
done

if [[ ${#unreachable[@]} -gt 0 ]]; then
	summary "## e2e-realnet: PROXY DOWN"
	summary ""
	summary "The following real Jami dhtproxy instance(s) did not answer an HTTP request after 4 attempts each:"
	for p in "${unreachable[@]}"; do
		summary "- ${p}"
	done
	summary ""
	summary "This is a third-party outage, not a problem with stunmesh-provisioner. Re-run the job once the proxy is back."
	echo "::error::e2e-realnet: PROXY DOWN -- ${unreachable[*]} did not answer. This is a third-party outage, not a stunmesh-provisioner defect."
	die "one or more real Jami dhtproxy instances are unreachable: ${unreachable[*]}"
fi

summary "## e2e-realnet: proxy reachability"
summary ""
summary "Both real Jami dhtproxy instances answered an HTTP request:"
for p in "${PROXIES[@]}"; do
	summary "- ${p}"
done
log "Both proxies are reachable. Proceeding to the round trip."
