#!/usr/bin/env bash
# run.sh -- OpenWrt e2e harness entry point.
#
# Resolves the current OpenWrt stable release, builds an ImageBuilder image
# with kmod-wireguard and wireguard-tools, boots it under KVM, waits for
# SSH, runs the phase scripts under phases/, and tears everything down.
# -accel kvm is hardcoded (see lib.sh boot_guest): this harness never falls
# back to TCG.
#
# Before boot, it stands up the real controller side on the host --
# stunmesh-provd (init, node add, publish --once) and a fake dhtproxy the
# guest can reach at 10.0.2.2 through QEMU's slirp networking -- publishes
# a real bundle, and proves it is retrievable from the fake proxy at the
# DHT key the node will use. It then builds stunmesh-agent for the guest
# (linux/amd64) and injects the full node payload: the binary,
# /etc/config/stunmesh-agent (carrying the real namespace, node ID, controller
# public key and proxy URL the controller just generated), the node's
# real identity key, and the real init and hotplug scripts from
# contrib/openwrt -- everything a freshly flashed device would have right
# after an operator finished the manual key exchange, with a real bundle
# already waiting on the proxy, except nothing has fetched it yet.
# phases/phase-smoke.sh proves the skeleton itself (boot -> inject -> SSH
# -> assert); phases/phase-payload.sh proves the payload landed intact.
# phases/phase-fetch-basic.sh publishes a second, realistic bundle (one
# WireGuard interface, one peer) and runs the real stunmesh-agent
# `--oneshot` in the guest, proving the agent's uci/ubus calls actually
# produce the intended result on real netifd -- and that a second run
# against the same bundle changes nothing. phases/phase-diff-removal.sh
# publishes further revisions of a two-interface bundle to prove
# reload, removal and teardown. phases/phase-daemon.sh, phase-hotplug.sh
# and phase-lock.sh prove the platform integration
# contrib/openwrt/README.md sections 1 and 4 describe: the procd daemon
# service, a real hotplug-triggered restart, and lock contention
# between two real `--oneshot` runs. phases/phase-routes.sh and
# phase-firewall.sh prove route_allowed_ips: false and that an
# operator-added firewall zone survives an apply. phases/phase-reboot.sh
# proves PLAN.md 2.6's "no boot step" claim against a real guest reboot.
#
# Every phase_* function is self-contained: it publishes whatever
# fixture it needs and does not assume any other phase already ran, or
# ran before it. Phases run in the explicit order PHASE_ORDER lists
# below, cheapest and most basic first, not file order or the order
# their comments read in above -- see PHASE_ORDER's own comment for
# why that order was chosen.
#
# Usage:
#   run.sh [--image PATH] [--openwrt-version VERSION] [--port PORT] [--keep-work]
#
# Env (equivalent to the flags above, flags win when both are given):
#   E2E_IMAGE            path to an already-built openwrt.img (raw, not
#                         gzipped). Skips download, checksum verification,
#                         extraction and build entirely -- for iterating on
#                         assertions without paying the ~95s build cost on
#                         every run.
#   OPENWRT_VERSION       OpenWrt release to build, e.g. 24.10.1. Empty
#                         resolves the latest stable release automatically.
#   E2E_SSH_HOST_PORT     host port QEMU forwards to the guest's SSH
#                         (default 2222).
#   E2E_KEEP_WORK         1 keeps the working directory (image, boot log,
#                         SSH key) after the run instead of deleting it.
#   E2E_NAMESPACE         the stunmesh-provd namespace this run creates and
#                         writes into the guest's /etc/config/stunmesh-agent
#                         (default: e2e-namespace).
#   E2E_NODE_ID           the node ID this run registers with `node add`
#                         and writes into /etc/config/stunmesh-agent
#                         (default: e2e-node).
#   E2E_FAKEPROXY_PORT    port the fake dhtproxy listens on, on every
#                         interface (default: 8787).
#
# The controller public key and the proxy URL are never operator-supplied:
# they come from the real `stunmesh-provd init` and the fake dhtproxy this
# run itself starts, so they are always live values, not placeholders.
#
# Requires: curl, sha256sum, unzstd, make (ImageBuilder path); go, make
# (agent and provd build); losetup, blkid, mount, umount, sync, sudo
# (injection); qemu-system-x86_64, timeout, ssh, ssh-keygen (boot and
# control); wg (generating fresh WireGuard key material for a fixture,
# on the host -- see lib.sh's generate_wg_keypair). Each is checked up
# front, by name, so a missing tool is reported before any of it runs.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${HERE}/../../.." && pwd)
CONTRIB_DIR="${REPO_ROOT}/contrib/openwrt"
# shellcheck source=test/e2e/openwrt/lib.sh
. "${HERE}/lib.sh"
# shellcheck source=test/e2e/openwrt/assert.sh
. "${HERE}/assert.sh"

E2E_IMAGE=${E2E_IMAGE:-}
E2E_KEEP_WORK=${E2E_KEEP_WORK:-0}
SSH_PORT=${E2E_SSH_HOST_PORT:-2222}
OPENWRT_VERSION=${OPENWRT_VERSION:-}
OPENWRT_TARGET=x86
OPENWRT_SUBTARGET=64
OPENWRT_PROFILE=generic
OPENWRT_PACKAGES="kmod-wireguard wireguard-tools"

E2E_NAMESPACE=${E2E_NAMESPACE:-e2e-namespace}
E2E_NODE_ID=${E2E_NODE_ID:-e2e-node}
E2E_FAKEPROXY_PORT=${E2E_FAKEPROXY_PORT:-8787}
# refresh_interval in the guest's UCI and config.yaml. Only
# phase-daemon.sh's procd service ticks on it; --oneshot ignores it.
E2E_REFRESH_INTERVAL=${E2E_REFRESH_INTERVAL:-10s}

usage() {
	sed -n '2,44p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--image)
		E2E_IMAGE="$2"
		shift 2
		;;
	--openwrt-version)
		OPENWRT_VERSION="$2"
		shift 2
		;;
	--port)
		SSH_PORT="$2"
		shift 2
		;;
	--keep-work)
		E2E_KEEP_WORK=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "Unknown argument: $1" >&2
		usage >&2
		exit 1
		;;
	esac
done

for cmd in curl sha256sum unzstd make go sync sudo \
	qemu-system-x86_64 timeout ssh ssh-keygen wg; do
	need_cmd "$cmd"
done
# losetup, blkid, mount and umount are invoked via sudo everywhere in this
# harness; they commonly live in /sbin, which a non-root PATH may omit even
# though sudo's own secure_path includes it. Check them the same way they
# are actually run.
for cmd in losetup blkid mount umount; do
	need_cmd_root "$cmd"
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/stunmesh-e2e-openwrt.XXXXXX")
QEMU_PID=""
FAKEPROXY_PID=""
DELAYED_FAKEPROXY_PID=""
MOUNT_DIR=""
LOOP_DEV=""

# cleanup runs on every exit path: normal completion, an assertion failure,
# a dependency or boot failure, and an interrupt (Ctrl-C). It kills QEMU
# and the fake dhtproxy first (a leaked qemu-system-x86_64 or fakeproxy
# process is the harness's worst failure mode for a developer's machine),
# then unwinds any loop-mount left behind by an interrupted
# inject_guest_files, then removes the working directory unless
# --keep-work asked to keep it.
cleanup() {
	local exit_code=$?
	stop_guest
	stop_fake_proxy
	stop_delayed_fake_proxy
	if [[ -n "${MOUNT_DIR:-}" ]]; then
		sudo umount "$MOUNT_DIR" 2>/dev/null || true
		rmdir "$MOUNT_DIR" 2>/dev/null || true
	fi
	if [[ -n "${LOOP_DEV:-}" ]]; then
		sudo losetup -d "$LOOP_DEV" 2>/dev/null || true
	fi
	if [[ "$E2E_KEEP_WORK" == 1 ]]; then
		log "Kept working directory: ${WORK}"
	else
		rm -rf "$WORK"
	fi
	exit "$exit_code"
}
trap cleanup EXIT INT TERM

ensure_kvm_available

if [[ -n "$E2E_IMAGE" ]]; then
	[[ -f "$E2E_IMAGE" ]] || die "No such image: ${E2E_IMAGE}"
	log "Using prebuilt image: ${E2E_IMAGE} (skipping download and build)"
	cp "$E2E_IMAGE" "${WORK}/openwrt.img"
	IMAGE_PATH="${WORK}/openwrt.img"
else
	resolve_openwrt_version
	download_imagebuilder
	extract_imagebuilder
	build_openwrt_image
fi

build_agent_binary
generate_identity_key

build_provd_binary
build_fakeproxy_binary
start_fake_proxy "$E2E_FAKEPROXY_PORT"

setup_controller "$E2E_NAMESPACE" "$E2E_NODE_ID" "$IDENTITY_PUBKEY" "$FAKEPROXY_HOST_URL"
publish_fixture "${HERE}/fixtures/empty" "$E2E_NAMESPACE" "$E2E_NODE_ID"

# The smallest honest check for this item: a real `publish --once` put a
# real bundle to the fake proxy, and that value is actually retrievable
# from it at the DHT key the node will use -- the same GET a node's own
# fetch performs (internal/dhtproxy's package doc). This is not a claim
# about the guest: the guest has not even booted yet, and asserting that
# its agent fetches and applies this bundle is a later item.
assert_output_contains "the published bundle is retrievable from the fake dhtproxy at its DHT key" \
	"curl -fsS ${FAKEPROXY_HOST_URL}/${PUBLISHED_KEY}" '"data"'

ssh-keygen -t ed25519 -N "" -f "${WORK}/e2e_key" -q -C "stunmesh-e2e-openwrt"
inject_guest_files "${WORK}/e2e_key.pub" "$AGENT_BIN" "$IDENTITY_KEY_PATH" \
	"$E2E_NAMESPACE" "$E2E_NODE_ID" "$CONTROLLER_PUBKEY" "$FAKEPROXY_GUEST_URL"

SSH_KEY="${WORK}/e2e_key"
export SSH_PORT SSH_KEY

boot_guest "$IMAGE_PATH" "$SSH_PORT" "${WORK}/boot.log"
wait_for_ssh "$SSH_PORT" "$SSH_KEY"

log "Running phases..."
# declare -F only reports function NAMES, with no per-file origin: if two
# phase files each define the same phase_* name, the second sourced file
# silently overwrites the first and declare -F still shows the name
# exactly once -- the PHASE_ORDER cross-check below would see nothing
# wrong, the shadowed file's checks would simply never run, and the
# suite would report a clean pass. Catch that here, per file, before it
# can happen: source each phase file standalone in a throwaway
# interpreter first (nothing else loaded) to see exactly which phase_*
# names IT defines, independent of what any earlier file already
# defined, then fail loudly the moment a name repeats across files. If
# the standalone probe itself fails to source a file (a real syntax
# error, or a top-level reference to a variable only run.sh/lib.sh
# would normally provide), that is treated as a probe failure and dies
# immediately too -- silently falling back to "this file defines no
# phase_* functions" would let a duplicate slip past undetected, which
# is exactly the failure mode this check exists to prevent.
declare -A PHASE_FUNCTION_FILE=()
for phase in "${HERE}"/phases/phase-*.sh; do
	log "-- loading $(basename "$phase") --"
	if ! PHASE_PROBE_OUTPUT=$(bash -c '. "$1" && declare -F' _ "$phase" 2>&1); then
		die "could not determine phase_* functions in $(basename "$phase"): sourcing it standalone failed: ${PHASE_PROBE_OUTPUT}"
	fi
	mapfile -t FILE_PHASES < <(printf '%s\n' "$PHASE_PROBE_OUTPUT" | awk '{print $3}' | grep '^phase_')
	for fn in "${FILE_PHASES[@]}"; do
		if [[ -n "${PHASE_FUNCTION_FILE[$fn]:-}" ]]; then
			die "phase function '${fn}' is defined in both $(basename "${PHASE_FUNCTION_FILE[$fn]}") and $(basename "$phase") -- the second definition silently shadows the first; rename one of them"
		fi
		PHASE_FUNCTION_FILE[$fn]="$phase"
	done
	# shellcheck source=/dev/null
	. "$phase"
done

# PHASE_ORDER is the deliberate run order, not the accident of
# `declare -F`'s alphabetical listing this replaced. Cheapest, most
# basic checks run first so a broken build fails fast: phase_smoke
# first (only proves boot -> inject -> SSH -> assert, no payload, no
# fetch), phase_payload second (checks the injected payload landed,
# still no fetch). From there the order follows growing scenario
# complexity -- a first fetch, then multi-revision diff/removal,
# routes, an operator-added firewall zone, the procd daemon service, a
# real hotplug event, lock contention between two `--oneshot` runs --
# and phase_reboot_uci_persistence runs last: it costs about 24s (a real
# guest reboot), more than every other phase combined, and a real
# reboot leaves the guest in a freshly booted state that is a poor
# starting point for any phase after it.
#
# Every phase must stay self-contained regardless of this order: it
# publishes whatever fixture it needs and does not assume any other
# phase already ran. This list exists so a reader knows what runs and
# when, not to license one phase depending on another's leftover
# state -- a hidden dependency would make phases un-runnable alone and
# would break the moment this list is reordered again.
PHASE_ORDER=(
	phase_smoke
	phase_payload
	phase_fetch_basic
	phase_diff_removal
	phase_routes
	phase_firewall_survives
	phase_daemon
	phase_hotplug_wan_ifup
	phase_lock_overlap
	phase_reboot_uci_persistence
)

# Cross-check PHASE_ORDER against the phase_* functions actually defined
# by the sourced files, in both directions. A phase file added without a
# matching PHASE_ORDER entry must not silently never run; a stale
# PHASE_ORDER entry with no matching function must not silently be
# skipped either -- declare -F is the ground truth for what exists, and
# by this point it is safe to treat as such: the sourcing loop above has
# already ruled out two files quietly defining the same name, which is
# the one way declare -F's name-only view could otherwise lie about a
# file's checks actually having run.
mapfile -t DEFINED_PHASES < <(declare -F | awk '{print $3}' | grep '^phase_' | sort)
mapfile -t SORTED_PHASE_ORDER < <(printf '%s\n' "${PHASE_ORDER[@]}" | sort)

MISSING_FROM_ORDER=$(comm -23 \
	<(printf '%s\n' "${DEFINED_PHASES[@]}") \
	<(printf '%s\n' "${SORTED_PHASE_ORDER[@]}")) || true
MISSING_FUNCTION=$(comm -13 \
	<(printf '%s\n' "${DEFINED_PHASES[@]}") \
	<(printf '%s\n' "${SORTED_PHASE_ORDER[@]}")) || true

if [[ -n "$MISSING_FROM_ORDER" ]]; then
	die "phase function(s) defined but missing from PHASE_ORDER: ${MISSING_FROM_ORDER}"
fi
if [[ -n "$MISSING_FUNCTION" ]]; then
	die "PHASE_ORDER lists function(s) that do not exist: ${MISSING_FUNCTION}"
fi

for fn in "${PHASE_ORDER[@]}"; do
	log "-- running ${fn} --"
	"$fn"
done

stop_guest
report_assertions
