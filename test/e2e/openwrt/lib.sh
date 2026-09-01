#!/usr/bin/env bash
# lib.sh -- shared mechanics for the OpenWrt e2e harness.
#
# Sourced by run.sh. Every function here does one proven step: resolve the
# release, download and verify the ImageBuilder, build the image, inject
# files by loop-mounting the rootfs, boot QEMU under KVM, wait for SSH, and
# run a command in the guest. These mechanics were measured on a real
# GitHub-hosted runner before this harness existed -- nothing here is
# re-derived or re-measured.
#
# -accel kvm is hardcoded in boot_guest and never falls back to TCG. A TCG
# boot is slow enough to hide the timing-sensitive uci/ubus/netifd bugs this
# harness exists to catch, so a silent fallback would be worse than a loud
# failure.
#
# State this file mutates on the caller's behalf, so run.sh's cleanup trap
# can find anything left behind by a failure or an interrupt:
#   QEMU_PID              set while the guest is running, cleared by
#                         stop_guest. reboot_guest clears and re-sets it
#                         across a real reboot.
#   FAKEPROXY_PID         set while the fake dhtproxy is running, cleared
#                         by stop_fake_proxy.
#   DELAYED_FAKEPROXY_PID set while the delayed fake dhtproxy
#                         (start_delayed_fake_proxy, phase-lock.sh only)
#                         is running, cleared by stop_delayed_fake_proxy.
#   MOUNT_DIR             set while the rootfs partition is mounted,
#                         cleared after.
#   LOOP_DEV              set while the image is loop-attached, cleared
#                         after.
#
# build_agent_binary, build_provd_binary, build_fakeproxy_binary,
# generate_identity_key, start_fake_proxy, start_delayed_fake_proxy and
# setup_controller also set AGENT_BIN, PROVD_BIN, FAKEPROXY_BIN,
# IDENTITY_KEY_PATH, IDENTITY_PUBKEY, FAKEPROXY_HOST_URL,
# FAKEPROXY_GUEST_URL, DELAYED_FAKEPROXY_HOST_URL,
# DELAYED_FAKEPROXY_GUEST_URL, PROVD_ROOT and CONTROLLER_PUBKEY
# respectively -- run.sh reads these to drive the real controller and to
# fill in inject_guest_files.
set -euo pipefail

log() {
	echo "[e2e-openwrt] $*"
}

die() {
	echo "[e2e-openwrt] ERROR: $*" >&2
	exit 1
}

# need_cmd NAME -- fails loudly and specifically when NAME is not on PATH.
# Called once per dependency up front, so a missing tool is reported before
# any network call or build, not halfway through one.
need_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1. Install it and re-run."
}

# need_cmd_root NAME -- like need_cmd, but checks under sudo's PATH instead
# of the caller's. losetup, blkid, mount and umount live in /sbin, which a
# non-root user's PATH often omits even though sudo's secure_path includes
# it. Every call site for these tools already runs them via sudo, so
# checking with the same elevation avoids a false "missing" report.
need_cmd_root() {
	sudo sh -c "command -v '$1'" >/dev/null 2>&1 \
		|| die "Missing dependency: $1 (checked under sudo's PATH). Install it and re-run."
}

# ensure_kvm_available -- fails loudly unless /dev/kvm is read-write for this
# user by the time it returns. It never falls back to TCG: if this function
# does not return cleanly, the run stops here rather than booting slow.
#
# The udev rule and the poll loop are necessary because `udevadm trigger`
# returns before udev finishes applying the rule, so a check right after it
# races the rule and can lose. `udevadm settle` waits for udev's queue to
# drain, which helps but is not a guarantee on every host, so this also
# polls the device mode directly with a bounded timeout.
ensure_kvm_available() {
	if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
		log "/dev/kvm is present and read-write."
		return
	fi

	log "/dev/kvm is not read-write yet. Installing the enable-KVM udev rule..."
	echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
		| sudo tee /etc/udev/rules.d/99-kvm4all.rules >/dev/null
	sudo udevadm control --reload-rules
	sudo udevadm trigger --name-match=kvm
	sudo udevadm settle --timeout=30 || true

	local timeout_seconds=30 start_time waited
	start_time=$(date +%s)
	while [[ ! -e /dev/kvm || ! -r /dev/kvm || ! -w /dev/kvm ]]; do
		waited=$(( $(date +%s) - start_time ))
		if (( waited >= timeout_seconds )); then
			die "/dev/kvm did not become read-write within ${timeout_seconds}s. This harness never falls back to TCG."
		fi
		sleep 0.5
	done
	log "/dev/kvm became read-write after $(( $(date +%s) - start_time ))s."
}

# resolve_openwrt_version -- sets OPENWRT_VERSION to the latest stable
# release, unless it is already set (an operator override). The releases
# index lists every release line OpenWrt ever published, release candidates
# and betas included; a plain "X.Y.Z" name (three numeric components, nothing
# else) is a stable point release, and sorting those as versions gives the
# current stable release with nothing hardcoded.
resolve_openwrt_version() {
	if [[ -n "${OPENWRT_VERSION:-}" ]]; then
		log "Using OpenWrt version override: ${OPENWRT_VERSION}"
		return
	fi

	log "Resolving the latest OpenWrt stable release..."
	local index
	index=$(curl -fsSL https://downloads.openwrt.org/releases/) \
		|| die "Could not fetch the OpenWrt releases index."
	OPENWRT_VERSION=$(echo "$index" \
		| grep -oE 'href="[0-9]+\.[0-9]+\.[0-9]+/"' \
		| sed -E 's/^href="//; s#/"$##' \
		| sort -V \
		| tail -1)
	[[ -n "$OPENWRT_VERSION" ]] || die "Found no stable release in the OpenWrt releases index."
	log "Resolved OpenWrt version: ${OPENWRT_VERSION}"
}

# download_imagebuilder -- downloads the ImageBuilder tarball and its
# sha256sums into $WORK, and fails the run on a checksum mismatch rather than
# building from an unverified download.
download_imagebuilder() {
	local base_url ib_file line
	base_url="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/${OPENWRT_TARGET}/${OPENWRT_SUBTARGET}"
	ib_file="openwrt-imagebuilder-${OPENWRT_VERSION}-${OPENWRT_TARGET}-${OPENWRT_SUBTARGET}.Linux-x86_64.tar.zst"

	log "Downloading the ImageBuilder (${ib_file})..."
	curl -fsSL -o "${WORK}/${ib_file}" "${base_url}/${ib_file}" \
		|| die "Download of the ImageBuilder failed."
	curl -fsSL -o "${WORK}/sha256sums" "${base_url}/sha256sums" \
		|| die "Download of sha256sums failed."

	line=$(grep -F " *${ib_file}" "${WORK}/sha256sums" || true)
	[[ -n "$line" ]] || die "No sha256sums entry for ${ib_file}."
	(cd "$WORK" && echo "$line" | sha256sum -c -) \
		|| die "ImageBuilder checksum verification FAILED for ${ib_file}."

	IMAGEBUILDER_FILE="${WORK}/${ib_file}"
	log "ImageBuilder downloaded and checksum verified."
}

# extract_imagebuilder -- unpacks IMAGEBUILDER_FILE (set by
# download_imagebuilder) into $WORK/imagebuilder and sets IMAGEBUILDER_DIR.
extract_imagebuilder() {
	log "Extracting the ImageBuilder..."
	mkdir -p "${WORK}/imagebuilder"
	tar --use-compress-program=unzstd -xf "$IMAGEBUILDER_FILE" \
		-C "${WORK}/imagebuilder" --strip-components=1 \
		|| die "Extraction of the ImageBuilder failed."
	IMAGEBUILDER_DIR="${WORK}/imagebuilder"
}

# build_openwrt_image -- runs make image against IMAGEBUILDER_DIR, picks the
# ext4-combined output out of the results (make image builds every image
# format the target defines in one pass), decompresses it, and sets
# IMAGE_PATH to the raw image.
build_openwrt_image() {
	log "Building the OpenWrt image (make image, profile=${OPENWRT_PROFILE})..."
	make -C "$IMAGEBUILDER_DIR" image \
		PROFILE="$OPENWRT_PROFILE" \
		PACKAGES="$OPENWRT_PACKAGES" \
		|| die "make image failed."

	local image_gz
	image_gz="${IMAGEBUILDER_DIR}/bin/targets/${OPENWRT_TARGET}/${OPENWRT_SUBTARGET}/openwrt-${OPENWRT_VERSION}-${OPENWRT_TARGET}-${OPENWRT_SUBTARGET}-${OPENWRT_PROFILE}-ext4-combined.img.gz"
	[[ -f "$image_gz" ]] || die "Expected ext4-combined image not found at ${image_gz}."

	log "Decompressing the image..."
	gunzip -c "$image_gz" > "${WORK}/openwrt.img" \
		|| die "Decompression of the built image failed."
	IMAGE_PATH="${WORK}/openwrt.img"
	log "Image ready: ${IMAGE_PATH}"
}

# build_agent_binary -- builds stunmesh-agent for the guest's architecture
# (linux/amd64: this harness always builds the x86-64 OpenWrt target, never
# the mips one committed under dist/) through the repository's own
# Makefile, so this can never drift from how the binary is really built.
# Writes it to $WORK/dist, not the repo's own dist/, so a run never
# clobbers a binary a developer built there by hand. Sets AGENT_BIN.
build_agent_binary() {
	log "Building stunmesh-agent for linux/amd64 (make agent)..."
	make -C "$REPO_ROOT" agent GOOS=linux GOARCH=amd64 DIST="${WORK}/dist" VERSION="e2e-test" \
		|| die "make agent failed."
	AGENT_BIN="${WORK}/dist/stunmesh-agent"
	[[ -x "$AGENT_BIN" ]] || die "Expected agent binary not found at ${AGENT_BIN}."
	log "Agent binary ready: ${AGENT_BIN}"
}

# generate_identity_key -- generates the node identity key with the real
# `stunmesh-agent keygen`, never hand-rolled bytes, so the key on disk is
# exactly what a device would have after an operator ran keygen for real.
# The guest is x86-64 and so is this runner, so the just-built AGENT_BIN
# (linux/amd64) runs directly here; no guest boot is needed to generate it.
#
# keygen only takes --config-dir and always writes "identity.key" inside
# it. Sets IDENTITY_KEY_PATH and IDENTITY_PUBKEY. keygen's stdout is only
# ever the public key; it is captured into a variable, here, for
# setup_controller's `node add` to consume below, and never printed or
# logged, so no key material reaches any harness output.
generate_identity_key() {
	IDENTITY_KEY_PATH="${WORK}/identity.key"
	log "Generating the node identity key (stunmesh-agent keygen)..."
	IDENTITY_PUBKEY=$("$AGENT_BIN" keygen --config-dir "$WORK") \
		|| die "stunmesh-agent keygen failed."
	[[ -f "$IDENTITY_KEY_PATH" ]] || die "keygen did not create ${IDENTITY_KEY_PATH}."
	[[ -n "$IDENTITY_PUBKEY" ]] || die "keygen produced no public key on stdout."
	log "Identity key generated."
}

# generate_wg_keypair -- prints a fresh WireGuard key pair as
# "PRIVATE_KEY PUBLIC_KEY" on one line, using the real `wg` tool. Every
# e2e fixture that needs WireGuard key material (the private key of
# the node's own tunnel, or a peer's public key) calls this instead of
# a fixed, committed key: a fixed key checked into the repo would be a
# real (if throwaway) private key sitting in git history forever, and
# a freshly generated one proves the same thing about the agent's
# uci/ubus calls without ever needing one. Nothing this prints is
# logged; the caller is responsible for keeping the private half out
# of any output the harness itself prints.
generate_wg_keypair() {
	local priv pub
	priv=$(wg genkey) || die "wg genkey failed."
	pub=$(echo "$priv" | wg pubkey) || die "wg pubkey failed."
	echo "${priv} ${pub}"
}

# build_provd_binary -- builds stunmesh-provd for this runner's own
# platform (it is the controller: it runs on the host, never on the
# guest) through the repository's own Makefile, the same way
# build_agent_binary builds the agent -- so this can never drift from how
# the binary is really built. Writes it to $WORK/dist, alongside the
# agent binary. Sets PROVD_BIN.
build_provd_binary() {
	log "Building stunmesh-provd (make provd)..."
	make -C "$REPO_ROOT" provd DIST="${WORK}/dist" VERSION="e2e-test" \
		|| die "make provd failed."
	PROVD_BIN="${WORK}/dist/stunmesh-provd"
	[[ -x "$PROVD_BIN" ]] || die "Expected stunmesh-provd binary not found at ${PROVD_BIN}."
	log "stunmesh-provd binary ready: ${PROVD_BIN}"
}

# build_fakeproxy_binary -- builds the fake dhtproxy
# (test/e2e/openwrt/fakeproxy), a harness-only Go program, not one of the
# two product binaries the Makefile knows about, so a plain `go build` is
# the right tool here, the same way it would be for any other
# harness-only helper. Sets FAKEPROXY_BIN.
build_fakeproxy_binary() {
	log "Building the fake dhtproxy (go build)..."
	(cd "$REPO_ROOT" && go build -o "${WORK}/dist/fakeproxy" ./test/e2e/openwrt/fakeproxy) \
		|| die "Building the fake dhtproxy failed."
	FAKEPROXY_BIN="${WORK}/dist/fakeproxy"
	[[ -x "$FAKEPROXY_BIN" ]] || die "Expected fakeproxy binary not found at ${FAKEPROXY_BIN}."
	log "Fake dhtproxy binary ready: ${FAKEPROXY_BIN}"
}

# start_fake_proxy PORT -- starts the fake dhtproxy (FAKEPROXY_BIN) in the
# background, bound to every interface at PORT, not just 127.0.0.1: the
# guest reaches the host at 10.0.2.2 through QEMU's slirp networking (see
# boot_guest's -netdev user,...), and a loopback-only bind would answer
# this harness's own checks while refusing the guest's fetch (the next
# item). Sets FAKEPROXY_PID, FAKEPROXY_HOST_URL (for stunmesh-provd and
# this harness's own checks, both running on the host) and
# FAKEPROXY_GUEST_URL (the value written into the guest's
# /etc/config/stunmesh-agent). Blocks until the proxy actually answers an HTTP
# request, so nothing after this call can race an unready listener.
start_fake_proxy() {
	local port="$1"
	log "Starting the fake dhtproxy on port ${port}..."
	"$FAKEPROXY_BIN" -addr "0.0.0.0:${port}" >"${WORK}/fakeproxy.log" 2>&1 &
	FAKEPROXY_PID=$!
	FAKEPROXY_HOST_URL="http://127.0.0.1:${port}"
	FAKEPROXY_GUEST_URL="http://10.0.2.2:${port}"
	[[ -n "$FAKEPROXY_HOST_URL" && -n "$FAKEPROXY_GUEST_URL" ]] \
		|| die "Fake dhtproxy URLs were not set for port ${port}."

	# A syntactically valid but certainly-unused dhtkey: any real
	# GET/PUT the harness later performs uses a different key
	# (namespace/node_id derived), so this probe can never collide
	# with real data. A 404 for it proves the server is not just
	# accepting TCP connections but actually running store.ServeHTTP.
	local probe_key="0000000000000000000000000000000000000000"
	local attempt=1 code
	while true; do
		if ! kill -0 "$FAKEPROXY_PID" 2>/dev/null; then
			die "Fake dhtproxy exited before it started listening. Check ${WORK}/fakeproxy.log."
		fi
		code=$(curl -s -o /dev/null -w '%{http_code}' "${FAKEPROXY_HOST_URL}/${probe_key}" 2>/dev/null || true)
		[[ "$code" == "404" ]] && break
		attempt=$((attempt + 1))
		if (( attempt > 50 )); then
			die "Fake dhtproxy did not start listening within 5s. Check ${WORK}/fakeproxy.log."
		fi
		sleep 0.1
	done
	log "Fake dhtproxy is listening (pid=${FAKEPROXY_PID})."
}

# stop_fake_proxy -- kills the fake dhtproxy started by start_fake_proxy,
# if still running. Idempotent, the same as stop_guest.
stop_fake_proxy() {
	[[ -n "${FAKEPROXY_PID:-}" ]] || return 0
	kill "$FAKEPROXY_PID" 2>/dev/null || true
	wait "$FAKEPROXY_PID" 2>/dev/null || true
	FAKEPROXY_PID=""
}

# start_delayed_fake_proxy PORT DELAY -- like start_fake_proxy, but a
# second, independent fakeproxy instance (its own process, its own
# empty value table) started with -get-delay DELAY (a Go duration,
# for example "3s"). Sets DELAYED_FAKEPROXY_PID,
# DELAYED_FAKEPROXY_HOST_URL and DELAYED_FAKEPROXY_GUEST_URL, the
# delayed-instance counterparts of start_fake_proxy's own variables.
#
# phase-lock.sh is the only caller. It needs a GET that stays open
# long enough for a second, real `stunmesh-agent fetch` to reliably
# start while the first still holds the lock (see fakeproxy/main.go's
# getDelay doc comment) -- a delay every other phase's fetches would
# otherwise have to pay too, if this were the same instance
# start_fake_proxy already runs for the rest of the harness.
start_delayed_fake_proxy() {
	local port="$1" delay="$2"
	log "Starting the delayed fake dhtproxy on port ${port} (get-delay ${delay})..."
	"$FAKEPROXY_BIN" -addr "0.0.0.0:${port}" -get-delay "$delay" >"${WORK}/fakeproxy-delayed.log" 2>&1 &
	DELAYED_FAKEPROXY_PID=$!
	DELAYED_FAKEPROXY_HOST_URL="http://127.0.0.1:${port}"
	DELAYED_FAKEPROXY_GUEST_URL="http://10.0.2.2:${port}"
	[[ -n "$DELAYED_FAKEPROXY_HOST_URL" && -n "$DELAYED_FAKEPROXY_GUEST_URL" ]] \
		|| die "Delayed fake dhtproxy URLs were not set for port ${port}."

	# Same readiness probe as start_fake_proxy, deliberately not
	# factored out into a shared helper: the two callers already read
	# fine on their own, and a shared helper would need to somehow
	# hand back which of two different PID/URL variable sets to fill,
	# for no real gain in a file this size.
	local probe_key="0000000000000000000000000000000000000001"
	local attempt=1 code
	while true; do
		if ! kill -0 "$DELAYED_FAKEPROXY_PID" 2>/dev/null; then
			die "Delayed fake dhtproxy exited before it started listening. Check ${WORK}/fakeproxy-delayed.log."
		fi
		code=$(curl -s -o /dev/null -w '%{http_code}' "${DELAYED_FAKEPROXY_HOST_URL}/${probe_key}" 2>/dev/null || true)
		[[ "$code" == "404" ]] && break
		attempt=$((attempt + 1))
		if (( attempt > 50 )); then
			die "Delayed fake dhtproxy did not start listening within 5s. Check ${WORK}/fakeproxy-delayed.log."
		fi
		sleep 0.1
	done
	log "Delayed fake dhtproxy is listening (pid=${DELAYED_FAKEPROXY_PID})."
}

# stop_delayed_fake_proxy -- kills the fake dhtproxy started by
# start_delayed_fake_proxy, if still running. Idempotent, the same as
# stop_fake_proxy.
stop_delayed_fake_proxy() {
	[[ -n "${DELAYED_FAKEPROXY_PID:-}" ]] || return 0
	kill "$DELAYED_FAKEPROXY_PID" 2>/dev/null || true
	wait "$DELAYED_FAKEPROXY_PID" 2>/dev/null || true
	DELAYED_FAKEPROXY_PID=""
}

# setup_controller NAMESPACE NODE_ID IDENTITY_PUBKEY PROXY_URL -- stands
# up the real controller side of a deployment through the actual
# stunmesh-provd binary: `init` makes the namespace and its controller
# key pair, `node add` registers this node with its identity public key.
# Sets PROVD_ROOT (the --dir every stunmesh-provd invocation in this
# harness uses) and CONTROLLER_PUBKEY (the value inject_guest_files
# writes into the guest's /etc/config/stunmesh-agent).
#
# Ordering matters, the same way it would for a real operator: the node's
# identity key pair must already exist (generate_identity_key, which
# run.sh calls before this), because `node add` needs its public half as
# an argument. init's controller key pair has no such dependency and
# could in principle run at any point before publish -- it runs first
# here only because `node add` needs an initialized namespace to add the
# node into.
setup_controller() {
	local namespace="$1" node_id="$2" identity_pubkey="$3" proxy_url="$4"
	PROVD_ROOT="${WORK}/provd-root"

	log "Running stunmesh-provd init ${namespace}..."
	"$PROVD_BIN" --dir "$PROVD_ROOT" init "$namespace" >/dev/null \
		|| die "stunmesh-provd init failed."

	local pubkey_path="${PROVD_ROOT}/${namespace}/controller.pub"
	[[ -f "$pubkey_path" ]] || die "init did not write ${pubkey_path}."
	CONTROLLER_PUBKEY=$(cat "$pubkey_path")
	[[ -n "$CONTROLLER_PUBKEY" ]] || die "${pubkey_path} is empty."

	point_proxies_at "$namespace" "$proxy_url"

	log "Running stunmesh-provd node add ${namespace} ${node_id}..."
	"$PROVD_BIN" --dir "$PROVD_ROOT" node add "$namespace" "$node_id" "$identity_pubkey" >/dev/null \
		|| die "stunmesh-provd node add failed."
	log "Controller ready: namespace=${namespace} node_id=${node_id}"
}

# point_proxies_at NAMESPACE PROXY_URL -- overwrites
# <namespace>/provd.yaml's proxy list with PROXY_URL alone, replacing the
# default Jami proxies `init` wrote (PLAN.md 7.3, init_cmd.go's
# defaultProvdYAML). provd.yaml is one of the files PLAN.md 7.1 names as
# the operator's to edit; this harness plays the operator's part here the
# same way it hand-writes /etc/config/network for the guest.
point_proxies_at() {
	local namespace="$1" proxy_url="$2"
	local path="${PROVD_ROOT}/${namespace}/provd.yaml"
	cat >"$path" <<EOF
plugins:
  dht:
    type: dhtproxy
    proxies:
      - ${proxy_url}
use_plugin: dht
republish_interval: 5m
EOF
}

# publish_fixture FIXTURE_DIR NAMESPACE NODE_ID -- copies FIXTURE_DIR's
# wg.yaml and stunmesh.yaml over the node's own, then runs the real
# `stunmesh-provd publish --once` and parses its own stdout for the DHT
# key it reports (the same "published ns/node: key=..." line
# printPublishReport prints for a real operator, see
# cmd/stunmesh-provd/publish_cmd.go). Sets PUBLISHED_KEY.
#
# Fixtures live under test/e2e/openwrt/fixtures/ as files, not as inline
# shell strings here: a later item rewrites wg.yaml/stunmesh.yaml between
# phases and re-publishes, and every phase that needs a new bundle on the
# fake proxy only has to add a fixture directory and call this function
# again with it -- no shell-string plumbing to add alongside it.
publish_fixture() {
	local fixture_dir="$1" namespace="$2" node_id="$3"
	local node_dir="${PROVD_ROOT}/${namespace}/nodes/${node_id}"

	[[ -f "${fixture_dir}/wg.yaml" ]] || die "Fixture ${fixture_dir} has no wg.yaml."
	[[ -f "${fixture_dir}/stunmesh.yaml" ]] || die "Fixture ${fixture_dir} has no stunmesh.yaml."
	cp "${fixture_dir}/wg.yaml" "${node_dir}/wg.yaml"
	cp "${fixture_dir}/stunmesh.yaml" "${node_dir}/stunmesh.yaml"

	log "Publishing fixture $(basename "$fixture_dir") for ${namespace}/${node_id}..."
	local output
	output=$("$PROVD_BIN" --dir "$PROVD_ROOT" publish --namespace "$namespace" --once) \
		|| die "stunmesh-provd publish failed: ${output}"

	PUBLISHED_KEY=$(echo "$output" | grep -oE 'key=[0-9a-f]{40}' | head -1 | cut -d= -f2)
	[[ -n "$PUBLISHED_KEY" ]] || die "Could not find a DHT key in publish output: ${output}"
	log "Published, DHT key: ${PUBLISHED_KEY}"
}

# write_guest_config PATH PROXY_URL -- writes a config.yaml to PATH in
# the already-booted guest, pointed at PROXY_URL, using
# E2E_NAMESPACE/E2E_NODE_ID/CONTROLLER_PUBKEY. phase-lock.sh's only
# caller: its second fetch needs its own config.yaml pointed at the
# delayed proxy, since the primary config.yaml stays pointed at the
# main fake dhtproxy every other phase uses.
#
# Piped through ssh stdin, not expanded into the remote command line:
# PROXY_URL and the controller pubkey can both contain characters a
# double-quoted remote command would need escaping for, and the guest's
# busybox has no base64 applet.
write_guest_config() {
	local path="$1" proxy_url="$2" content
	content=$(cat <<YAML
namespace: "${E2E_NAMESPACE}"
node_id: "${E2E_NODE_ID}"
controller_pubkey: "${CONTROLLER_PUBKEY}"
identity_key: "/etc/stunmesh/agent/identity.key"
last: "/etc/stunmesh/agent/last.json"
lock: "/var/lock/stunmesh-agent.lock"
use_plugin: "e2e"
plugins:
  e2e:
    type: "dhtproxy"
    proxies:
      - "${proxy_url}"
YAML
	)
	printf '%s\n' "$content" | guest_exec "$SSH_PORT" "$SSH_KEY" \
		"cat > '${path}' && chmod 0600 '${path}'" \
		|| die "Could not write ${path} in the guest."
}

# inject_guest_files PUBKEY_PATH AGENT_BIN IDENTITY_KEY NAMESPACE NODE_ID
#   CONTROLLER_PUBKEY PROXY_URL -- loop-mounts IMAGE_PATH's rootfs partition
# and writes everything a provisioned node needs before first boot: the SSH
# key and network config the harness itself needs to reach the guest, plus
# the full stunmesh-agent payload -- binary, identity key,
# /etc/config/stunmesh-agent, the real init and hotplug scripts from
# contrib/openwrt, and /etc/stunmesh/agent/config.yaml itself (same
# values as the UCI section, so both agree). Writing config.yaml
# directly lets most phases run `stunmesh-agent --oneshot` without
# starting the procd service first; phase-daemon.sh is the one phase
# that exercises UCI -> config.yaml generation through the real init
# script. After this, the guest looks exactly like a freshly flashed
# device an operator has just finished the manual key exchange on,
# except nothing has fetched anything yet.
#
# A stock OpenWrt image ships no /etc/config/network at all -- /etc/board.d
# generates it on first boot from board-detection logic, and the default it
# would pick (static 192.168.1.1) is unreachable through QEMU's user-mode
# networking. This writes lan on DHCP instead, which lands the guest in
# QEMU's own 10.0.2.0/24 network where a plain hostfwd already reaches it.
#
# The rootfs is selected by content, not by filesystem type: the boot
# partition on this image is ext4 too, so "the ext4 partition" is ambiguous.
# Each ext4 candidate is mounted read-only and kept only if it has
# /etc/openwrt_release or an executable /sbin/init.
#
# namespace, node_id, controller_pubkey and proxy_url are parameters, not
# hardcoded: the next item (the real controller and fake dhtproxy) only has
# to supply its own values through these same four positions.
inject_guest_files() {
	local pubkey="$1" agent_bin="$2" identity_key="$3" \
		namespace="$4" node_id="$5" controller_pubkey="$6" proxy_url="$7"
	log "Injecting the network config, SSH key and stunmesh-agent payload into ${IMAGE_PATH}..."

	LOOP_DEV=$(sudo losetup -fP --show "$IMAGE_PATH") || die "losetup failed to attach ${IMAGE_PATH}."
	sudo udevadm settle --timeout=10 2>/dev/null || true

	local part fstype probe_dir rootfs_part=""
	for part in "${LOOP_DEV}"p*; do
		fstype=$(sudo blkid -o value -s TYPE "$part" 2>/dev/null || true)
		[[ "$fstype" == "ext4" ]] || continue
		probe_dir=$(mktemp -d)
		if sudo mount -o ro "$part" "$probe_dir" 2>/dev/null; then
			if [[ -f "${probe_dir}/etc/openwrt_release" || -x "${probe_dir}/sbin/init" ]]; then
				sudo umount "$probe_dir"
				rmdir "$probe_dir"
				rootfs_part="$part"
				break
			fi
			sudo umount "$probe_dir"
		fi
		rmdir "$probe_dir"
	done
	if [[ -z "$rootfs_part" ]]; then
		sudo losetup -d "$LOOP_DEV"
		LOOP_DEV=""
		die "Found no ext4 partition with /etc/openwrt_release or /sbin/init on ${IMAGE_PATH}."
	fi

	MOUNT_DIR=$(mktemp -d)
	sudo mount "$rootfs_part" "$MOUNT_DIR" || die "Mounting ${rootfs_part} failed."

	sudo mkdir -p "${MOUNT_DIR}/etc/config"
	sudo tee "${MOUNT_DIR}/etc/config/network" >/dev/null <<'NETCONF'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config globals 'globals'
	option ula_prefix 'fd00::/48'

config interface 'lan'
	option device 'eth0'
	option proto 'dhcp'
NETCONF

	sudo mkdir -p "${MOUNT_DIR}/etc/dropbear"
	sudo cp "$pubkey" "${MOUNT_DIR}/etc/dropbear/authorized_keys"
	sudo chmod 600 "${MOUNT_DIR}/etc/dropbear/authorized_keys"

	log "Installing the stunmesh-agent binary..."
	sudo install -m 0755 "$agent_bin" "${MOUNT_DIR}/usr/sbin/stunmesh-agent"

	# The identity key file itself is 0600, the same as a real device
	# (contrib/openwrt/README.md section 2); /etc/config/stunmesh-agent
	# only holds its path, at 0644, set explicitly below since a real
	# device ships it that way and nothing in it is secret.
	log "Installing the node identity key..."
	sudo mkdir -p "${MOUNT_DIR}/etc/stunmesh/agent"
	sudo install -m 0600 "$identity_key" "${MOUNT_DIR}/etc/stunmesh/agent/identity.key"

	log "Writing /etc/config/stunmesh-agent..."
	sudo tee "${MOUNT_DIR}/etc/config/stunmesh-agent" >/dev/null <<STUNMESH_AGENT_UCI
config stunmesh-agent 'main'
	option namespace            '${namespace}'
	option node_id              '${node_id}'
	option controller_pubkey    '${controller_pubkey}'
	option use_plugin           'e2e'
	option refresh_interval     '${E2E_REFRESH_INTERVAL}'
	option full_apply_interval  '0'
	option identity_key         '/etc/stunmesh/agent/identity.key'
	option last                 '/etc/stunmesh/agent/last.json'
	option lock                 '/var/lock/stunmesh-agent.lock'

config stunmesh-agent-plugin 'e2e'
	option type    'dhtproxy'
	list   proxies '${proxy_url}'
STUNMESH_AGENT_UCI
	sudo chmod 0644 "${MOUNT_DIR}/etc/config/stunmesh-agent"

	# Written directly, not only derived from UCI at boot -- see this
	# function's own doc comment above for why both exist and why they
	# carry the same values.
	log "Writing /etc/stunmesh/agent/config.yaml..."
	sudo tee "${MOUNT_DIR}/etc/stunmesh/agent/config.yaml" >/dev/null <<CONFIG_YAML
namespace: "${namespace}"
node_id: "${node_id}"
controller_pubkey: "${controller_pubkey}"
identity_key: "/etc/stunmesh/agent/identity.key"
last: "/etc/stunmesh/agent/last.json"
lock: "/var/lock/stunmesh-agent.lock"
use_plugin: "e2e"
plugins:
  e2e:
    type: "dhtproxy"
    proxies:
      - "${proxy_url}"
CONFIG_YAML
	sudo chmod 0600 "${MOUNT_DIR}/etc/stunmesh/agent/config.yaml"

	# The real init and hotplug scripts, installed as-is from contrib/ --
	# never a copy kept in this harness, which would drift from what
	# actually ships and stop testing it.
	log "Installing the init and hotplug scripts from contrib/openwrt..."
	sudo install -m 0755 "${CONTRIB_DIR}/stunmesh-agent.init" \
		"${MOUNT_DIR}/etc/init.d/stunmesh-agent"
	sudo mkdir -p "${MOUNT_DIR}/etc/hotplug.d/iface"
	sudo install -m 0755 "${CONTRIB_DIR}/hotplug-iface" \
		"${MOUNT_DIR}/etc/hotplug.d/iface/95-stunmesh-agent"

	sync
	sudo umount "$MOUNT_DIR"
	rmdir "$MOUNT_DIR"
	MOUNT_DIR=""
	sudo losetup -d "$LOOP_DEV"
	LOOP_DEV=""
	log "Injection complete."
}

# boot_guest IMAGE PORT LOG_FILE -- starts QEMU in the background under
# -accel kvm with virtio-net-pci (measured 18s boot-to-SSH on the runner,
# versus 22s for e1000) and sets QEMU_PID. The whole invocation is wrapped in
# `timeout` as a second, independent bound against a hung guest, on top of
# wait_for_ssh's own attempt bound below.
boot_guest() {
	local image="$1" port="$2" log_file="$3"
	local boot_timeout_seconds="${BOOT_TIMEOUT_SECONDS:-180}"

	log "Booting the guest under KVM (virtio-net-pci, hostfwd tcp::${port}-:22)..."
	timeout "$boot_timeout_seconds" qemu-system-x86_64 \
		-accel kvm \
		-machine pc \
		-cpu host \
		-m 256 \
		-smp 2 \
		-drive "file=${image},format=raw,if=virtio" \
		-netdev "user,id=net0,hostfwd=tcp::${port}-:22" \
		-device virtio-net-pci,netdev=net0 \
		-display none \
		-serial "file:${log_file}" \
		-monitor none \
		-no-reboot &
	QEMU_PID=$!
	log "QEMU started, pid=${QEMU_PID} (bounded to ${boot_timeout_seconds}s)."
}

# stop_guest -- kills the guest started by boot_guest, if still running.
# Idempotent: safe to call more than once (the cleanup trap does), and safe
# to call after the guest already exited on its own.
stop_guest() {
	[[ -n "${QEMU_PID:-}" ]] || return 0
	kill "$QEMU_PID" 2>/dev/null || true
	wait "$QEMU_PID" 2>/dev/null || true
	QEMU_PID=""
}

# wait_for_ssh PORT KEY [ATTEMPTS] [INTERVAL_SECONDS] -- blocks until a
# key-based SSH login succeeds, or fails loudly. Bounded by ATTEMPTS *
# INTERVAL_SECONDS (default 90 * 2 = 180s), matching boot_guest's own
# `timeout` bound. Also fails immediately, with a distinct message, if QEMU
# has already exited -- that is a different failure than "never came up" and
# deserves a different diagnosis.
wait_for_ssh() {
	local port="$1" key="$2"
	local attempts="${3:-90}" interval="${4:-2}"
	local attempt=1 start_epoch
	start_epoch=$(date +%s)

	while (( attempt <= attempts )); do
		if [[ -n "${QEMU_PID:-}" ]] && ! kill -0 "$QEMU_PID" 2>/dev/null; then
			die "QEMU exited before SSH came up. Check the boot log for the guest's console output."
		fi
		if ssh -i "$key" \
			-o StrictHostKeyChecking=no \
			-o UserKnownHostsFile=/dev/null \
			-o ConnectTimeout=2 \
			-o BatchMode=yes \
			-p "$port" root@127.0.0.1 true 2>/dev/null; then
			log "SSH is up after $(( $(date +%s) - start_epoch ))s."
			return
		fi
		sleep "$interval"
		attempt=$((attempt + 1))
	done
	die "SSH never came up within $(( attempts * interval ))s. The guest booted but is not answering SSH, or networking/injection is broken."
}

# guest_exec PORT KEY CMD -- runs CMD (a single command string) in the guest
# over SSH and returns its exit status. Used directly by run.sh, and by
# assert.sh's assertion functions.
guest_exec() {
	local port="$1" key="$2" cmd="$3"
	ssh -i "$key" \
		-o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null \
		-o BatchMode=yes \
		-o ConnectTimeout=5 \
		-p "$port" root@127.0.0.1 "$cmd"
}

# guest_capture PORT KEY CMD [FALLBACK] -- like `var=$(guest_exec ...)`,
# except a failed CMD (for example, reading a file an earlier failed
# assertion left missing) never propagates CMD's nonzero exit as a
# script-aborting error. On failure this prints FALLBACK *after*
# whatever CMD already wrote to stdout, not instead of it -- the two
# are concatenated, not swapped. FALLBACK is only correct for a CMD
# that writes nothing on failure (sha256sum or wc on a missing file,
# for example), so a failed read is the only thing FALLBACK stands in
# for. A CMD that can print a real, meaningful value and still exit
# nonzero in a normal case (`grep -c` on no match, for instance) must
# absorb that exit itself, with its own trailing `|| true`, so the
# value it already printed reaches the caller unchanged -- a FALLBACK
# here would land appended after that real value, not in place of it.
#
# assert.sh's assertions deliberately never stop the run on failure
# (see assert.sh's own top comment), so a plain `var=$(guest_exec
# ...)` used for a before/after capture defeats that under this
# harness's `set -euo pipefail`: the read itself aborts the whole
# script the instant its file is missing, skips every later phase,
# and buries report_assertions' summary. Capturing through this
# instead means the read always succeeds at the shell level.
#
# FALLBACK given (e.g. phase-lock.sh's "0" for a before-any-action
# count): returned as-is on failure, because it is a real, meaningful
# default value the caller chose, not just an error flag -- the
# caller's own arithmetic or comparison still needs to work with it.
#
# FALLBACK omitted: returns a sentinel unique to *this call*
# ("GUEST_CAPTURE_FAILED:<nanoseconds>-<random>"), not one fixed
# string. A fixed sentinel would make a before/after assert_equal
# report a false "ok" if the same guest command failed identically on
# both sides (for example, a file that was missing before the second
# fetch and is still missing after it) -- exactly the silent pass this
# guard exists to prevent, not reproduce.
#
# CMD's stderr is left alone, not redirected to /dev/null: a capture
# that fails for an unexpected reason (a dropped SSH connection, not
# the missing-file case this exists for) still needs its diagnostic
# on the console, the same as a plain guest_exec failure would leave
# visible.
#
# Several phases do this kind of before/after (or single-value)
# capture; this is the one place that owns the guard so each phase
# does not reinvent it.
guest_capture() {
	local port="$1" key="$2" cmd="$3"
	if [[ $# -ge 4 ]]; then
		guest_exec "$port" "$key" "$cmd" || echo "$4"
	else
		guest_exec "$port" "$key" "$cmd" || echo "GUEST_CAPTURE_FAILED:$(date +%s%N)-$RANDOM"
	fi
}

# guest_capture_failed VALUE -- true when VALUE is one of
# guest_capture's own no-FALLBACK sentinels, i.e. the read behind it
# never reached the guest. Callers that need to do arithmetic on a
# no-FALLBACK capture (a before/after delta, for example) cannot rely
# on the sentinel simply losing an equality or substring check the
# way phase-diff-removal.sh's ifindex_of comparisons do -- feeding it
# to `$(( ))` is a bash error, not a clean "not equal", so they must
# recognize it explicitly before doing arithmetic and record a named
# assertion failure instead. What to do about a failed capture differs
# by caller (a single before/after pair vs. several sharing one
# delta-and-compare helper), so only the recognizing predicate lives
# here; the response stays at each call site.
guest_capture_failed() {
	[[ "$1" == GUEST_CAPTURE_FAILED:* ]]
}

# reboot_guest IMAGE PORT KEY LOG_FILE -- reboots the running guest and
# proves it came back from a real reboot, not a second fresh boot:
# phase-reboot.sh's whole point (PLAN.md 2.6, "No boot step. UCI is
# persistent.") only holds if the guest that answers SSH afterwards is
# the same disk having actually restarted, not a new VM.
#
# Sends "reboot" over SSH -- the connection drops as the guest goes
# down, so its own exit status is meaningless and ignored. Then waits
# for QEMU_PID to exit: boot_guest's -no-reboot makes a guest-issued
# reset terminate QEMU instead of resetting the VM in place, so "the
# guest is down" is only true once that process is gone, not the
# instant the SSH command returns. Once it is gone, this calls
# boot_guest and wait_for_ssh again on the same IMAGE -- the very disk
# the just-exited guest wrote its own UCI commits to, not a copy.
#
# Bounded to reboot_timeout_seconds (default 60s) waiting for QEMU to
# exit, the same pattern boot_guest's own `timeout` and wait_for_ssh's
# attempt bound use: a hung shutdown fails loudly here instead of
# wait_for_ssh timing out later with a misleading "never came up".
reboot_guest() {
	local image="$1" port="$2" key="$3" log_file="$4"
	local reboot_timeout_seconds="${REBOOT_TIMEOUT_SECONDS:-60}"

	log "Rebooting the guest..."
	guest_exec "$port" "$key" "sync; reboot" >/dev/null 2>&1 || true

	local waited=0
	while [[ -n "${QEMU_PID:-}" ]] && kill -0 "$QEMU_PID" 2>/dev/null; do
		if (( waited >= reboot_timeout_seconds )); then
			die "QEMU did not exit within ${reboot_timeout_seconds}s of the guest-issued reboot. -no-reboot should have made it terminate on reset."
		fi
		sleep 1
		waited=$((waited + 1))
	done
	log "QEMU exited after the guest's reboot request (waited ${waited}s); booting it again from the same image."
	QEMU_PID=""

	boot_guest "$image" "$port" "$log_file"
	wait_for_ssh "$port" "$key"
}
