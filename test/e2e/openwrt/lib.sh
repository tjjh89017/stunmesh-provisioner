#!/usr/bin/env bash
# lib.sh -- shared mechanics for the OpenWrt e2e harness.
#
# Sourced by run.sh. Every function here does one proven step: resolve the
# release, download and verify the ImageBuilder, build the image, inject
# files by loop-mounting the rootfs, boot QEMU under KVM, wait for SSH, and
# run a command in the guest. The mechanics are lifted verbatim from
# .github/workflows/probe.yml, which measured them on a real GitHub-hosted
# runner -- nothing here is re-derived or re-measured.
#
# -accel kvm is hardcoded in boot_guest and never falls back to TCG. A TCG
# boot is slow enough to hide the timing-sensitive uci/ubus/netifd bugs this
# harness exists to catch, so a silent fallback would be worse than a loud
# failure.
#
# State this file mutates on the caller's behalf, so run.sh's cleanup trap
# can find anything left behind by a failure or an interrupt:
#   QEMU_PID   set while the guest is running, cleared by stop_guest.
#   MOUNT_DIR  set while the rootfs partition is mounted, cleared after.
#   LOOP_DEV   set while the image is loop-attached, cleared after.
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
# The udev rule and the poll loop are the exact steps
# .github/workflows/probe.yml proved necessary: `udevadm trigger` returns
# before udev finishes applying the rule, so a check right after it races the
# rule and can lose. `udevadm settle` waits for udev's queue to drain, which
# helps but is not a guarantee on every host, so this also polls the device
# mode directly with a bounded timeout.
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

# inject_guest_files PUBKEY_PATH -- loop-mounts IMAGE_PATH's rootfs partition
# and writes a DHCP lan config plus an authorized_keys file for root, so the
# guest becomes reachable over "hostfwd=tcp::PORT-:22" on first boot.
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
# This is the SKELETON injection only: network config and an SSH key, no
# stunmesh-agent payload. A later item extends this function's call site to
# also inject the agent binary and its config.
inject_guest_files() {
	local pubkey="$1"
	log "Injecting network config and SSH key into ${IMAGE_PATH}..."

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
