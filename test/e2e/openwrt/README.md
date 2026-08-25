# OpenWrt e2e harness

This harness boots a real OpenWrt x86-64 VM under KVM and runs the real
`stunmesh-agent` binary against it. It proves the agent's `uci`, `ubus`
and hotplug calls do what the code intends on real `netifd` and a real
kernel. `run.sh` is the entry point and the source of truth for what
runs; this document explains how to use it and why it is built the way
it is.

## 1. What this proves, and what it does not

The Go unit tests run `stunmesh-agent` against a fake `exec` (PLAN.md
section 5). They prove the agent builds the right UCI commands. They
cannot prove `netifd` actually does the right thing with those
commands: whether `ubus call network reload` really reconfigures a
running WireGuard interface, whether a removed UCI section really
tears the kernel device down, whether a reboot really brings the
tunnel back from UCI alone. This harness answers those questions
against a real guest.

It found a real defect this way: a plain `network reload` does not
push a peer-only change into the kernel, so `fetch_apply.go` now runs
`ifup <iface>` for every new or changed interface. `phases/phase-diff-removal.sh`
is the check that caught it.

Be precise about what it does not prove:

- It builds and runs the `linux/amd64` `stunmesh-agent` binary, not
  the `mips_24kc` binary that ships to real routers. The two share the
  same source; only the target architecture differs.
- It talks to `test/e2e/openwrt/fakeproxy`, a minimal stand-in for
  `dhtproxy` (see section 6), not a real Jami `dhtproxy` instance and
  not real OpenDHT.
- `stunmesh-go` itself is stubbed out (see section 8). Nothing here
  tests `stunmesh-go`.

## 2. Running it locally

Requires: `curl`, `sha256sum`, `unzstd`, `make`, `go`, `sync`, `sudo`,
`qemu-system-x86_64`, `timeout`, `ssh`, `ssh-keygen`, `wg` on `PATH`,
plus `losetup`, `blkid`, `mount`, `umount` reachable under `sudo`
(these commonly live in `/sbin`, which a non-root `PATH` may omit even
though `sudo`'s `secure_path` includes it). `run.sh` checks every one
of these by name before it does anything else, so a missing tool is
reported up front, not halfway through a build.

It also needs `/dev/kvm`, read-write. On a machine where it is not
already read-write, `run.sh` installs a `udev` rule to fix that itself
(see section 8); it needs `sudo` for this too. The harness never falls
back to software emulation (TCG): a TCG boot is slow enough to hide
the timing-sensitive bugs this harness exists to catch, so a missing
KVM device is a loud failure, not a silent slowdown.

Run it from the repository root:

```
test/e2e/openwrt/run.sh
```

A from-scratch run (downloading and building the OpenWrt image) takes
about 4m20s locally. In CI, the whole job takes 4m27s.

## 3. Iterating quickly with `--image`

Most of a from-scratch run's time goes to the ImageBuilder download
and `make image` (about 95s), not to anything this harness's own
assertions exercise. Build the image once, keep it, and reuse it:

```
E2E_KEEP_WORK=1 test/e2e/openwrt/run.sh
# note the "Kept working directory: ..." line it prints, then:
test/e2e/openwrt/run.sh --image /path/to/that/work/dir/openwrt.img
```

`--image` skips the download, checksum verification, extraction and
build entirely. A run with `--image` takes about 20-40s: essentially
just boot, inject and the phases themselves.

## 4. Flags and environment variables

Flags win when both a flag and its equivalent environment variable are
given.

| Flag | Env var | Meaning |
|---|---|---|
| `--image PATH` | `E2E_IMAGE` | Path to an already-built `openwrt.img` (raw, not gzipped). Skips download, checksum verification, extraction and build. |
| `--openwrt-version VERSION` | `OPENWRT_VERSION` | OpenWrt release to build, e.g. `24.10.1`. Empty resolves the latest stable release automatically. |
| `--port PORT` | `E2E_SSH_HOST_PORT` | Host port QEMU forwards to the guest's SSH (default `2222`). |
| `--keep-work` | `E2E_KEEP_WORK` | `1` keeps the working directory (image, boot log, SSH key) after the run instead of deleting it. |
| `-h`, `--help` | -- | Print the usage comment at the top of `run.sh`. |

Env-only:

| Env var | Meaning |
|---|---|
| `E2E_NAMESPACE` | The `stunmesh-provd` namespace this run creates and writes into the guest's `/etc/config/provd` (default `e2e-namespace`). |
| `E2E_NODE_ID` | The node ID this run registers with `node add` and writes into `/etc/config/provd` (default `e2e-node`). |
| `E2E_FAKEPROXY_PORT` | Port the main fake dhtproxy listens on, on every interface (default `8787`). |

The controller public key and the proxy URL that end up in the guest's
`/etc/config/provd` are never operator-supplied placeholders: they
come from the real `stunmesh-provd init` and the fake dhtproxy this
run itself starts, so they are always live values.

A few more env vars exist for narrower needs, undocumented in
`run.sh`'s own usage banner because they are rarely worth changing:
`BOOT_TIMEOUT_SECONDS` (default 180, `lib.sh`'s `boot_guest`),
`REBOOT_TIMEOUT_SECONDS` (default 60, `lib.sh`'s `reboot_guest`), and
`E2E_LOCK_FAKEPROXY_PORT` (default 8788, the second fakeproxy instance
`phases/phase-lock.sh` starts for its lock-contention check).

## 5. What each phase asserts

Every `phase_*` function is self-contained: it publishes whatever
fixture it needs and does not assume any other phase already ran, in
any order. This section lists them in the order `run.sh`'s
`PHASE_ORDER` array actually runs them (see section 8 on why that
order was chosen, and why it is no longer file order or alphabetical
order).

- **`phase_smoke`** (`phases/phase-smoke.sh`) -- no payload, no
  bundle. Only checks that `ubus` answers and `uci show network`
  names the `lan` interface this harness's own injection wrote. It
  exists to prove boot -> inject -> SSH -> assert works end to end,
  independent of anything `stunmesh-agent`-specific.
- **`phase_payload`** (`phases/phase-payload.sh`) -- no fetch here:
  checks the injected payload landed correctly before anything runs.
  `stunmesh-agent --version` runs; the init and hotplug scripts are
  installed, executable, and byte-identical (by SHA-256) to the real
  files under `contrib/openwrt/`; the identity key is mode 0600;
  `/etc/config/provd` parses as UCI; the `stunmesh` stand-in runs and
  logs the action it was given.
- **`phase_fetch_basic`** (`phases/phase-fetch-basic.sh`) -- the
  first real fetch: publishes one interface with one peer, fetches it,
  and reads back `wg show`, `ubus call network.interface.wg0 status`
  and the `uci` sections it should have created, plus `last.json`'s
  path and mode (0600). A second fetch of the same bundle exits 3 (no
  change) and leaves `/etc/config/network`, `last.json` and the
  `stunmesh` stand-in's action log byte-identical.
- **`phase_diff_removal`** (`phases/phase-diff-removal.sh`) --
  publishes and fetches four bundle revisions on the same guest: (v1)
  a two-interface baseline; (v2) only `wg1`'s peer key changes, wg0
  untouched -- checks that a plain `network reload`, with no explicit
  `ifup`, really does push the new peer into the kernel, and that
  `wg0`'s netdev (by its unchanged `ifindex`) was not restarted; (v3)
  `wg1` removed from the bundle -- checks its UCI sections and kernel
  netdev are both gone, `wg0` still untouched; (v4) full teardown --
  checks every agent-created UCI section and netdev is gone, the
  `stunmesh` stand-in was told `stop`, and a UCI section this phase
  added by hand (never recorded in the agent's `last.json`) survives.
- **`phase_routes`** (`phases/phase-routes.sh`) -- publishes a bundle
  with `route_allowed_ips: false` and an explicit `routes:` list.
  Checks the kernel's main routing table for `wg0` holds exactly the
  listed routes (with the second entry's metric) and nothing derived
  from the peer's own `allowed_ips`.
- **`phase_firewall_survives`** (`phases/phase-firewall.sh`) -- adds a
  firewall zone naming `wg0` by hand (the operator's one-time step,
  PLAN.md 2.7), then publishes a second revision that forces `wg0`'s
  own UCI sections to be deleted and recreated. Checks the hand-added
  zone, and its reference to `wg0`, survive untouched.
- **`phase_cron_line`** (`phases/phase-cron.sh`) -- `service
  stunmesh-agent start` installs a tagged cron line using
  `fetch_interval` from `/etc/config/provd`, leaves a foreign
  crontab line alone, and a real `crond` picks up the new file
  (checked via a fresh `crond (busybox...` syslog line). A repeated
  `start` leaves exactly one managed line, never two. `stop` removes
  the managed line, leaves the foreign one, and the crontab file's
  mode survives every rewrite.
- **`phase_hotplug_wan_ifup`** (`phases/phase-hotplug.sh`) -- defines
  two bridge-backed logical interfaces (`wan`, `testif`) with no real
  hardware behind them, then fires real `ifup`/`ifdown` through the
  real tools. A real `ifup wan` runs exactly one hotplug-triggered
  fetch (counted via a `hotplug fetch` syslog line the hotplug script
  alone logs); `ifdown wan` and `ifup testif` run none.
- **`phase_lock_overlap`** (`phases/phase-lock.sh`) -- launches two
  real `stunmesh-agent fetch` processes in the guest, staggered by 1s,
  against a second fake dhtproxy instance that deliberately delays its
  GET so the two overlap for real. Checks exactly one of the two logs
  the lock-contention message, only the winner's action reaches the
  `stunmesh` stand-in, and the winner's bundle reaches the kernel.
- **`phase_reboot_uci_persistence`** (`phases/phase-reboot.sh`) --
  applies a known-good bundle, stops the fake dhtproxy entirely (so no
  boot-delay fetch, cron line or hotplug event could possibly reach
  it), reboots the guest for real, and checks `wg0` is back up with
  the same key and peer, `/etc/config/network` is byte-identical
  across the reboot, and the `stunmesh` stand-in's action log --
  written to tmpfs, so it cannot survive by accident -- is absent,
  proving no agent code ran. It runs last: a real guest reboot costs
  about 24s, more than every other phase combined, and leaves the
  guest freshly booted -- a poor starting point for any phase after
  it.

## 6. Fixtures and the fake proxy

Fixtures live under `fixtures/<name>/` as `wg.yaml` (or
`wg.yaml.tmpl`) plus `stunmesh.yaml`, not as inline shell strings in a
phase script. `lib.sh`'s `publish_fixture` copies a fixture's two
files over the node's own config directory and runs the real
`stunmesh-provd publish --once` against them.

A `.tmpl` fixture is rendered by its phase before publishing: `sed`
substitutes placeholders like `@NODE_PRIVATE_KEY@` and
`@PEER_PUBLIC_KEY@` with WireGuard key material `lib.sh`'s
`generate_wg_keypair` generates fresh, via the real `wg` tool, on
every run. No real key material is ever committed to a fixture file:
a fixed, checked-in private key would be a real (if throwaway) secret
sitting in git history forever, and a fresh key pair proves the same
thing about the agent's `uci`/`ubus` calls without needing one.
`fixtures/empty/` is the one plain (non-template) fixture: `wg: {}`,
the teardown bundle used both as the very first published state and
by `phase_diff_removal`'s teardown step.

`fakeproxy/` (`main.go`) is a minimal stand-in for a real `dhtproxy`
instance. It speaks the same wire shape `internal/dhtproxy.Client`
expects -- `GET /{key}` returns the last value `PUT` under that key as
one line of JSON with a `data` field (404 if never written); `POST
/{key}` stores the request body verbatim -- but keeps everything in a
process-local map, never expires anything, and never talks to
OpenDHT. It binds every interface, not just loopback, because the
guest reaches the host at `10.0.2.2` through QEMU's slirp networking.
It runs with no TLS: the guest-host link never leaves the host
machine, and the bundle payload is already sealed end-to-end before it
ever reaches this proxy. Its `-get-delay` flag, used only by
`phase-lock.sh`, sleeps before answering a `GET`, which is what makes
that phase's lock-contention race deterministic instead of flaky (see
`fakeproxy/main.go`'s own comment on `getDelay`).

## 7. Debugging a failure

Each assertion prints one `ok -` or `FAIL -` line as it runs; a failed
assertion never stops the run, so one failure does not hide the next
one. `report_assertions` prints the final tally and the run's exit
status reflects it.

When something fails:

- Re-run with `--keep-work` (or `E2E_KEEP_WORK=1`) so the working
  directory under `$TMPDIR` (`stunmesh-e2e-openwrt.XXXXXX`) survives
  the cleanup trap. `run.sh` prints its path ("Kept working
  directory: ...") on exit.
- Read `boot.log` in that directory: it is the guest's serial
  console, the only evidence available for a guest that never came up
  or never answered SSH. `phase-reboot.sh` writes a second one,
  `boot-after-reboot.log`, for the post-reboot boot.
- Read `fakeproxy.log` (and, if `phase-lock.sh` ran,
  `fakeproxy-delayed.log`) for what the fake dhtproxy saw and served.
- In CI, the `e2e-openwrt` composite action uploads exactly these
  three logs (`boot.log`, `fakeproxy.log`, `fakeproxy-delayed.log`) as
  the `e2e-openwrt-diagnostics` artifact, on every outcome, success
  included. It never uploads the image, the built binaries or the SSH
  key: they are either large and reproducible from the same run, or,
  for the key, not something to publish.
- A phase's own comments usually explain what evidence it is looking
  at and why (for example, why `phase-diff-removal.sh` uses a netdev's
  `ifindex`, not `wg show`'s handshake counters, as "was this
  interface restarted" evidence). Read the phase script itself before
  the assertion helpers in `assert.sh`.

## 8. Non-obvious mechanics

A few things this harness depends on are not obvious from reading a
single function in isolation:

- **The rootfs is found by content, not by filesystem type.** The
  image's boot partition is ext4 too, so "the ext4 partition" alone is
  ambiguous. `inject_guest_files` mounts every ext4 candidate read-only
  and keeps the first one with `/etc/openwrt_release` or an executable
  `/sbin/init`.
- **This harness builds a custom image with the ImageBuilder and
  injects files offline, instead of booting a stock image and
  provisioning it over SSH.** A stock image was measured as a working
  alternative -- empty-password root login and `apk add
  kmod-wireguard wireguard-tools` both succeed -- but it depends on a
  non-standard slirp subnet and an empty-password login that a real
  OpenWrt user would not run with. The ImageBuilder path relies only
  on offline file injection, which this harness already needs for
  `inject_guest_files`, so it carries no extra load-bearing assumption
  of its own.
- **`/dev/kvm` needs a bounded wait after the udev rule, not a
  one-shot check.** `udevadm trigger` returns before udev has finished
  applying the rule; `udevadm settle` helps but is not a guarantee on
  every host. `ensure_kvm_available` polls the device mode directly,
  bounded to 30s, and fails loudly rather than falling back to
  software emulation.
- **Phases run in the explicit order `run.sh`'s `PHASE_ORDER` array
  lists, not file order, comment order or alphabetical order.**
  `run.sh` sources every `phases/phase-*.sh` file first, then calls
  each function named in `PHASE_ORDER`, in that order: cheapest and
  most basic first (`phase_smoke`, `phase_payload`), growing scenario
  complexity through the middle, and `phase_reboot_uci_persistence`
  last because a real guest reboot costs about 24s -- more than every
  other phase combined -- and leaves the guest freshly booted, a poor
  starting point for any phase after it. Before running anything,
  `run.sh` cross-checks `PHASE_ORDER` against the `phase_*` functions
  `declare -F` actually finds, in both directions, and `die`s if they
  disagree: a phase file added without a `PHASE_ORDER` entry must not
  silently never run, and a stale `PHASE_ORDER` entry with no matching
  function must not silently be skipped. Every phase is still written
  to be self-contained -- this list says what runs and when, it does
  not license one phase depending on another's leftover state.
- **A stock OpenWrt image ships no `/etc/config/network` at all.**
  `/etc/board.d` writes one on first boot from board-detection logic,
  and the default it would pick (static `192.168.1.1`) is unreachable
  through QEMU's user-mode networking. `inject_guest_files` writes
  `lan` on DHCP instead, before first boot, which lands the guest in
  QEMU's own `10.0.2.0/24` network that a plain `hostfwd` already
  reaches.
- **`stunmesh-go` is stubbed, not built or installed.** The injected
  `/etc/init.d/stunmesh` is a two-line stand-in that logs whatever
  action it was called with and always exits 0. What is under test
  here is whether `stunmesh-agent` calls it at the right moments with
  the right action, never `stunmesh-go` itself.
- **`-accel kvm` is hardcoded and never falls back to TCG.** A TCG
  boot is slow enough to hide the timing-sensitive `uci`/`ubus`/
  `netifd` races this harness exists to catch, so a silent fallback
  would be worse than a loud failure.
- **`ifindex`, not `wg show`'s counters, is "was this interface
  restarted" evidence.** A WireGuard netdev's ifindex
  (`/sys/class/net/<if>/ifindex`) is assigned once, at kernel-device
  creation, and never changes while the device lives; if `netifd`
  tears an interface down and recreates it, the new device gets a new
  ifindex. `wg show`'s handshake and transfer counters read zero
  either way in this harness (no fixture peer is a reachable remote
  that could complete a real handshake), so they cannot answer the
  same question.
