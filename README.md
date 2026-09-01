# stunmesh-provisioner

This project provisions stunmesh-go nodes on OpenWrt devices. The controller,
`stunmesh-provd`, publishes encrypted WireGuard and stunmesh-go config
bundles to OpenDHT via dhtproxy. The agent, `stunmesh-agent`, runs on the
OpenWrt device. It fetches each bundle, decrypts it, and applies it.

See the [`stunmesh-openwrt`](https://github.com/tjjh89017/stunmesh-openwrt)
repository's `docs/quick-start.md` for a step-by-step guide from nothing to
one working node.

## Binaries

- `cmd/stunmesh-provd`: the controller. It runs on an operator's machine.
- `cmd/stunmesh-agent`: the agent. It runs on the OpenWrt device.

## Running the controller as a service

`contrib/systemd/stunmesh-provd.service` runs `stunmesh-provd publish` as a
long-lived, hardened systemd service. See
`contrib/systemd/README.md` for install steps.

## Running the controller as a container

The image at `ghcr.io/tjjh89017/stunmesh-provd` ships `stunmesh-provd`
only. Tags follow the release: `vX.Y.Z` for a tagged release, `latest`
for the newest non-prerelease release, and `main` for the latest commit
on the default branch.

The only state the controller keeps is the `--dir` tree (default
`/etc/stunmesh/provd`). Mount it as a real, host-backed volume, never an
anonymous one: the tree holds the controller identity key and every
tunnel's private key, and losing it means every node has to be
re-provisioned.

```sh
docker run --rm -v stunmesh-provd:/etc/stunmesh/provd \
  ghcr.io/tjjh89017/stunmesh-provd init myns

docker run --rm -v stunmesh-provd:/etc/stunmesh/provd \
  ghcr.io/tjjh89017/stunmesh-provd node add myns node1 < node1.pub

# No command runs the republish loop (publish with no --once); it runs
# until it receives SIGINT or SIGTERM (`docker stop`).
docker run -d --name stunmesh-provd \
  -v stunmesh-provd:/etc/stunmesh/provd \
  ghcr.io/tjjh89017/stunmesh-provd
```

## Agent binary size (`mips_24kc`)

`make agent-mips` builds `stunmesh-agent` for 32-bit MIPS routers
(OpenWrt target `mips_24kc`, soft-float). Sizes below use Go 1.26.5,
`GOOS=linux GOARCH=mips GOMIPS=softfloat`, `CGO_ENABLED=0`.

| Build | Size |
|---|---|
| Default (`STRIP=1 TRIMPATH=1 EMBED_CA=1`, `-ldflags '-s -w' -trimpath -tags embedca`) | 6.9 MiB (7,274,689 bytes) |
| `EMBED_CA=0` (no Mozilla root bundle) | 6.8 MiB (7,143,617 bytes) |
| `EXTRA_MIN=1` (adds `upx --lzma --best`) | 1.8 MiB (1,886,860 bytes) |
| `EXTRA_MIN=1 EMBED_CA=0` | 1.7 MiB (1,786,972 bytes) |

The default build is what a release or the OpenWrt package ships
(`.plan/PLAN.md` 2.1.1: "Releases and the OpenWrt package do not use
UPX"). `EXTRA_MIN=1` is the smallest size for a router with little
flash space.

`EMBED_CA=1` is the default. The embedded roots cost 128 KiB of the
default build and 98 KiB after UPX, and they activate only when the
system provides no certificate store, so they are inert on an image
that has `ca-bundle`. Build with `EMBED_CA=0` when the image is known
to have one and the flash space matters more.

## Firewall zone

Every stunmesh-managed WireGuard interface is placed, by default, in a
shared OpenWrt firewall zone named `stunmesh` (`option input/output/forward
'ACCEPT'`, no `masq`). The agent creates it the first time it applies any
interface, adds each managed interface's `list network` entry as that
interface comes and goes, and deletes the zone (and its forwardings) once
the last managed interface is removed. It never touches a `firewall.stunmesh`
section it did not create itself (an operator-owned zone under that same
name is left alone).

The agent also creates three default `config forwarding` sections tied to
the zone's own lifecycle (created and deleted together with it):

- `lan` -> `stunmesh`: the router's LAN can reach every mesh peer.
- `stunmesh` -> `lan`: every mesh peer can reach the router's LAN.
- `stunmesh` -> `wan`: a mesh peer's traffic can egress through this
  node's own internet connection, NATed by `wan`'s own `masq` (the normal
  OpenWrt default), not by anything the agent sets.

**No NAT between `lan` and `stunmesh` in either direction**: the zone
itself never sets `masq`, so traffic crossing it keeps its real source
address both ways; end-to-end reachability relies on the WireGuard
allowed-ips/routes the bundle already provisions. This assumes the
standard OpenWrt `lan`/`wan` zones exist (the default on every stock
image); if either is missing, the corresponding forwarding is simply
inert, not an error.

Because the agent owns these sections, a later apply that touches the
zone reconciles them back to this default shape. An operator who edits
or removes them by hand should expect that edit to be undone on such an
apply; there is currently no way to opt an interface out of the zone or
turn a forwarding off permanently short of not using this feature's
managed zone at all (a hand-added zone under a different name, the way
`test/e2e/openwrt/phases/phase-firewall.sh` covers, is unaffected either
way).

## Periodic full apply (`--full-apply`)

`stunmesh-agent fetch --full-apply` skips the "no change since last
apply" shortcut and reruns the entire apply procedure -- UCI, both
`uci commit`s, both reloads, `ifup`, the stunmesh config file, and
`last.json` -- even when the newest bundle is identical to what
`last.json` already recorded. `contrib/openwrt/stunmesh-agent.init`
installs a second, independently tagged cron line that runs it once a
day by default (`option full_apply_interval_hours` in
`/etc/config/stunmesh-agent`, alongside the existing frequent,
diff-based line); see `contrib/openwrt/README.md` section 3. This is
also what re-adds a pre-existing interface to the firewall zone above
if it was applied by an older agent build, before this feature shipped.

## OpenWrt end-to-end tests

`test/e2e/openwrt/` boots a real OpenWrt x86-64 VM under KVM and runs
the real `stunmesh-agent` binary against it. It proves the agent's
`uci`, `ubus` and hotplug calls work on real `netifd`, not a mocked
`exec` -- fetching and applying a bundle, diffing and removing
interfaces, the cron line, hotplug, lock contention, routes, a
firewall zone surviving an apply, and a reboot with no proxy or agent
running. CI (`e2e-required` in `.github/workflows/main.yaml`) gates on
it for every push and pull request. See
`test/e2e/openwrt/README.md` for how to run and extend it.

Status: pre-alpha, see .plan/PLAN.md
