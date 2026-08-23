# stunmesh-provisioner

This project provisions stunmesh-go nodes on OpenWrt devices. The controller,
`stunmesh-provd`, publishes encrypted WireGuard and stunmesh-go config
bundles to OpenDHT via dhtproxy. The agent, `stunmesh-agent`, runs on the
OpenWrt device. It fetches each bundle, decrypts it, and applies it.

## Binaries

- `cmd/stunmesh-provd`: the controller. It runs on an operator's machine.
- `cmd/stunmesh-agent`: the agent. It runs on the OpenWrt device.

## Running the controller as a service

`contrib/systemd/stunmesh-provd.service` runs `stunmesh-provd publish` as a
long-lived, hardened systemd service. See
`contrib/systemd/README.md` for install steps.

## Agent binary size (`mips_24kc`)

`make agent-mips` builds `stunmesh-agent` for 32-bit MIPS routers
(OpenWrt target `mips_24kc`, soft-float). Sizes below use Go 1.26.5,
`GOOS=linux GOARCH=mips GOMIPS=softfloat`, `CGO_ENABLED=0`.

| Build | Size |
|---|---|
| Default (`STRIP=1 TRIMPATH=1`, `-ldflags '-s -w' -trimpath`, no UPX) | 6.8 MiB (7,143,617 bytes) |
| `EXTRA_MIN=1` (adds `upx --lzma --best`) | 1.7 MiB (1,785,868 bytes) |

The default build is what a release or the OpenWrt package ships
(`.plan/PLAN.md` 2.1.1: "Releases and the OpenWrt package do not use
UPX"). `EXTRA_MIN=1` is the smallest size for a router with little
flash space.

Status: pre-alpha, see .plan/PLAN.md
