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

Status: pre-alpha, see .plan/PLAN.md
