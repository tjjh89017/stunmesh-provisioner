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

Status: pre-alpha, see .plan/PLAN.md
