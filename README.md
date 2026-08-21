# stunmesh-provisioner

This project provisions stunmesh-go nodes on OpenWrt devices. The controller,
`stunmesh-provd`, publishes encrypted WireGuard and stunmesh-go config
bundles to OpenDHT via dhtproxy. The agent, `stunmesh-agent`, runs on the
OpenWrt device. It fetches each bundle, decrypts it, and applies it.

## Binaries

- `cmd/stunmesh-provd`: the controller. It runs on an operator's machine.
- `cmd/stunmesh-agent`: the agent. It runs on the OpenWrt device.

Status: pre-alpha, see .plan/PLAN.md
