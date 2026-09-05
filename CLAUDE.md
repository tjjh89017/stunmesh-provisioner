# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Two Go binaries in one module. `stunmesh-provd` (controller, operator's
machine) builds a config bundle per node, seals it with `nacl/box`, and PUTs
it to OpenDHT through the Jami dhtproxy REST API. `stunmesh-agent` (OpenWrt
router, a long-running daemon) GETs the values, decrypts, validates,
diffs against `last.json`, and applies the result through `uci` / `ubus`,
managing an embedded copy of `stunmesh-go` in-process.

`docs/format.md` is the normative field reference: bundle format, DHT key
derivation, and validation phases. Comments cite its section numbers (e.g.
"docs/format.md 6") when a rule comes from there.

## Commands

```sh
make build          # both binaries into dist/ (CGO_ENABLED=0, -s -w, -trimpath, -tags embedca)
make agent-mips     # release agent for mips_24kc routers (softfloat); also agent-mipsle, agent-arm64
make test           # contrib/openwrt shell tests, then go test ./...
make test-openwrt   # only the contrib/openwrt shell tests (no Go, no root)
make vet            # go vet for host GOOS/GOARCH *and* linux/mips softfloat
make fmt-check      # fails if gofmt would change a file
make tidy-check     # go mod tidy -diff
```

`make vet`'s second pass is load-bearing: it compiles every package under a
32-bit GOARCH, which is where an untyped 64-bit constant overflowing `int`
shows up. Do not drop it.

Single test / package:

```sh
go test ./internal/bundle -run TestCanonical -v
go test ./cmd/stunmesh-agent -run TestFetch -v
go test -tags embedca ./...      # the embedca build tag guards the embedded CA fallback
```

End-to-end (both are required CI checks, gated by the `E2E` job):

```sh
test/e2e/openwrt/run.sh                      # boots a real OpenWrt VM under KVM (~4m20s cold)
E2E_KEEP_WORK=1 test/e2e/openwrt/run.sh      # keep the work dir, then reuse the image:
test/e2e/openwrt/run.sh --image /path/to/openwrt.img   # ~20-40s per iteration
test/e2e/realnet/run.sh                      # real round trip against the real Jami proxies
```

See `test/e2e/openwrt/README.md` for phases, fixtures, and debugging. CI steps
live in `.github/actions/*`; the Makefile is the single source of truth, so a
CI change that is not also a Makefile change is usually wrong.

```sh
docker build -t stunmesh-provd --build-arg VERSION=$(git describe --tags --dirty) .
```

builds the controller-only image (`Dockerfile`, root). `.github/workflows/main.yaml`
builds and pushes `ghcr.io/tjjh89017/stunmesh-provd:main` only on a push to
main; a pull request does not build it. `.github/workflows/release.yml`
builds release binaries/tarballs and pushes `vX.Y.Z`/`latest` container tags
on a pushed tag.

## Architecture

Shared packages under `internal/` are used by both binaries:

- `bundle` — the inner bundle type, JSON decode with the strict phase-1/phase-2
  checks (docs/format.md 7), and `Canonical`, whose bytes must equal
  `jq -S -c 'del(.timestamp)'`. Presence is content: an absent key and an
  explicit empty container (`"wg":{}`, `"routes":[]`) are different bundles.
  `timestamp` is never content.
- `crypto` — `nonce(24) || nacl/box` seal/open. `Open` deliberately does not
  distinguish wrong-recipient / wrong-sender / tampered.
- `dhtkey` — `SHA1(namespace + "/" + nodeID)`, lowercase hex; both parts must
  be non-empty and `/`-free or the key space collides.
- `dhtproxy` — HTTP client over the proxy list; `Get` treats 404/empty as
  "keep trying the other proxies" and reports partial outages via `PartialError`.
- `execx` — the only path to external commands. `Runner` interface, `Exec` in
  production, `Fake` in tests (exact command-sequence assertions). **Secret
  policy:** an error from `Exec.Run` never contains an argument value or
  captured stdout/stderr, because arguments carry WireGuard private keys.
- `uci` — bundle interface → ordered `uci` command batch, and recorded section
  names → delete batch. Golden files in `internal/uci/testdata/`.
- `last` — `last.json`: per-interface content plus the *exact* UCI section
  names the agent created. Deletion is always by recorded name, never by pattern.
- `store` — the operator's `/etc/stunmesh/provd/<namespace>/...` tree. The
  write side never overwrites a file the operator owns.
- `testvectors` — loads the repo-root `testdata/` golden vectors. Test-only.

Both `cmd/` mains are three lines: they call `Run(args, stdin, stdout, stderr,
version)` so every command is testable with fake args and buffers. Keep new
logic inside `Run`, not `main`.

Agent apply order (`cmd/stunmesh-agent/fetch_apply.go`): write UCI → `uci
commit network` → `ubus call network reload` → `ifup <iface>` for each
new/changed interface → write `last.json`. `network reload` alone does not
push a peer-only change into the kernel. The daemon rebuilds or stops the
embedded stunmesh-go app after `applyDiff` returns.

`stunmesh-agent` is a long-running daemon. Its default mode fetches/applies
once at start, then ticks on its own
`refresh_interval` and `full_apply_interval` (both read from `config.yaml`,
`cmd/stunmesh-agent/config.go`). `--oneshot` runs one full-apply cycle and
exits; `--stunmesh-only` skips the fetch/apply loop entirely and runs only
the embedded stunmesh-go app. `keygen` is the only subcommand. SIGINT/SIGTERM
shut down gracefully; restart the process to reload.

`contrib/openwrt/` holds the agent's two procd init scripts
(`stunmesh-agent.init` for the daemon, `stunmesh-only.init` for
`--stunmesh-only`, disabled by default) and hotplug script, plus an optional
procd init script for the controller (`stunmesh-provd.init`), all packaged by
the separate `stunmesh-openwrt` feed. The agent reads no UCI itself:
`stunmesh-agent.init` reads `/etc/config/stunmesh-agent` and renders
`config.yaml` from it before starting the daemon; `hotplug-iface` restarts
the running daemon (no signal, no flags) when the WAN interface comes up.
`contrib/openwrt/tests/` tests the agent's shell scripts directly, with no VM.

## Conventions

- ASD-STE100 style in docs and comments: short sentences, active voice, one
  instruction per sentence. Comments explain *why*, and cite docs/format.md
  sections when a rule comes from there.
- Every item gets unit tests; external commands go through `execx` with a fake.
- Never log or embed a secret (tunnel private keys, preshared keys, the
  identity key, the decrypted bundle) in output or error text.
- `CGO_ENABLED=0`, one module, two `main` packages. No new dependency without a
  reason — the agent is size-constrained (6.9 MiB on `mips_24kc`).
- The controller holds every tunnel private key. `wg.yaml`, `last.json`, and
  the identity key are mode 0600; `/etc/config/network` is 0644 by OpenWrt
  convention and does hold tunnel keys.
