# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Two Go binaries in one module. `stunmesh-provd` (controller, operator's
machine) builds a config bundle per node, seals it with `nacl/box`, and PUTs
it to OpenDHT through the Jami dhtproxy REST API. `stunmesh-agent` (OpenWrt
router, cron-driven, not a daemon) GETs the values, decrypts, validates,
diffs against `last.json`, and applies the result through `uci` / `ubus` /
`/etc/init.d/stunmesh`.

`.plan/PLAN.md` is the normative design: bundle format, DHT key derivation,
validation phases, apply procedure, storage tree, milestones. `docs/format.md`
is the normative field reference (it wins over PLAN.md 4.3 if they disagree).
Read the relevant PLAN.md section before changing behaviour — most code
comments cite section numbers (e.g. "PLAN.md 4.6") and those citations are
expected to stay accurate.

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

## Architecture

Shared packages under `internal/` are used by both binaries:

- `bundle` — the inner bundle type, JSON decode with the strict phase-1/phase-2
  checks (PLAN.md 4.4), and `Canonical`, whose bytes must equal
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

Agent apply order (PLAN.md 6, and `cmd/stunmesh-agent/fetch_apply.go`):
write UCI → `uci commit network` → `ubus call network reload` → `ifup <iface>`
for each new/changed interface → `/etc/init.d/stunmesh reload|stop` → only then
write `last.json`. The `ifup` step exists because the OpenWrt e2e harness proved
a plain `network reload` does not push a peer-only change into the kernel.
Exit codes: `0` applied, `3` no change, anything else failure.

`contrib/openwrt/` holds the init script and the hotplug script that the
separate `stunmesh-openwrt` feed packages. The agent reads no UCI itself: the
init script reads `/etc/config/provd` and passes flags. `contrib/openwrt/tests/`
tests those shell scripts directly, with no VM.

## Conventions

- ASD-STE100 style in docs and comments: short sentences, active voice, one
  instruction per sentence. Comments explain *why*, and cite PLAN.md sections.
- Every item gets unit tests; external commands go through `execx` with a fake.
- Never log or embed a secret (tunnel private keys, preshared keys, the
  identity key, the decrypted bundle) in output or error text.
- `CGO_ENABLED=0`, one module, two `main` packages. No new dependency without a
  reason — the agent is size-constrained (6.9 MiB on `mips_24kc`).
- The controller holds every tunnel private key. `wg.yaml`, `last.json`, and
  the identity key are mode 0600; `/etc/config/network` is 0644 by OpenWrt
  convention and does hold tunnel keys.

## Open work

`.plan/README.md` maps stages to powerloop runs; `.plan/stage*.md` are the
per-stage specs. `.issue/*.md` holds reviewed-but-unfixed findings (in
Traditional Chinese), each with its verification status — reproduce a finding
before acting on it. Stage 4 (`docs/provisioning.md`, `docs/controller.md`,
`docs/openwrt.md`, `docs/security.md`) is not written yet, and the
`.plan/stage5-openwrt-device.md` checklist is still unticked even though the
OpenWrt VM e2e harness now covers most of its items automatically.
