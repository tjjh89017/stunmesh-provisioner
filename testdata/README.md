# Test vectors

This directory holds golden test vectors for `internal/bundle`, `internal/crypto`,
and `internal/dhtkey`.

The pinning test lives in `internal/testvectors`, not here. Go excludes any
directory named `testdata` from `go test ./...`, so a test placed directly in
this directory would never run. `internal/testvectors` loads these files
through `runtime.Caller`-relative paths and pins them instead.

File modes do not matter here. These are test keys only. Do not use them for
anything real.

## Key pairs

`controller.key`, `controller.pub`, `node.key`, `node.pub`, `tunnel.key`, and
`tunnel.pub` are Curve25519 key pairs in WireGuard base64 form (32 bytes,
standard base64 with padding, one line, trailing newline).

Each pair comes from a fixed seed string, so the vectors are reproducible:

1. `private_key = SHA-256(seed)`.
2. Clamp the private key as X25519 requires: clear the low 3 bits of byte 0,
   clear bit 7 of byte 31, and set bit 6 of byte 31.
3. `public_key = curve25519.X25519(private_key, curve25519.Basepoint)` from
   `golang.org/x/crypto/curve25519`.

Seeds:

| File | Seed |
|---|---|
| `controller.key` / `controller.pub` | `stunmesh-provisioner-test-controller` |
| `node.key` / `node.pub` | `stunmesh-provisioner-test-node` |
| `tunnel.key` / `tunnel.pub` | `stunmesh-provisioner-test-tunnel` |

`bundle.json` uses `tunnel.key` as the WireGuard interface private key (a real
bundle carries a tunnel key, not the node's identity key). It reuses
`controller.pub` as a placeholder peer public key for `bravo`, and uses
`node.pub` as the peer public key for `charlie`.

## `bundle.json`

A pretty-printed inner bundle, as defined in `PLAN.md` section 4.2, for
namespace `test-ns`, node `alpha`. It has one interface (`wg0`) and two peers
(`bravo`, `charlie`), and covers most optional fields: `listen_port`, `mtu`,
interface `options`, `route_allowed_ips`, `routes` (with and without a
gateway), peer `preshared_key` (omitted), peer `endpoint`,
`persistent_keepalive`, and peer `options`.

## `canonical.json`

The canonical form of `bundle.json`: `timestamp` removed, keys sorted
recursively, no whitespace, one trailing newline. Produced with:

```sh
jq -S -c 'del(.timestamp)' testdata/bundle.json > testdata/canonical.json
```

`jq` was installed, so this is the method used. `testdata_test.go` re-derives
the same bytes with `encoding/json` (which sorts map keys on marshal) and
compares them against this file.

## `dhtkey.txt`

Lowercase hex of `SHA1("test-ns" + "/" + "alpha")`, one line, trailing
newline. Produced with:

```sh
printf '%s' 'test-ns/alpha' | sha1sum
```

## `ciphertext.b64`

`nonce(24) || nacl/box ciphertext` of `canonical.json`, base64 standard with
padding, one line, trailing newline. This is the wire format defined in
`PLAN.md` section 4.1: nothing is in plain text and there is no outer JSON.

Plaintext: `canonical.json` (not `bundle.json` -- the sealed value carries the
canonical form). Recipient: `node.pub` (the node identity key). Sender:
`controller.key` (the controller private key), matching `PLAN.md` section
2.4. Nonce: fixed at the 24 bytes `0x00, 0x01, ... 0x17`, not random, so the
vector is reproducible; production code in `internal/crypto` always uses a
random nonce.

Produced by `internal/crypto`'s test-only `SealWithNonce` helper, which
shares its implementation with the package's `Seal` function (the only
difference being the caller-supplied nonce). This file is a committed
vector, not a cache: a normal test run reseals `canonical.json` with the
fixed nonce and asserts the result matches the file byte-for-byte, and
fails loudly if the file is missing. It never writes the file itself, so a
broken `Seal` cannot silently create a wrong golden.

To deliberately (re)generate this file (for example after an intentional
change to the sealing format), run:

```sh
STUNMESH_REGEN_GOLDEN=1 go test ./internal/crypto/... -run TestRegenerateGoldenCiphertext -v
```

Review the resulting diff before committing it.
