# DHT data format

## 1. Scope

This document defines the data that stunmesh-provisioner stores on the
DHT and the data inside it, and the controller's backend
configuration. It defines the DHT key, the encrypted DHT value, the
inner bundle that the value carries after decryption, and the
`provd.yaml` settings that select the backend that stores DHT values.

Implementers of a publisher (`stunmesh-provd`) or an agent
(`stunmesh-agent`) are the readers of this document. `PLAN.md` section
4 is the design source. This document tracks the code in
`internal/bundle`, `internal/dhtkey`, `internal/crypto`,
`internal/dhtproxy`, and `internal/store`, and is more specific than
`PLAN.md` where the code adds a rule.

## 2. DHT key

The DHT key is the lowercase hex SHA-1 digest of the namespace and
the node ID, joined by one `/` character:

```
key = SHA1(namespace + "/" + node_id)
```

The key is a 40-character lowercase hex string.

| Rule | Detail |
|---|---|
| `namespace` | Must not be empty. Must not contain `/`. |
| `node_id` | Must not be empty. Must not contain `/`. |

The no-`/` rule stops a collision. Without it, the pair
`("a", "b/c")` and the pair `("a/b", "c")` join to the same string
`a/b/c` and hash to the same key.

Golden vector: for `namespace = "test-ns"` and `node_id = "alpha"`,
the key is the value in `testdata/dhtkey.txt`:

```
be9c941a9a95be818895c0fb0ee60aecab6cb4f3
```

## 3. Controller backend configuration

`provd.yaml` selects the backend that stores DHT values. A backend is
a plugin. This format defines one plugin type, `dhtproxy`, backed by
`internal/dhtproxy`.

A `provd.yaml` names its backend in one of two forms. The plugin form
names a `plugins` map and a `use_plugin` selector:

```yaml
plugins:
  dht:
    type: dhtproxy
    proxies:
      - https://dhtproxy2.jami.net
      - https://dhtproxy3.jami.net
use_plugin: dht
republish_interval: 5m
```

| Key | Rule |
|---|---|
| `plugins` | Map of plugin name to plugin definition. The name (`dht` above) is the operator's own label; the controller does not interpret it beyond matching it against `use_plugin`. |
| `plugins.*.type` | Required. Selects the plugin implementation. Only `dhtproxy` exists. |
| `plugins.*.proxies` | Required when `type` is `dhtproxy`. List of dhtproxy base URLs. |
| `use_plugin` | Required alongside `plugins`. Names the entry in `plugins` that this deployment uses. |
| `republish_interval` | Required. Top-level, outside `plugins`. Same meaning in both forms (section 8). |

The legacy shorthand form names a top-level `proxies` list instead,
with no `plugins` map and no `use_plugin`:

```yaml
proxies:
  - https://dhtproxy2.jami.net
  - https://dhtproxy3.jami.net
republish_interval: 5m
```

A top-level `proxies` list means one implicit `dhtproxy` plugin.
`republish_interval` keeps the same top-level key and the same meaning
as in the plugin form.

`provd.yaml` is malformed in each of these cases, and the controller
rejects it:

| Case | Detail |
|---|---|
| Both forms present | A top-level `proxies` list and a `plugins` map both exist in one file. |
| `use_plugin` names a missing entry | `use_plugin` names an entry that `plugins` does not contain. |
| `use_plugin` without `plugins` | `use_plugin` is present, but no `plugins` map exists. |
| `plugins` without `use_plugin` | A `plugins` map exists, but `use_plugin` is absent. Selection is always explicit; there is no default entry. |
| Unknown plugin type | A `plugins.*.type` value other than `dhtproxy`. |

## 4. DHT value

The DHT value is layered. Each layer wraps the one before it:

1. The inner bundle, encoded as JSON (section 5).
2. Sealed with `nacl/box`: `nonce(24 bytes) ‖ ciphertext`.
3. The sealed bytes, encoded as standard base64 with padding.
4. Placed in the `data` field of the dhtproxy JSON object.

```
data field  =  base64( nonce(24) || nacl/box(inner bundle JSON) )
```

Nothing is in plain text on the DHT. There is no outer JSON around
the sealed bytes; the `data` field holds only the base64 text. The
inner bundle JSON (section 5) never contains a `null` value; omit a
key instead of setting it to `null`.

The controller is the sender. It seals with its own private key and
the node's identity public key. The node is the recipient. It opens
with its own identity private key and the controller's public key.

`Open` can fail. A failure means one thing only: the value did not
open with this key pair. The three possible causes — a wrong
recipient key, a wrong sender key, and a tampered ciphertext — are
not distinguished. Distinguishing them would let an attacker probe
keys with the difference.

## 5. Inner bundle

The inner bundle is the plain text that `nacl/box` reveals after a
successful open. It is JSON. This example matches
`testdata/bundle.json`, for namespace `test-ns`, node `alpha`. It has
one interface (`wg0`) and two peers (`bravo`, `charlie`):

```json
{
  "version": 1,
  "namespace": "test-ns",
  "node_id": "alpha",
  "timestamp": 1755760000,
  "wg": {
    "wg0": {
      "private_key": "<tunnel private key, base64>",
      "listen_port": 51820,
      "addresses": ["10.0.0.1/24", "fd00::1/64"],
      "mtu": 1420,
      "options": { "defaultroute": "0" },
      "route_allowed_ips": false,
      "routes": [
        { "cidr": "10.20.0.0/16", "gateway": "10.0.0.2" },
        { "cidr": "fd00:20::/32" }
      ],
      "peers": {
        "bravo": {
          "public_key": "<bravo tunnel public key>",
          "allowed_ips": ["10.0.0.2/32"],
          "endpoint": "bravo.example.com:51820",
          "persistent_keepalive": 25,
          "options": { "description": "Bravo" }
        },
        "charlie": {
          "public_key": "<charlie tunnel public key>",
          "allowed_ips": ["10.0.0.3/32", "fd00::3/128"]
        }
      }
    }
  },
  "stunmesh": "interfaces:\n  wg0:\n    peers:\n      bravo: {}\nplugins:\n  cf:\n    type: cloudflare\n    api_token: test-token\n"
}
```

## 6. Fields

Canonical form (section 8) preserves presence: an absent field and an
explicit empty one (`"wg":{}`, `"routes":[]`, `"options":{}`) produce
different canonical bytes, so two such bundles compare unequal.

A JSON `null` is not permitted anywhere in the bundle, at any depth:
omit the key instead of setting it to `null` (section 7).

| Field | Required | Rule |
|---|---|---|
| `version` | Yes | Must be `1`. |
| `namespace` | Yes | Must equal the receiving node's namespace. |
| `node_id` | Yes | Must equal the receiving node's node ID. |
| `timestamp` | Yes | Unix time at publish. Positive integer, at most 9007199254740991 (2^53-1). Picks the newest of several values (section 9). Not compared with the node's own clock. |
| `wg` | Yes | Map of interface name to interface. Can be empty (remove all interfaces). Absent is an error. |
| `wg.*.private_key` | Yes | Tunnel private key. |
| `wg.*.listen_port` | No | Integer, 1-65535. Absent: WireGuard picks a random port. |
| `wg.*.addresses` | Yes | List. At least one entry. |
| `wg.*.mtu` | No | Integer, 576-65535. Absent: use the platform default. |
| `wg.*.route_allowed_ips` | No | Boolean. Default `true`. Installs a route for each peer's `allowed_ips` on this interface. |
| `wg.*.routes` | No | List of static routes on this interface. Default empty. |
| `wg.*.options` | No | Map of string to string. Extra options for the interface. |
| `routes[].cidr` | Yes | IPv4 or IPv6 prefix. |
| `routes[].gateway` | No | Next hop. Absent: on-link through the interface. Must not be present and empty (`""`); `Validate` rejects that. |
| `routes[].metric` | No | Integer, 0-4294967295. |
| `wg.*.peers` | Yes | Map of peer name to peer. Can be empty. |
| `peers.*.public_key` | Yes | Peer tunnel public key. |
| `peers.*.preshared_key` | No | Must not be present and empty (`""`); `Validate` rejects that. |
| `peers.*.allowed_ips` | Yes | List. At least one entry. |
| `peers.*.endpoint` | No | `host:port`. IPv6: `[addr]:port`. Must not be present and empty (`""`); `Validate` rejects that. |
| `peers.*.persistent_keepalive` | No | Integer, seconds, 0-65535. |
| `peers.*.options` | No | Map of string to string. Extra options for the peer. |
| `stunmesh` | Yes | String. Full `stunmesh-go` `config.yaml` text. The agent does not parse it. Empty string (`""`): no stunmesh config, and still counts as present. `Validate` rejects a bundle where the key is absent entirely. |

A bundle must not have a key that is not in this table, at any
level. `Validate` rejects a bundle that fails a rule in this table.

Every number in the bundle must be a plain base-10 integer: no
fraction (`1.0`), no exponent (`1e3`), no `-0`. Go's `*int`/`int64`
decoding and jq's float64 arithmetic disagree on these spellings, so
`Parse` rejects them outright rather than risk `Canonical` diverging
from the `jq -S -c 'del(.timestamp)'` reference (section 8).

No string value or object key may contain an escaped, unpaired UTF-16
high surrogate (`\uD800`-`\uDBFF` not immediately followed by
`\uDC00`-`\uDFFF`): Go decodes it to U+FFFD and would accept it, but
jq rejects it, so `Parse` rejects it too rather than have no jq
reference to check `Canonical` against.

`Validate` does not check these two things:

- Whether a key field (`private_key`, `public_key`,
  `preshared_key`) is valid base64 or the right length.
- Whether a `cidr`, `addresses`, or `allowed_ips` entry is a valid
  CIDR or IP address.

## 7. Checks after decryption

The node runs these checks in two phases. Every phase 1 check runs
before any phase 2 check. If a phase 1 check fails, the node rejects
the value without running any phase 2 check.

Phase 1 looks only at the JSON text itself: its syntax and its
literal structure. It does not yet know the node's own namespace or
node ID, and it does not yet look at field-specific rules like
`listen_port`'s range.

| # | Check |
|---|---|
| 1 | The bytes are syntactically valid JSON. |
| 2 | No `null` value exists anywhere in the JSON, at any depth. |
| 3 | Every number in the JSON is a plain base-10 integer: no fraction, no exponent, no `-0`. |
| 4 | No string value or object key contains an escaped, unpaired UTF-16 high surrogate. |
| 5 | No unknown key exists at any level, and every key that is present holds a value of the JSON type its field expects (for example, `wg` must be an object, `addresses` must be an array). |
| 6 | No data follows the closing `}` of the JSON object. |

Checks 2 and 3 both come from one walk over the decoded value. If a
bundle breaks both rules at once, which of the two errors is
reported first is unspecified (it follows Go's map key iteration
order). Checks 1 and 4-6 are otherwise strictly ordered as listed.

Phase 2 runs only after phase 1 passes completely. It checks the
now-parsed value against the receiving node's own namespace and node
ID and against each field's rule from section 6:

| # | Check |
|---|---|
| 7 | `version` is `1`. |
| 8 | `namespace` equals the node's namespace. |
| 9 | `node_id` equals the node's node ID. |
| 10 | `timestamp` is a positive integer, at most 9007199254740991 (2^53-1). |
| 11 | `stunmesh` is present (an empty string is valid; the key must exist). |
| 12 | `wg` is present (an empty map is valid; the key must exist). |
| 13 | Every interface has `private_key`, at least one address, and a `peers` map; a present `listen_port` is 1-65535 and a present `mtu` is 576-65535. |
| 14 | Every peer has `public_key` and at least one `allowed_ips` entry, does not have a present-but-empty `preshared_key` or `endpoint`, and a present `persistent_keepalive` is 0-65535. |
| 15 | Every route has a `cidr`, does not have a present-but-empty `gateway`, and a present `metric` is 0-4294967295. |

If one check fails, the node rejects the value. The node changes no
file.

## 8. Change detection

The content of a bundle is everything except `timestamp`.
`timestamp` only orders values; it is not content.

The canonical form of a bundle is its JSON with these rules:

- No `timestamp` key.
- All object keys sorted, at every level.
- No whitespace between tokens.
- No trailing newline.

Two bundles with the same canonical form have the same content, even
if their `timestamp` differs. The reference command for tests is:

```sh
jq -S -c 'del(.timestamp)'
```

Golden vector: `testdata/canonical.json` is the canonical form of
`testdata/bundle.json`.

## 9. More than one value

The dhtproxy can return more than one value for one key: an old
republish, or a value a third party wrote.

An agent must:

1. Try to decrypt every returned value.
2. Keep the decrypted bundle with the largest `timestamp`.
3. Read at most 64 values. Ignore the rest and log a warning.

A flood of junk values under a key is a denial of service. It does
not compromise a node, because a value that fails to decrypt is
discarded. Version 1 of this format has no replay protection: an old,
valid, correctly-sealed value stays valid until a newer one exists.

## 10. Golden vectors

| File | Pins |
|---|---|
| `testdata/dhtkey.txt` | Section 2, DHT key. |
| `testdata/bundle.json` | Section 5, inner bundle. Section 6, fields. |
| `testdata/canonical.json` | Section 8, canonical form. |
| `testdata/ciphertext.b64` | Section 4, DHT value. Sealed with a fixed nonce (the 24 bytes `0x00` through `0x17`), not a random one, so the vector is reproducible. Production code always uses a random nonce. |
| `testdata/controller.key` / `.pub` | Section 4, sender key pair. |
| `testdata/node.key` / `.pub` | Section 4, recipient key pair. |
| `testdata/tunnel.key` / `.pub` | Section 5, `wg.*.private_key` / peer `public_key` example values. |
