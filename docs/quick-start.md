# Quick start

This guide takes an operator from nothing to one working node: a
controller that publishes bundles, and one OpenWrt router that fetches
and applies one of them. It uses two nodes (`node1`, `node2`) so the
example has a real peer to connect to.

`docs/format.md` is the full field reference for `wg.yaml` and the
bundle it becomes. This guide only covers the fields one minimal
tunnel needs.

## 1. Before you start

You need:

- A controller machine: any Linux (or macOS/Windows) host that can
  reach `https://dhtproxy2.jami.net` and `https://dhtproxy3.jami.net`
  over HTTPS. This holds every node's tunnel private key, so treat it
  like any other secrets machine.
- One OpenWrt router per node, with `wireguard-tools` and
  `kmod-wireguard` installed (`opkg install wireguard-tools
  kmod-wireguard`).
- A way to copy two short lines of text (a public key, then a few
  constants) from the controller to each router, and one public key
  back. This guide uses copy-paste; any channel works, because none of
  it is secret except the value you must never copy: a private key.

## 2. Controller setup (once per deployment)

Build both binaries:

```sh
make build
```

This produces `dist/stunmesh-provd` and `dist/stunmesh-agent`.

Create the provisioning tree and a namespace:

```sh
dist/stunmesh-provd --dir /etc/stunmesh/provd init myns
```

`--dir` defaults to `/etc/stunmesh/provd`; omit it if you use that
path. Output looks like this:

```
wrote /etc/stunmesh/provd/README.md
namespace myns: /etc/stunmesh/provd/myns
wrote /etc/stunmesh/provd/myns/provd.yaml
generated controller key pair, public key: <controller public key, base64>
```

`init` is safe to run again: an existing file or key is left
untouched and reported as such.

### The tree it creates

```
/etc/stunmesh/provd/
├── README.md
└── myns/
    ├── provd.yaml         proxy list and republish interval
    ├── controller.key     controller private key (SECRET, mode 0600)
    ├── controller.pub     controller public key (mode 0644)
    └── nodes/
        └── <node_id>/
            ├── identity.pub    node identity public key (mode 0644)
            ├── wg.yaml         this node's WireGuard settings (SECRET, mode 0600)
            └── stunmesh.yaml   this node's stunmesh-go settings (mode 0644)
```

The namespace directory and each node directory are mode 0700.
`controller.key` and `wg.yaml` hold private key material; never copy
them off the controller, log them, or paste them anywhere. Every other
file under the tree is safe to view or copy.

### Running the controller: native binary + systemd

```sh
sudo install -m 0755 dist/stunmesh-provd /usr/local/bin/stunmesh-provd
sudo useradd --system --no-create-home --shell /usr/sbin/nologin stunmesh-provd
sudo cp contrib/systemd/stunmesh-provd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now stunmesh-provd.service
```

Run `init` and `node add` as the `stunmesh-provd` user so the tree
already belongs to it, or `chown -R stunmesh-provd:stunmesh-provd
/etc/stunmesh/provd` afterward. See `contrib/systemd/README.md` for
the full steps. The unit runs `stunmesh-provd publish` (the republish
loop, no `--once`) and only ever reads the tree.

### Running the controller: container

```sh
docker run --rm -v stunmesh-provd:/etc/stunmesh/provd \
  ghcr.io/tjjh89017/stunmesh-provd init myns

docker run -d --name stunmesh-provd \
  -v stunmesh-provd:/etc/stunmesh/provd \
  ghcr.io/tjjh89017/stunmesh-provd
```

Mount `/etc/stunmesh/provd` as a real, host-backed volume, never an
anonymous one. It holds the controller identity key and every tunnel's
private key. Losing it means every node has to be re-provisioned: a
fresh controller key cannot decrypt anything the old one published,
and the tunnel private keys themselves are gone.

## 3. Node setup (once per node)

Do this once for `node1`, then again for `node2`.

### Install the agent on the router

Build (or download) `stunmesh-agent` for the router's architecture
(for example `make agent-mips` for `mips_24kc`) and copy it, and the
two `contrib/openwrt/` scripts, to the router:

```sh
scp dist/stunmesh-agent root@<router>:/usr/sbin/stunmesh-agent
scp contrib/openwrt/stunmesh-agent.init root@<router>:/etc/init.d/stunmesh-agent
scp contrib/openwrt/hotplug-iface root@<router>:/etc/hotplug.d/iface/95-stunmesh-agent
ssh root@<router> chmod 0755 /usr/sbin/stunmesh-agent /etc/init.d/stunmesh-agent /etc/hotplug.d/iface/95-stunmesh-agent
```

### Generate the node's identity key

On the router:

```sh
stunmesh-agent keygen --identity-key /etc/stunmesh/provd/identity.key
```

This prints one line, the node's identity public key, and writes the
private key to `/etc/stunmesh/provd/identity.key` at mode 0600. Running
`keygen` again against the same path reuses the existing key instead of
replacing it.

`keygen` has no OpenWrt-specific requirement; if you would rather keep
every private key off the router until it is provisioned, build
`stunmesh-agent` for the controller's own OS/architecture and run
`keygen` there instead, then copy the resulting `identity.key` file to
the router's `/etc/stunmesh/provd/identity.key` (mode 0600) over a
channel you trust.

### Register the node on the controller

Paste the printed identity public key into `node add`:

```sh
dist/stunmesh-provd --dir /etc/stunmesh/provd node add myns node1
```

`node add` reads the identity key from stdin when the third argument
is omitted, so you can also pipe it directly:

```sh
ssh root@<router> stunmesh-agent keygen --identity-key /etc/stunmesh/provd/identity.key \
  | dist/stunmesh-provd --dir /etc/stunmesh/provd node add myns node1
```

Output:

```
node myns/node1: /etc/stunmesh/provd/myns/nodes/node1
wrote /etc/stunmesh/provd/myns/nodes/node1/identity.pub
wrote /etc/stunmesh/provd/myns/nodes/node1/wg.yaml
wrote /etc/stunmesh/provd/myns/nodes/node1/stunmesh.yaml
NAMESPACE=myns
NODE_ID=node1
CONTROLLER_PUBKEY=<controller public key, base64>
DHT_PROXY=https://dhtproxy2.jami.net
DHT_PROXY=https://dhtproxy3.jami.net
```

`node add` is safe to run again: it never overwrites `wg.yaml` or
`stunmesh.yaml` once they exist.

### Configure `/etc/config/provd` on the router

Paste the four printed constants (plus the identity key file's path)
into `/etc/config/provd` on the router:

```
config provd 'main'
    option namespace          'myns'
    option node_id            'node1'
    option controller_pubkey  '<CONTROLLER_PUBKEY from above>'
    list   proxy              'https://dhtproxy2.jami.net'
    list   proxy              'https://dhtproxy3.jami.net'
    option private_key_file   '/etc/stunmesh/provd/identity.key'
    option boot_delay         '15'
    option fetch_interval     '5'
    option lock_file          '/var/lock/stunmesh-agent.lock'
```

`private_key_file` is only a path; the identity private key itself
never goes in this file. `/etc/config/provd` is mode 0644 (world
readable on the router); the file `private_key_file` points at must
stay mode 0600.

Repeat this whole section for `node2`.

## 4. Write `wg.yaml` and `stunmesh.yaml` on the controller

Edit `/etc/stunmesh/provd/myns/nodes/node1/wg.yaml` and
`.../node2/wg.yaml`. `node add` writes a fully commented-out template;
delete the leading `#` from the lines you use. This minimal, complete
example gives `node1` and `node2` one interface each, with one peer
each:

`myns/nodes/node1/wg.yaml`:

```yaml
wg0:
  private_key: <node1 tunnel private key, base64>
  addresses:
    - 10.0.0.1/24
  peers:
    node2:
      public_key: <node2 tunnel public key, base64>
      allowed_ips:
        - 10.0.0.2/32
      endpoint: node2.example.com:51820
```

`myns/nodes/node2/wg.yaml`:

```yaml
wg0:
  private_key: <node2 tunnel private key, base64>
  addresses:
    - 10.0.0.2/24
  peers:
    node1:
      public_key: <node1 tunnel public key, base64>
      allowed_ips:
        - 10.0.0.1/32
      endpoint: node1.example.com:51820
```

Each peer here names a static `endpoint`, because this minimal example
leaves `stunmesh.yaml` empty. Omit `endpoint` once stunmesh-go runs on
the node: it sets the endpoint at runtime, which is the whole point of
this system. A node behind NAT needs stunmesh-go; a static endpoint
only works for a node with a reachable address.

Generate each tunnel key pair with `wg genkey` and `wg pubkey`, the
same as any other WireGuard setup; `stunmesh-provd` does not generate
tunnel keys. The controller keeps every tunnel private key in these
files (mode 0600); it never gives a router its own tunnel private key
back except inside the encrypted bundle.

`stunmesh.yaml` can stay empty: an empty file is a valid bundle
(`stunmesh: ""`, meaning "no stunmesh-go config"). Fill it in with a
real `stunmesh-go` `config.yaml` only if this node needs one.

See `docs/format.md` for every optional `wg.yaml` field
(`listen_port`, `mtu`, `route_allowed_ips`, `routes`, `options`,
`preshared_key`, `persistent_keepalive`, and the peer/route
presence rules).

## 5. Publish and fetch

On the controller, publish once:

```sh
dist/stunmesh-provd --dir /etc/stunmesh/provd publish --once
```

```
published myns/node1: key=<hex dht key>
published myns/node2: key=<hex dht key>
```

Exit code `0` means every node in the round published to every
configured proxy. If a namespace or node has a problem, that node's
error is printed and the exit code is nonzero, but the other nodes
still publish.

On each router, either start the recurring service:

```sh
service stunmesh-agent enable
service stunmesh-agent start
```

or run one fetch by hand for the first try:

```sh
stunmesh-agent fetch \
  --namespace myns --node-id node1 \
  --controller-pubkey '<CONTROLLER_PUBKEY>' \
  --identity-key /etc/stunmesh/provd/identity.key
```

`service stunmesh-agent start` runs one fetch in the background after
`boot_delay` seconds and installs a cron line that repeats it every
`fetch_interval` minutes; it does not run `fetch` as a supervised
daemon.

## 6. Verify

On the router, after a fetch has applied:

```sh
wg show
ubus call network.interface.wg0 status
uci show network
logread -e stunmesh-agent
```

`wg show` lists the interface and its peer. `ubus call
network.interface.wg0 status` shows the interface netifd brought up.
`uci show network` shows the sections the agent created. `logread -e
stunmesh-agent` shows the fetch's outcome (`fetch applied`, `fetch: no
change`, or `fetch failed, exit code <n>`).

The agent's memory of what it applied is `/etc/stunmesh/provd/last.json`
(mode 0600, the default `--last` path). It records each interface's
content and the exact UCI section names the agent created for it.

## 7. Troubleshooting

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Applied a change (or, for `publish`, every node published). |
| `3` | `fetch` decrypted a valid, newest bundle identical to `last.json`. Nothing changed; this is success, not failure. |
| other | Failure: a bad flag, an unreadable file, a DHT error, decryption failure, or a bundle that failed a check. |

"No change" (exit `3`) means the newest bundle's content is byte-for-byte
the same as what the agent already applied; the router state is
untouched.

An empty DHT result (the key has nothing on it yet, or every value
under it failed to decrypt) does nothing. It is never treated as a
teardown. To remove every interface from a node on purpose, publish a
bundle where `wg.yaml` is an explicit empty map (`wg: {}`) and
`stunmesh.yaml` is empty.

The tool never touches firewall zones. Add the interface to a zone
once, by hand, by adding a line to the zone's section in
`/etc/config/firewall`:

```
list network '<iface>'
```

The interface name is stable across re-publishes, so this is a
one-time step per node.
