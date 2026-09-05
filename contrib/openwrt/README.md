# stunmesh-provisioner OpenWrt scripts

Three files here are the agent integration; a fourth is an optional
init script for the controller, `stunmesh-provd`. The `stunmesh-openwrt`
package repository copies all four from a release tarball; this
repository does not build an OpenWrt package.

- `stunmesh-agent.init` -- installs to `/etc/init.d/stunmesh-agent`.
  procd service for `stunmesh-agent` (the daemon, default mode).
- `stunmesh-only.init` -- procd service for `stunmesh-agent
  --stunmesh-only`. Where it installs is the package feed's decision;
  see the stunmesh-openwrt repository. Disabled by
  default; see "Two services, pick one" below.
- `hotplug-iface` -- installs to `/etc/hotplug.d/iface/95-stunmesh-agent`.
- `stunmesh-provd.init` -- installs to `/etc/init.d/stunmesh-provd`.
- `tests/` -- shell tests for `stunmesh-agent.init` and `hotplug-iface`,
  run with no VM (see "Tests" below).

## 1. `stunmesh-agent` is a daemon

`stunmesh-agent` is a long-running process. Its default mode -- no
flags beyond `--config-dir`/`--config` -- fetches, decrypts, checks,
and applies once at start, then keeps running: it ticks on its own
`refresh_interval` (a normal cycle) and `full_apply_interval` (a
periodic full re-apply), both read from `config.yaml`.

`stunmesh-agent.init` reflects this:

- It calls `procd_open_instance` and `procd_set_param respawn`: procd
  supervises the process and restarts it if it exits unexpectedly, the
  normal shape for a daemon.
- `start_service` first (re)generates `/etc/stunmesh/agent/config.yaml`
  from UCI (`write_config`), then hands the command line to procd. A
  node with no `/etc/config/stunmesh-agent`, or a `main` section
  missing a required option, is treated as "not provisioned yet":
  `write_config` returns 1, and `start_service` returns 0 without
  ever opening a procd instance -- calm and quiet, not an error.
- There is no `reload_signal`: `stunmesh-agent` has no SIGHUP handler.
  `/etc/init.d/stunmesh-agent reload` (`reload_service`)
  regenerates `config.yaml` from the current UCI state and then
  restarts the process outright (the default rc.common `restart`,
  stop then start). The daemon's own startup already does "read
  config.yaml, run one cycle immediately", so a restart already is
  the reload an operator wants.
- A failed startup cycle is retried on the next `refresh_interval` tick.
- `/etc/init.d/stunmesh-agent enable|disable` -- the standard
  rc.common mechanism -- controls whether the service starts at boot
  at all.

## 2. `/etc/config/stunmesh-agent`

`stunmesh-agent.init` reads the `main` section, plus one
`stunmesh-agent-plugin` section per backend plugin a deployment
configures:

```
config stunmesh-agent 'main'
    option namespace                  'mymesh-7f3a'
    option node_id                    'alpha'
    option controller_pubkey          '...'
    option use_plugin                 'mydht'
    option refresh_interval           '5m'
    option full_apply_interval        '24h'
    option identity_key               '/etc/stunmesh/agent/identity.key'
    option last                       '/etc/stunmesh/agent/last.json'
    option lock                       '/var/lock/stunmesh-agent.lock'

config stunmesh-agent-plugin 'mydht'
    option type    'dhtproxy'
    list  proxies  'https://dhtproxy2.jami.net'
    list  proxies  'https://dhtproxy3.jami.net'
```

Every UCI option name is the same as its `config.yaml` key: this
mapping is purely mechanical, `option` for a scalar and `list` for an
array, with no renaming in either direction. `list proxies` is the
only accepted list name.

| UCI option (`main`) | `config.yaml` key | Required |
|---|---|---|
| `namespace` | `namespace` | yes |
| `node_id` | `node_id` | yes |
| `controller_pubkey` | `controller_pubkey` | yes |
| `use_plugin` | `use_plugin` | no -- omitted, the built-in default `dhtproxy` backend and proxy list apply |
| `refresh_interval` | `refresh_interval` | no -- defaults to `5m` |
| `full_apply_interval` | `full_apply_interval` | no -- defaults to `24h`; `0` disables the periodic full apply |
| `identity_key` | `identity_key` | no -- defaults to `identity.key` alongside `config.yaml` |
| `last` | `last` | no -- defaults to `last.json` alongside `config.yaml` |
| `lock` | `lock` | no -- defaults to `/var/lock/stunmesh-agent.lock` |

| UCI option (`stunmesh-agent-plugin`) | `config.yaml` key | Required |
|---|---|---|
| `type` | `plugins.<name>.type` | yes (only `dhtproxy` exists) |
| `proxies` (list) | `plugins.<name>.proxies` | yes for `dhtproxy` |

The section's own UCI name (`'mydht'` above) is the key `use_plugin`
must name and the key under `plugins` in the rendered `config.yaml`.

`stunmesh-agent.init` has no UCI option for the embedded stunmesh-go
app's own settings (`config.yaml`'s `stunmesh:` section): that section
is either left out entirely (the embedded app falls back to its own
built-in search path, normally `/etc/stunmesh/config.yaml`) or written
by hand into `config.yaml` -- there is no UCI schema for it today.

The identity private key itself is never in
`/etc/config/stunmesh-agent`. That file is mode 0644 on OpenWrt
(readable by anyone on the box); only `identity_key`'s *path* goes in
it. `config.yaml` itself is written at mode 0600 by `write_config`
(it carries the same non-secret values UCI already had, but is kept
private out of caution); the key file `identity_key` points to must
be mode 0600, written once by `stunmesh-agent keygen`.

### Missing or incomplete configuration

`write_config` treats a missing `/etc/config/stunmesh-agent`, or a
`main` section missing `namespace`, `node_id`, or `controller_pubkey`,
as "not provisioned yet": it logs one line with `logger -t
stunmesh-agent` and returns 1 without writing `config.yaml`.
`start_service` then returns 0 without starting anything. This is the
state of a freshly flashed node before an operator has run the manual
key exchange: boring and quiet, not an error.

## 3. Two services, pick one

`stunmesh-agent.init` (`/etc/init.d/stunmesh-agent`) is the full
daemon: fetch, decrypt, check, apply UCI/firewall, *and* manage the
embedded stunmesh-go app's lifecycle as the fetched bundle's stunmesh
text or interfaces change.

`stunmesh-only.init` runs `stunmesh-agent --stunmesh-only`: only the embedded stunmesh-go app, reading its own
`config.yaml` `stunmesh:` section (or the built-in defaults, since
`config.yaml` is optional in this mode). No fetch, no DHT, no UCI, no
`last.json`.

A deployment enables exactly one of the two. Running both would start
two stunmesh-go instances against the same config file. Neither script
checks for that mistake: `stunmesh-only.init` must never start by
default. How an operator activates it is the package feed's business
(see the stunmesh-openwrt repository); whatever the path, the operator
enables it explicitly and leaves `stunmesh-agent` disabled.

## 4. Hotplug: which events restart the daemon

`hotplug-iface` runs on every interface hotplug event OpenWrt fires,
so it must filter hard:

- Reacts only to `ACTION=ifup` on `INTERFACE=wan`.
- Ignores `ifdown` and `ifupdate`.
- Ignores every other interface, including `wan6`: once `wan` itself
  is up, `stunmesh-agent` can already reach the dhtproxy over
  whichever address family is available.

On a match, it restarts `stunmesh-agent` -- `/etc/init.d/stunmesh-agent
restart` -- but only when the service is already running (`/etc/init.d/stunmesh-agent
running`, an rc.common command procd's `USE_PROCD=1` provides): a
node with no `/etc/config/stunmesh-agent` yet, or with the service
deliberately disabled or stopped, is left alone. `stunmesh-agent` has
no SIGHUP handler, so a restart -- which makes the daemon reread
`config.yaml` and run one cycle immediately, the same as any other
startup -- is the trigger, not a signal.

If a deployment's WAN logical interface is not named `wan`, this
script needs its interface name changed (or made configurable) before
it will trigger. There is no UCI option for this yet; a deployment
with a non-default WAN name is a case for the `stunmesh-openwrt`
packaging repository to resolve, not this repository.

## 5. Shell dialect

Every script targets BusyBox ash (OpenWrt's `/bin/sh`), not bash: no
arrays, no `[[ ]]`, no `local` outside of what ash itself supports
(ash's `local` is fine; POSIX `sh` in general is not guaranteed to
have it, but BusyBox ash does), no `function` keyword, no
process substitution, no `$'...'` strings. `set -- ...` and `"$@"`
build an argument list where one is needed, since ash has no arrays.
Checked with `shellcheck -s dash`.

## 6. Tests

`contrib/openwrt/tests/` (`run.sh`, `test_init.sh`, `test_hotplug.sh`,
`lib.sh`) tests `stunmesh-agent.init` and `hotplug-iface` with no VM.
`make test` (and so CI) runs `test-openwrt` before `go test ./...`;
run it alone with `make test-openwrt` or `sh contrib/openwrt/tests/run.sh`.

`test_init.sh` sources a filtered copy of `stunmesh-agent.init` with
fakes for `config_load`/`config_get` and `procd_*`. It covers
`write_config`'s rendering (every scalar, a `use_plugin`/`plugins`
entry, mode 0600, an incomplete or absent UCI config) and
`start_service`'s procd dispatch, and parses each rendered
`config.yaml` back with a real YAML parser to check `yaml_quote`'s
escaping.

`test_hotplug.sh` runs the real, unmodified `hotplug-iface` against
its guard clauses and, with a fake init script standing in for
`/etc/init.d/stunmesh-agent`, checks the restart-dispatch path.

Both test files run under `sh` (dash) and, when a `busybox` binary is
on `PATH`, under `busybox ash` too; `run.sh` reports which ran.

## 7. `stunmesh-provd.init` (the controller service)

Optional procd service for `stunmesh-provd`, the controller.
`contrib/systemd/README.md` covers the normal way to run it (a
systemd unit on a regular Linux host, not an OpenWrt router).

Reads `/etc/config/stunmesh-provd` (`dir`, default
`/etc/stunmesh/provd`; `namespace`, optional) and refuses to start
when the config section or the `dir` tree (provisioned with
`stunmesh-provd init`/`node add`) is missing. Never writes to that
tree. No test file yet -- its only real logic is the `dir`-exists
guard in `start_service`.
