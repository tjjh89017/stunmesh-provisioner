# stunmesh-agent OpenWrt scripts

These two files are the OpenWrt integration for `stunmesh-agent`
(`PLAN.md` section 3 and M4). The `stunmesh-openwrt` package repository
copies them from a release tarball; this repository does not build an
OpenWrt package (`PLAN.md` M6).

- `stunmesh-agent.init` -- installs to `/etc/init.d/stunmesh-agent`.
- `hotplug-iface` -- installs to `/etc/hotplug.d/iface/95-stunmesh-agent`.

## 1. `stunmesh-agent` is not a daemon

`stunmesh-agent fetch` runs once and exits (`PLAN.md` section 5). It is
cron-driven, the same as any OpenWrt one-shot maintenance task.
`stunmesh-agent.init` reflects this on purpose:

- It never calls `procd_open_instance`. If it did, procd would manage
  `stunmesh-agent fetch` as a supervised service and would treat every
  normal exit as a crash to recover from, restarting it in a tight
  loop.
- `start()` runs one fetch in the background, after `option
  boot_delay` seconds, and installs a cron line built from `option
  fetch_interval`.
- `stop()` removes that cron line. Nothing else needs to stop: every
  fetch has already exited by the time `stop()` runs.
- A repeated `start()` (for example `service stunmesh-agent restart`)
  removes any cron line it installed before adding the new one. The
  crontab never ends up with two lines for `stunmesh-agent`.
- `/etc/init.d/stunmesh-agent enable|disable` -- the standard
  rc.common mechanism -- controls whether `start()` runs at boot at
  all. No separate UCI "enabled" option is needed for that.

Exit code 3 (`PLAN.md` section 5: no change) is success, not failure.
Both scripts log it as "no change" and never treat it as an error.

## 2. `/etc/config/provd`

Both scripts read the `main` section of `/etc/config/provd`
(`PLAN.md` section 3):

```
config provd 'main'
    option namespace          'mymesh-7f3a'
    option node_id            'alpha'
    option controller_pubkey  '...'
    list   proxy              'https://dhtproxy2.jami.net'
    list   proxy              'https://dhtproxy3.jami.net'
    option private_key_file   '/etc/stunmesh/provd/identity.key'
    option boot_delay         '15'
    option fetch_interval     '5'
    option lock_file          '/var/lock/stunmesh-agent.lock'
```

| UCI option | stunmesh-agent flag | Required |
|---|---|---|
| `namespace` | `--namespace` | yes |
| `node_id` | `--node-id` | yes |
| `controller_pubkey` | `--controller-pubkey` | yes |
| `proxy` (list) | `--proxy` (repeated, once per entry) | no -- falls back to the binary's built-in default list when the section has none |
| `private_key_file` | `--identity-key` | yes |
| `boot_delay` | sleep before the first fetch (init only) | no -- defaults to 15 |
| `fetch_interval` | minutes between cron runs (init only) | no -- defaults to 5 |
| `lock_file` | `--lock` | no -- defaults to `/var/lock/stunmesh-agent.lock` |

`--last` and `--stunmesh-config` are not in the UCI schema. Both
scripts omit those flags and let `stunmesh-agent` use its own
defaults (`/etc/stunmesh/provd/last.json` and
`/etc/stunmesh/config.yaml`).

The identity private key itself is never in `/etc/config/provd`. That
file is mode 0644 on OpenWrt (readable by anyone on the box); only
`private_key_file`'s *path* goes in it. The key file it points to must
be mode 0600, written once by `stunmesh-agent keygen`.

### Missing or incomplete configuration

Both scripts treat a missing `/etc/config/provd`, or a `main` section
missing `namespace`, `node_id`, `controller_pubkey`, or
`private_key_file`, as "not provisioned yet": they log one line with
`logger -t stunmesh-agent` and exit 0. Neither script fails, retries in
a loop, or writes a cron line in this case. This is the state of a
freshly flashed node before an operator has run the manual key
exchange (`PLAN.md` 2.3, 2.7): boring and quiet, not an error.

## 3. The cron line

`start()` builds `*/<fetch_interval> * * * * <bin> fetch <flags>` and
appends it to `/etc/crontabs/root`, tagged with a fixed comment so it
can find and remove exactly that line later, never any other line a
person or another package put in that file. It nudges `crond` with
`/etc/init.d/cron reload` so the new schedule takes effect at once
instead of waiting for crond's own poll interval. `stop()` removes the
tagged line the same way.

None of the values written into the cron line are secret:
`controller_pubkey` is a public key, and `private_key_file` is only a
path. The key material itself never appears in the crontab, in a log
line, or on a command line that another process on the box could read
from `/proc`.

## 4. Hotplug: which events run a fetch

`hotplug-iface` runs on every interface hotplug event OpenWrt fires,
so it must filter hard:

- Reacts only to `ACTION=ifup` on `INTERFACE=wan`.
- Ignores `ifdown` and `ifupdate`.
- Ignores every other interface, including `wan6`: once `wan` itself
  is up, `stunmesh-agent` can already reach the dhtproxy over
  whichever address family is available.

If a deployment's WAN logical interface is not named `wan`, this
script needs its interface name changed (or made configurable) before
it will trigger. `PLAN.md`'s UCI schema (section 3) has no option for
this yet; a deployment with a non-default WAN name is a case for the
`stunmesh-openwrt` packaging repository to resolve, not this
repository.

`stunmesh-agent`'s own `--lock` file is the only thing that keeps this
hotplug-triggered fetch from overlapping a cron-triggered one; a
second instance that loses the lock exits 0 with one log line
(`PLAN.md` section 5, stage 3 item 2), so no separate locking is added
here.

## 5. Shell dialect

Both scripts target BusyBox ash (OpenWrt's `/bin/sh`), not bash: no
arrays, no `[[ ]]`, no `local` outside of what ash itself supports
(ash's `local` is fine; POSIX `sh` in general is not guaranteed to
have it, but BusyBox ash does), no `function` keyword, no
process substitution, no `$'...'` strings. `set -- ...` and `"$@"`
build each command's argument list, since ash has no arrays; this
also avoids the word-splitting bugs a plain string of flags would
have if a value ever contained a space. Checked with
`shellcheck -s dash`.
