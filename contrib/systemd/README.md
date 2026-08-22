# stunmesh-provd systemd service

This unit runs `stunmesh-provd publish` as the republish loop, on the
controller host. The controller host is a normal Linux machine, not an
OpenWrt router. OpenWrt packaging lives in the separate `stunmesh-openwrt`
repository; it does not use this unit.

## 1. Install the binary

Build the binary, then copy it to `/usr/local/bin`:

```sh
make provd
sudo install -m 0755 dist/stunmesh-provd /usr/local/bin/stunmesh-provd
```

Or run `sudo make install` from the repository root. `make install` does
the same copy, plus installs this unit file.

## 2. Create the dedicated user

The service runs as `stunmesh-provd`, not as root. Create the account
first:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin stunmesh-provd
```

## 3. Create the provisioning tree

Run `init` and `node add` as the `stunmesh-provd` user, so the tree they
create already belongs to it:

```sh
sudo -u stunmesh-provd stunmesh-provd init <namespace>
sudo -u stunmesh-provd stunmesh-provd node add <namespace> <node_id>
```

An operator who already ran `init` as their own account, or as root, must
give the tree to the service user instead of redoing that work:

```sh
sudo chown -R stunmesh-provd:stunmesh-provd /etc/stunmesh/provd
```

The namespace directory and its node directories stay mode 0700. The
`controller.key` and `wg.yaml` files stay mode 0600. Only their owner --
`stunmesh-provd`, once the steps above are done -- can read them. The
service unit never writes to this tree; it only reads it.

## 4. Install and start the unit

```sh
sudo cp contrib/systemd/stunmesh-provd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now stunmesh-provd.service
```

## 5. Check it

```sh
systemctl status stunmesh-provd.service
journalctl -u stunmesh-provd.service -f
```

A round is one line per node: `published <namespace>/<node_id>:
key=<hex>`. A namespace or node error names that namespace or node, never
a file's content or a key.

## Notes

- The unit sets `--dir /etc/stunmesh/provd` explicitly, the same path
  `stunmesh-provd` defaults to. Change both together if the tree lives
  elsewhere.
- The unit restarts on failure, up to 5 times within 10 minutes, then
  stops and leaves the service in the `failed` state. A repeating failure
  (for example a bad `--namespace`, or a tree the service user cannot
  read) needs an operator to look at `journalctl`, not another restart.
- `systemctl stop stunmesh-provd.service` sends SIGTERM. The loop exits 0
  on that signal; this is a clean shutdown, not a failure, and does not
  trigger a restart.
