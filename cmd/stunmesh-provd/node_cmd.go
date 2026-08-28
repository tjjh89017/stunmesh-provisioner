package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// nodeAddUsage is the usage line for `node add`. It is shared by every
// error path in this file so they never drift apart.
const nodeAddUsage = "usage: stunmesh-provd node add <namespace> <node_id> [<identity_pub_key>]\n"

// nodesDirMode is the mode for the <namespace>/nodes/ directory. It
// holds only node subdirectories, no file directly, so it gets the
// same plain mode as the provisioning root.
const nodesDirMode = 0o755

// nodeDirMode is the mode for one <namespace>/nodes/<node_id>/
// directory. It holds wg.yaml, which contains the tunnel private key
// (PLAN.md 7.1), so it gets the tighter mode a secret-holding
// directory needs, the same reasoning that gives the namespace
// directory 0700 in init_cmd.go.
const nodeDirMode = 0o700

// wgYAMLTemplate is the content `node add` writes for a new node's
// wg.yaml. It is fully commented out: every line starts with "#", so
// the file parses as the YAML document `null`, not as an empty map
// (`{}`).
//
// That choice is deliberate. wg.yaml becomes the bundle's `wg`
// section (PLAN.md 4.2, 4.3), and `wg` is required but may
// legitimately be an explicit empty map (`{}` means "remove every
// interface"). If the template parsed as `{}`, an operator who forgot
// to edit wg.yaml would get a bundle that validates and publishes
// successfully -- it would just silently tell the node to remove all
// its interfaces. Parsing as `null` instead makes stage 2 item 6
// (bundle assembly, which embeds this content under the `wg` key and
// validates with internal/bundle) reject the unedited file loudly, as
// a null value, right where the operator can see it -- instead of a
// working `publish` cycle that quietly wipes a node's tunnels.
const wgYAMLTemplate = `# wg.yaml -- WireGuard settings for this node.
#
# This file becomes the "wg" section of the node's bundle. Uncomment
# and fill in one block per WireGuard interface. Delete every "#" at
# the start of a line you use.
#
# wg0:
#   private_key: <this node's WireGuard tunnel private key, base64>
#   addresses:
#     - 10.0.0.1/24
#   # listen_port, mtu, route_allowed_ips, routes, and options are
#   # optional. See docs/format.md for their rules.
#   # listen_port: 51820
#   # mtu: 1420
#   # route_allowed_ips: false
#   # routes:
#   #   - cidr: 10.20.0.0/16
#   #     gateway: 10.0.0.2
#   peers:
#     bravo:
#       public_key: <bravo tunnel public key, base64>
#       allowed_ips:
#         - 10.0.0.2/32
#       # preshared_key, endpoint, and persistent_keepalive are
#       # optional.
#       # preshared_key: <psk, base64>
#       # persistent_keepalive: 25
#
# An empty "wg: {}" is valid and means "no interfaces": it removes
# every interface this node has. Write that explicitly if that is
# really what you want; do not leave this file as-is by accident.
`

// stunmeshYAMLTemplate is the content `node add` writes for a new
// node's stunmesh.yaml. It is empty on purpose: an empty file is a
// legitimate bundle "stunmesh" value (PLAN.md 4.3) meaning "no
// stunmesh config", so an operator who has no stunmesh-go settings
// for this node does not need to edit this file at all.
const stunmeshYAMLTemplate = ``

// runNode dispatches `stunmesh-provd node <subcommand>`. "add" is the
// only subcommand v1 defines (PLAN.md 7.4).
func runNode(env *Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, nodeAddUsage)
		return ExitUsage
	}

	switch args[0] {
	case "add":
		return runNodeAdd(env, args[1:])
	default:
		fmt.Fprintf(env.Stderr, "stunmesh-provd: node: unknown subcommand %q\n\n", args[0])
		fmt.Fprint(env.Stderr, nodeAddUsage)
		return ExitUsage
	}
}

// runNodeAdd implements `stunmesh-provd node add <namespace>
// <node_id> [<identity_pub_key>]` (PLAN.md 7.4).
//
// The identity key comes from the third positional argument when it
// is given. Otherwise runNodeAdd reads it from env.Stdin. This mirrors
// how init already treats "no namespace argument" as a request for a
// generated value, rather than introducing a separate "-" sentinel
// for the same idea.
//
// It is safe to run more than once against the same node: every write
// treats an existing file as success and leaves it untouched, so a
// re-run never clobbers an operator's edited wg.yaml.
func runNodeAdd(env *Env, args []string) int {
	if len(args) < 2 || len(args) > 3 {
		fmt.Fprint(env.Stderr, nodeAddUsage)
		return ExitUsage
	}

	namespace, nodeID := args[0], args[1]

	nsDir, err := store.ResolveName(env.Dir, namespace)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: node add: %v\n", err)
		return ExitError
	}

	deployment, err := store.ReadDeployment(env.Dir, namespace)
	if err != nil {
		if errors.Is(err, store.ErrNotExist) {
			fmt.Fprintf(env.Stderr, "stunmesh-provd: node add: namespace %q is not initialized (node %q): %v\n", namespace, nodeID, err)
			fmt.Fprintf(env.Stderr, "run `stunmesh-provd init %s` first\n", namespace)
			return ExitError
		}
		fmt.Fprintf(env.Stderr, "stunmesh-provd: node add: %v\n", err)
		return ExitError
	}

	nodesDir := filepath.Join(nsDir, "nodes")
	nodeDir, err := store.ResolveName(nodesDir, nodeID)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: node add: %v\n", err)
		return ExitError
	}

	identity, err := readIdentityKey(env, args)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: node add: %v\n", err)
		return ExitError
	}

	if err := store.CreateDir(nodesDir, nodesDirMode); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: node add: %v\n", err)
		return ExitError
	}
	if err := store.CreateDir(nodeDir, nodeDirMode); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: node add: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(env.Stdout, "node %s/%s: %s\n", namespace, nodeID, nodeDir)

	if err := writeNodeFile(env, filepath.Join(nodeDir, "identity.pub"), []byte(identity.String()+"\n"), 0o644, "identity.pub"); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: node add: %v\n", err)
		return ExitError
	}
	if err := writeNodeFile(env, filepath.Join(nodeDir, "wg.yaml"), []byte(wgYAMLTemplate), 0o600, "wg.yaml"); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: node add: %v\n", err)
		return ExitError
	}
	if err := writeNodeFile(env, filepath.Join(nodeDir, "stunmesh.yaml"), []byte(stunmeshYAMLTemplate), 0o644, "stunmesh.yaml"); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: node add: %v\n", err)
		return ExitError
	}

	printNodeConstants(env, namespace, nodeID, deployment)

	return ExitOK
}

// readIdentityKey returns the node identity public key for `node
// add`. args is the full (already length-checked) argument list of
// runNodeAdd: a third element supplies the key directly, its absence
// means "read it from env.Stdin". The key is parsed with
// crypto.ParseKey before it is returned, so an invalid key is
// rejected here rather than written to disk and discovered later, far
// from the cause, when `publish` fails on it. crypto.ParseKey trims
// surrounding whitespace, which matters for stdin input piped in with
// a trailing newline.
func readIdentityKey(env *Env, args []string) (crypto.Key, error) {
	var raw string
	if len(args) == 3 {
		raw = args[2]
	} else {
		data, err := io.ReadAll(env.Stdin)
		if err != nil {
			return crypto.Key{}, fmt.Errorf("read identity key from stdin: %w", err)
		}
		raw = string(data)
		// An empty stdin is almost always a plumbing mistake, not a bad
		// key: `docker exec` / `podman exec` without -i hands the
		// process a closed stdin, so the pipe the operator wrote never
		// arrives. crypto.ParseKey would call the empty string "must
		// decode to 32 bytes", which points at the key instead of the
		// pipe; name the real problem here.
		if strings.TrimSpace(raw) == "" {
			return crypto.Key{}, errors.New("identity key: stdin is empty (pass the key as an argument, or use docker/podman exec -i)")
		}
	}

	key, err := crypto.ParseKey(raw)
	if err != nil {
		// err (from crypto.ParseKey) never echoes raw; keep it that
		// way here too.
		return crypto.Key{}, fmt.Errorf("identity key: %w", err)
	}
	return key, nil
}

// writeNodeFile writes path with data and mode, treating
// store.ErrExists as a calm no-op: it reports what happened on
// env.Stdout and returns nil, exactly like init_cmd.go's writes.
// label is the file's name alone (no directory), for the message.
func writeNodeFile(env *Env, path string, data []byte, mode fs.FileMode, label string) error {
	if err := store.WriteFile(path, data, mode); err != nil {
		if !errors.Is(err, store.ErrExists) {
			return err
		}
		fmt.Fprintf(env.Stdout, "%s already exists, left unchanged\n", label)
		return nil
	}
	fmt.Fprintf(env.Stdout, "wrote %s\n", path)
	return nil
}

// printNodeConstants prints the five values PLAN.md section 3 lists
// for node init, in the four the controller can supply (the fifth,
// the node's own identity private key, never leaves the node).
func printNodeConstants(env *Env, namespace, nodeID string, deployment *store.Deployment) {
	fmt.Fprintf(env.Stdout, "NAMESPACE=%s\n", namespace)
	fmt.Fprintf(env.Stdout, "NODE_ID=%s\n", nodeID)
	fmt.Fprintf(env.Stdout, "CONTROLLER_PUBKEY=%s\n", deployment.ControllerPublicKey.String())
	for _, proxy := range deployment.Backend.Proxies {
		fmt.Fprintf(env.Stdout, "DHT_PROXY=%s\n", proxy)
	}
}
