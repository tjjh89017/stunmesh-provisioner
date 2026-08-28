// Package store reads and writes the operator's provisioning tree
// (PLAN.md 7.1).
//
// The read side (ReadDeployment, ReadNode, Namespaces, Nodes) never
// modifies a file. The write side (WriteFile, CreateDir) is the
// shared, single-responsibility layer that `stunmesh-provd init` and
// `node add` (stage 2 items 4 and 5) build on to create the tree; it
// never overwrites a file the operator already owns. See "Write
// primitives" below.
//
// # Tree layout
//
//	<root>/
//	├── README.md
//	└── <namespace>/
//	    ├── provd.yaml
//	    ├── controller.key
//	    ├── controller.pub
//	    └── nodes/
//	        └── <node_id>/
//	            ├── identity.pub
//	            ├── wg.yaml
//	            └── stunmesh.yaml
//
// The namespace and node ID are directory names, not file content.
// ReadDeployment and ReadNode reject a name that could escape the
// tree (empty, ".", "..", a leading ".", or a name containing a path
// separator) before touching the file system.
//
// # YAML decision
//
// wg.yaml must become the bundle's `wg` section without losing the
// presence semantics that internal/bundle depends on: an absent key,
// an explicit empty map (`{}`), and an explicit empty list (`[]`)
// must stay distinguishable (PLAN.md 4.3, 4.5; internal/bundle package
// doc). This package converts wg.yaml with sigs.k8s.io/yaml.YAMLToJSON
// instead of decoding it into a Go struct with a YAML library's own
// tags.
//
// YAMLToJSON parses the YAML into a generic tree
// (map[string]interface{}, []interface{}, scalars) and marshals that
// tree with encoding/json. A YAML key that is absent from the source
// document is simply not a key in the map; an explicit `{}` or `[]`
// stays an empty map or slice, not a nil one. Presence survives the
// conversion for free, because the conversion never passes through a
// Go struct's zero-value field. Decoding straight into a
// bundle.Interface-shaped struct with a YAML library's own tags would
// need every presence trick already in internal/bundle (pointer
// fields, custom (Un)MarshalJSON) re-derived a second time in the
// YAML library's tag dialect, and kept in sync with docs/format.md by
// hand forever after; converting to JSON reuses the one dialect
// internal/bundle already speaks.
//
// sigs.k8s.io/yaml was chosen over decoding directly with a YAML
// library (gopkg.in/yaml.v3 or go.yaml.in/yaml/v3) for that reason: it
// turns wg.yaml into the exact seam stage 2 item 6 (bundle assembly)
// needs — JSON bytes it can embed under the `wg` key of the assembled
// bundle and pass through bundle.Parse and bundle.Validate, the same
// code path stunmesh-agent uses. That gets item 6 unknown-key
// rejection, the no-`null` rule, the plain-base-10-integer rule, and
// the unpaired-surrogate rule for free, with one rule table
// (docs/format.md) instead of two.
//
// sigs.k8s.io/yaml is maintained by kubernetes-sigs and is the YAML
// library Kubernetes itself uses for this same YAML-as-JSON pattern.
// Its only transitive dependency is go.yaml.in/yaml/v2, the
// yaml.v3-lineage fork that sigs.k8s.io/yaml now vendors its YAML
// parsing from; no other module is pulled in. This package never
// decodes wg.yaml into a typed struct itself (see ReadNode), so a
// YAML syntax error is a structural error ("did not find expected
// key"), not a type-mismatch error that could echo a field value
// (some "cannot unmarshal into T" messages from struct-typed
// decoding do echo the offending scalar); avoiding struct-typed
// decoding here is itself part of the no-secrets-in-errors discipline
// (see the package doc "Errors" section).
//
// # Seam for bundle assembly (stage 2 item 6)
//
// Node.WG is JSON bytes shaped exactly like the bundle's `wg` value:
// a map of interface name to interface fields, with presence
// preserved. It is not wrapped in an outer `{"wg": ...}` envelope.
// Item 6 assembles the full bundle object (`version`, `namespace`,
// `node_id`, `timestamp`, this `wg` value, and `stunmesh`) and
// validates the assembled whole with bundle.Parse and
// (*bundle.Bundle).Validate. This package performs no bundle-level
// validation itself; it only decodes files.
//
// # Errors
//
// A caller distinguishes three failure kinds with errors.Is:
//
//   - ErrNotExist: a required file or directory is absent.
//   - ErrMalformed: a file exists but its content is not well-formed
//     (bad YAML, bad duration syntax).
//   - ErrInvalidKey: a key file exists and parses as text but is not a
//     valid key (bad base64, wrong length).
//
// stunmesh-provd publish (stage 2 item 7) uses this to skip one bad
// node without aborting the others. No error message from this
// package ever includes a file's content or a key's value; only a
// path, a namespace, a node ID, or a field name.
//
// # Write primitives
//
// WriteFile and CreateDir are the only two ways this package touches
// the file system for writing. Both refuse to overwrite: WriteFile
// reports ErrExists for a file that is already there, and CreateDir
// treats an existing directory as success and leaves it untouched.
// Neither takes a "force" flag, because the operator owns every file
// under root and no caller may ever be given a way to overwrite one,
// accidentally or otherwise. errors.Is(err, ErrExists) lets a caller
// such as `init` tell "already there, nothing done" apart from a real
// failure, so re-running `init` or `node add` against an existing
// tree is calm, not an error.
//
// Both primitives call os.Chmod after creating their target, so the
// mode a caller asks for is the mode the file or directory ends up
// with, regardless of the process umask (an OpenFile or MkdirAll
// permission argument is masked by umask and can only ever come out
// narrower than requested, never wider; an unusual umask that masks
// an owner bit could otherwise silently produce a private key file
// that even its own owner cannot read). CreateDir chmods only the
// directory it was asked to create, not any parent it had to create
// along the way; a caller that wants a parent and a leaf at different
// modes calls CreateDir once per level, parent first.
//
// Mode policy is the caller's choice, not something these primitives
// bake in, but PLAN.md 7.1 fixes two: controller.key and wg.yaml are
// 0600, because they hold a private key. Every other file in the
// tree is 0644. For directories, PLAN.md 7.1 does not specify a mode;
// this package recommends 0700 for a namespace directory and a node
// directory, tighter than the 0755 of a plain directory (root,
// nodes/). Both hold at least one secret file. The plan describes no
// group-based access model and the controller runs as a single
// operator or root account, so there is no one who legitimately needs
// to list a secret directory's file names without also being able to
// read the 0600 files inside it; keeping the directory listing itself
// private costs nothing and follows the same reasoning that already
// puts controller.key and wg.yaml at 0600 instead of 0644.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/tjjh89017/stunmesh-provisioner/internal/backend"
	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
)

// ErrNotExist means a required file or directory is absent.
var ErrNotExist = errors.New("store: does not exist")

// ErrMalformed means a file exists but its content is not
// well-formed.
var ErrMalformed = errors.New("store: malformed content")

// ErrInvalidKey means a key file exists but does not hold a valid
// key.
var ErrInvalidKey = errors.New("store: invalid key")

// ErrInvalidName means a namespace or node ID name is not a valid
// directory name: empty, ".", "..", hidden (a leading "."), or
// containing a path separator.
var ErrInvalidName = errors.New("store: invalid name")

// Deployment is one namespace directory's settings: provd.yaml and
// the controller key pair.
type Deployment struct {
	// Namespace is the directory name.
	Namespace string
	// Backend is the storage backend provd.yaml selects (docs/format.md
	// section 3).
	Backend BackendConfig
	// RepublishInterval is the parsed republish_interval from
	// provd.yaml.
	RepublishInterval time.Duration
	// ControllerPrivateKey is controller.key, parsed.
	ControllerPrivateKey crypto.Key
	// ControllerPublicKey is controller.pub, parsed.
	ControllerPublicKey crypto.Key
}

// BackendConfig is the backend plugin a provd.yaml selects
// (docs/format.md section 3): either the one entry in its "plugins"
// map that "use_plugin" names, or the implicit dhtproxy plugin the
// legacy top-level "proxies" shorthand names. Type is always
// "dhtproxy" for now -- docs/format.md defines no other plugin type,
// and ReadDeployment rejects any other Type value in provd.yaml
// before a BackendConfig is ever built.
type BackendConfig struct {
	// Type is the plugin implementation. Always "dhtproxy" for now.
	Type string
	// Proxies is the list of dhtproxy base URLs.
	Proxies []string
}

// Node is one node directory under a namespace's nodes/ subdirectory.
type Node struct {
	// NodeID is the directory name.
	NodeID string
	// IdentityPublicKey is identity.pub, parsed.
	IdentityPublicKey crypto.Key
	// WG is wg.yaml, converted to JSON. It is shaped exactly like the
	// bundle's `wg` value (PLAN.md 4.2): a map of interface name to
	// interface fields. Presence is preserved: a field absent from
	// wg.yaml stays absent in WG, and an explicit empty map or list
	// stays present-and-empty. See the package doc "YAML decision"
	// and "Seam for bundle assembly".
	WG json.RawMessage
	// Stunmesh is the raw stunmesh.yaml text, unchanged. An empty
	// file is legitimate: it means "no stunmesh config" and is
	// distinct from a missing file, which is ErrNotExist.
	Stunmesh string
}

// provdYAML is the on-disk shape of provd.yaml (docs/format.md section
// 3). RepublishInterval is decoded as a string first because YAML has
// no duration type; Go parses it with time.ParseDuration afterward.
//
// Proxies and Plugins/UsePlugin are the two mutually exclusive forms
// a provd.yaml names its backend with: the legacy top-level "proxies"
// shorthand, or the "plugins" map plus "use_plugin" selector.
// backendConfig resolves whichever form is present into a
// BackendConfig, or rejects the file as malformed. A field left
// unset here (an absent YAML key) decodes to its Go zero value --
// nil for Proxies and Plugins, "" for UsePlugin -- which is exactly
// the "absent" case backendConfig's presence checks test for.
//
// An unknown top-level key, or an unknown key inside a plugins
// entry, is silently ignored: sigs.k8s.io/yaml's Unmarshal goes
// through encoding/json's default decoder, which does not reject
// unknown fields (unlike internal/bundle's decoder, which calls
// DisallowUnknownFields). provd.yaml is operator-edited configuration,
// not a value the network can forge, so this package keeps that
// existing, permissive behavior rather than introducing strictness
// only for the new nested form.
type provdYAML struct {
	Proxies           []string              `json:"proxies"`
	Plugins           map[string]pluginYAML `json:"plugins"`
	UsePlugin         string                `json:"use_plugin"`
	RepublishInterval string                `json:"republish_interval"`
}

// pluginYAML is one entry in provd.yaml's "plugins" map.
type pluginYAML struct {
	Type    string   `json:"type"`
	Proxies []string `json:"proxies"`
}

// backendConfig resolves p's backend selection into a BackendConfig,
// rejecting every malformed case docs/format.md section 3 lists.
// provdPath names the file being read, for the error only; the error
// never carries a value out of the file itself (an operator-chosen
// plugin name or type), only the name of the key involved, matching
// this package's no-file-content rule (package doc "Errors").
func backendConfig(p provdYAML, provdPath string) (BackendConfig, error) {
	hasProxies := p.Proxies != nil
	hasPlugins := p.Plugins != nil
	hasUsePlugin := p.UsePlugin != ""

	switch {
	case hasProxies && hasPlugins:
		return BackendConfig{}, fmt.Errorf("%w: %s: proxies and plugins both present", ErrMalformed, provdPath)
	case hasUsePlugin && !hasPlugins:
		return BackendConfig{}, fmt.Errorf("%w: %s: use_plugin without plugins", ErrMalformed, provdPath)
	case hasPlugins && !hasUsePlugin:
		return BackendConfig{}, fmt.Errorf("%w: %s: plugins without use_plugin", ErrMalformed, provdPath)
	case hasPlugins:
		plugin, ok := p.Plugins[p.UsePlugin]
		if !ok {
			return BackendConfig{}, fmt.Errorf("%w: %s: use_plugin names a missing plugins entry", ErrMalformed, provdPath)
		}
		if plugin.Type != backend.TypeDHTProxy {
			return BackendConfig{}, fmt.Errorf("%w: %s: unknown plugin type", ErrMalformed, provdPath)
		}
		// docs/format.md section 3's table marks "plugins.*.proxies" as
		// "Required when type is dhtproxy". Without this check, a
		// plugin entry with no proxies (or an explicit empty list)
		// resolves to a BackendConfig with an empty Proxies slice, and
		// the failure only ever surfaces later, at publish time, deep
		// inside dhtproxy.New -- with a message that never names
		// provd.yaml at all. Catching it here, at the one place every
		// reader of provd.yaml goes through, gives the operator a clear
		// error naming the file and the field instead.
		//
		// The legacy top-level "proxies" shorthand (the default case
		// below) deliberately keeps its existing, more permissive
		// behavior: docs/format.md section 3's required-proxies rule is
		// stated for the plugins table, not the shorthand, and an empty
		// shorthand proxies list already has other, existing test
		// coverage (TestReadDeployment_MissingControllerKey) relying on
		// it not being rejected here.
		if len(plugin.Proxies) == 0 {
			return BackendConfig{}, fmt.Errorf("%w: %s: plugins.*.proxies is required for a dhtproxy plugin", ErrMalformed, provdPath)
		}
		return BackendConfig{Type: backend.TypeDHTProxy, Proxies: plugin.Proxies}, nil
	default:
		// Neither form present, or only the legacy top-level "proxies"
		// shorthand: one implicit dhtproxy plugin. An empty or absent
		// proxies list is accepted here, unlike the plugins-form case
		// above: that is this package's existing behavior for the
		// shorthand, which docs/format.md section 3's required-proxies
		// rule does not mention.
		return BackendConfig{Type: backend.TypeDHTProxy, Proxies: p.Proxies}, nil
	}
}

// Namespaces lists the namespace directories directly under root. It
// skips README.md and any other non-directory entry, and any hidden
// entry (a name starting with "."). The result is sorted by
// directory-read order (os.ReadDir already sorts by name).
func Namespaces(root string) ([]string, error) {
	return listDirs(root)
}

// Nodes lists the node ID directories under
// <root>/<namespace>/nodes/. It skips any non-directory entry and any
// hidden entry.
func Nodes(root, namespace string) ([]string, error) {
	nsDir, err := ResolveName(root, namespace)
	if err != nil {
		return nil, err
	}
	return listDirs(filepath.Join(nsDir, "nodes"))
}

// listDirs returns the directory-entry names directly under dir that
// are themselves directories and not hidden (a name starting with
// ".").
func listDirs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotExist, dir)
		}
		return nil, fmt.Errorf("store: read %s: %w", dir, err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
}

// ResolveName validates name (a namespace or a node ID) and returns
// filepath.Join(root, name). It rejects a name that could escape
// root: empty, ".", "..", a leading ".", or a name containing a path
// separator.
//
// ResolveName is exported so that `stunmesh-provd init` and `node
// add` (stage 2 items 4 and 5) validate a namespace or node ID name
// the same way the read side does, before they call WriteFile or
// CreateDir with the resulting path.
func ResolveName(root, name string) (string, error) {
	if name == "" || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	if strings.ContainsRune(name, '/') || strings.ContainsRune(name, os.PathSeparator) {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	// filepath.Base guards against a name that is technically free of
	// "/" on this platform's separator convention but still would not
	// name a single, direct child of root once cleaned.
	if filepath.Base(name) != name {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return filepath.Join(root, name), nil
}

// ReadDeployment reads the namespace directory <root>/<namespace>:
// provd.yaml, controller.key, and controller.pub.
func ReadDeployment(root, namespace string) (*Deployment, error) {
	nsDir, err := ResolveName(root, namespace)
	if err != nil {
		return nil, err
	}

	provdPath := filepath.Join(nsDir, "provd.yaml")
	data, err := readFile(provdPath)
	if err != nil {
		return nil, err
	}

	var p provdYAML
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformed, provdPath, err)
	}

	backend, err := backendConfig(p, provdPath)
	if err != nil {
		return nil, err
	}

	interval, err := time.ParseDuration(p.RepublishInterval)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: republish_interval", ErrMalformed, provdPath)
	}
	// A non-positive interval is syntactically a valid duration but
	// turns the republish loop into an unthrottled flood: runsAt never
	// advances past now, so every round republishes immediately with
	// no wait at all. Reject it here, at the one place every reader of
	// provd.yaml goes through, so the operator gets a clear error
	// naming the file and field instead of the controller silently
	// hammering its own dhtproxy servers.
	if interval <= 0 {
		return nil, fmt.Errorf("%w: %s: republish_interval must be positive", ErrMalformed, provdPath)
	}

	priv, err := readKey(filepath.Join(nsDir, "controller.key"))
	if err != nil {
		return nil, err
	}
	pub, err := readKey(filepath.Join(nsDir, "controller.pub"))
	if err != nil {
		return nil, err
	}

	return &Deployment{
		Namespace:            namespace,
		Backend:              backend,
		RepublishInterval:    interval,
		ControllerPrivateKey: priv,
		ControllerPublicKey:  pub,
	}, nil
}

// ReadNode reads the node directory
// <root>/<namespace>/nodes/<nodeID>: identity.pub, wg.yaml, and
// stunmesh.yaml.
func ReadNode(root, namespace, nodeID string) (*Node, error) {
	nsDir, err := ResolveName(root, namespace)
	if err != nil {
		return nil, err
	}
	nodeDir, err := ResolveName(filepath.Join(nsDir, "nodes"), nodeID)
	if err != nil {
		return nil, err
	}

	identity, err := readKey(filepath.Join(nodeDir, "identity.pub"))
	if err != nil {
		return nil, err
	}

	wgPath := filepath.Join(nodeDir, "wg.yaml")
	wgYAML, err := readFile(wgPath)
	if err != nil {
		return nil, err
	}
	wgJSON, err := yaml.YAMLToJSON(wgYAML)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrMalformed, wgPath)
	}

	stunmeshPath := filepath.Join(nodeDir, "stunmesh.yaml")
	stunmesh, err := readFile(stunmeshPath)
	if err != nil {
		return nil, err
	}

	return &Node{
		NodeID:            nodeID,
		IdentityPublicKey: identity,
		WG:                json.RawMessage(wgJSON),
		Stunmesh:          string(stunmesh),
	}, nil
}

// readFile reads path read-only and classifies a missing file as
// ErrNotExist.
func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotExist, path)
		}
		return nil, fmt.Errorf("store: read %s: %w", path, err)
	}
	return data, nil
}

// readKey reads path and parses it as a crypto.Key. It classifies a
// missing file as ErrNotExist and a file that does not hold a valid
// key as ErrInvalidKey. The error never includes the file content.
func readKey(path string) (crypto.Key, error) {
	data, err := readFile(path)
	if err != nil {
		return crypto.Key{}, err
	}
	key, err := crypto.ParseKey(string(data))
	if err != nil {
		return crypto.Key{}, fmt.Errorf("%w: %s: %v", ErrInvalidKey, path, err)
	}
	return key, nil
}
