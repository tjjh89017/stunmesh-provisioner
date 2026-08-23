// Package last reads and writes last.json, the agent's memory of what
// it created on this node (PLAN.md 2.6, 4.5, 6).
//
// # Schema
//
// last.json holds, for every interface the agent ever applied:
//
//   - Content: the interface's own fields (PLAN.md 4.2 "wg" value),
//     stored as a bundle.Interface. A later item (the diff, PLAN.md
//     6) canonicalizes this and the corresponding interface from the
//     new bundle the same way, and compares the two: equal content is
//     "unchanged", different content is "changed".
//   - Sections: the exact UCI section names the agent created for
//     this interface (the interface section itself, its route
//     sections, and its peer sections). A later item (the apply,
//     PLAN.md 6) deletes a "changed" or "removed" interface's
//     sections by these exact recorded names, never by pattern
//     (PLAN.md 6 "Rules").
//
// last.json also holds Stunmesh, the stunmesh-go config text the
// agent last wrote, for the same "unchanged" vs. "changed" comparison
// (PLAN.md 4.5: content is `wg` + `stunmesh`).
//
// State.WG reuses bundle.Interface directly, rather than a private
// copy of its fields, so the presence rules bundle.Interface already
// encodes (PLAN.md 4.3; an absent field and an explicit empty
// container are different content, see the internal/bundle package
// doc) apply here for free: encoding/json's normal (Un)Marshal
// behavior on bundle.Interface's fields -- most of them already
// pointers or nil-vs-empty slices and maps for exactly this reason --
// preserves presence through a Read/Write round trip without any
// extra code in this package.
//
// # Missing file
//
// A missing last.json is not an error. It means nothing has been
// applied to this node yet, so every interface in the next bundle is
// new (PLAN.md 4.5 "Missing last.json: treat as empty"). Read returns
// an empty, non-nil State in this case.
//
// # Corrupt or unreadable file
//
// An existing last.json that cannot be read, that is not valid JSON,
// or that declares a schema version this package does not know, is a
// hard error (ErrCorrupt), not treated as empty.
//
// This is deliberate. Silently treating a corrupt file as empty would
// make the agent believe every interface is new; it would try to
// create sections that already exist in UCI from the last successful
// apply, and it would lose the one record of which sections it is
// allowed to delete later (PLAN.md 6 "the agent deletes sections only
// by the exact names that last.json records"). Failing hard instead
// stops the agent from touching UCI at all until the operator
// intervenes, which matches PLAN.md 2.7: recovery from a lost
// last.json is out of scope for v1, and the sections stay in UCI
// until the operator removes them by hand. A node that cannot tell
// what it owns must not guess.
//
// # Writing
//
// Write is atomic and sets mode 0600 (PLAN.md 6: "last.json ...
// contains the tunnel private keys and the stunmesh text"). The
// caller decides when to call Write; PLAN.md 6 requires that to be
// only after every apply step has succeeded. This package does not
// enforce that ordering -- it only makes the write itself safe.
//
// # No secrets in errors
//
// Every error this package returns names a path and, for a decode
// failure, at most a JSON field name. None ever includes file
// content: last.json holds tunnel private keys and the stunmesh
// config text, and both can appear inside a syntactically broken
// file that trips a decode error.
package last

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
)

// CurrentVersion is the schema version this package reads and writes.
// Read rejects a file that declares any other version (ErrCorrupt);
// see the package doc "Corrupt or unreadable file".
const CurrentVersion = 1

// State is the schema of last.json: everything the agent recorded
// about what it last applied. See the package doc "Schema".
type State struct {
	Version int `json:"version"`
	// WG is keyed by interface name, the same key the bundle's own
	// `wg` map uses. A missing last.json (see Read) decodes to a
	// non-nil, empty WG, so every interface in the next bundle reads
	// as new without a nil check at the call site.
	WG map[string]Interface `json:"wg"`
	// Stunmesh is the stunmesh-go config text the agent last wrote.
	// It is always present once a bundle has been applied at all
	// (bundle.Bundle.Stunmesh is a required field, PLAN.md 4.3), so,
	// unlike bundle.Bundle.Stunmesh, this field does not need a
	// pointer to keep "absent" distinguishable from "": an empty
	// State (missing last.json) is the only absent case, and Read
	// reports that with an empty WG, not with this field.
	Stunmesh string `json:"stunmesh"`
}

// Interface is one WireGuard interface's recorded state: the content
// the agent applied, and the UCI section names it created for that
// content. See the package doc "Schema".
type Interface struct {
	// Content is the interface's fields as they were in the bundle
	// the agent applied (PLAN.md 4.2 "wg" value). It is not the UCI
	// text; it is the input the agent built that UCI text from, kept
	// so a later fetch can compare it against the new bundle's
	// interface (PLAN.md 4.5, 6).
	Content bundle.Interface `json:"content"`
	// Sections names every UCI section the agent created for this
	// interface. A later item deletes exactly these names, never a
	// pattern (PLAN.md 6 "Rules").
	Sections Sections `json:"sections"`
}

// Sections names the UCI sections one interface's apply created
// (PLAN.md 6 "UCI layout").
type Sections struct {
	// Interface is the interface section's name. PLAN.md 6 fixes it
	// equal to the bundle's interface key ("section name = netdev
	// name = bundle key"), so this field is always redundant with the
	// State.WG map key that holds it; it is still recorded explicitly
	// so Sections is a complete, self-contained list of every section
	// name a later delete step must remove, with no rule to
	// reconstruct from context.
	Interface string `json:"interface"`
	// Routes names the route sections, `<iface>_r_<n>`, in the order
	// the agent created them.
	Routes []string `json:"routes,omitempty"`
	// Peers names the peer sections, `<iface>_p_<peer>`, in the order
	// the agent created them.
	Peers []string `json:"peers,omitempty"`
}

// ErrCorrupt means last.json exists but this package could not use
// it: it failed to read, it is not valid JSON, or it declares a
// schema version other than CurrentVersion. See the package doc
// "Corrupt or unreadable file" for why this is a hard error rather
// than treated as an empty state. The wrapped detail never includes
// file content.
var ErrCorrupt = errors.New("last: corrupt or unreadable last.json")

// Read reads path and returns the State it holds.
//
// A missing path is not an error: Read returns an empty State (see
// the package doc "Missing file"). Any other failure to read or parse
// path is ErrCorrupt (see "Corrupt or unreadable file"); Read never
// returns a partially populated State alongside an error.
func Read(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyState(), nil
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, path, err)
	}

	var st State
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("%w: %s: not valid JSON", ErrCorrupt, path)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: %s: trailing data after the JSON object", ErrCorrupt, path)
	}

	if st.Version != CurrentVersion {
		return nil, fmt.Errorf("%w: %s: unknown schema version %d", ErrCorrupt, path, st.Version)
	}
	if st.WG == nil {
		st.WG = map[string]Interface{}
	}

	return &st, nil
}

// emptyState is the State Read returns for a missing last.json: no
// interface has ever been applied, so every interface in the next
// bundle is new (PLAN.md 4.5).
func emptyState() *State {
	return &State{
		Version: CurrentVersion,
		WG:      map[string]Interface{},
	}
}

// Write writes state to path atomically, at mode 0600.
//
// Write creates a temporary file in the same directory as path,
// writes and syncs it, then renames it onto path. A crash or power
// loss at any point during Write leaves path either absent, or still
// holding its previous content, or holding the new content in full --
// never truncated or partially written. os.Rename replaces an
// existing path atomically on every platform this project targets
// (Linux; PLAN.md 2.1.1 "OpenWrt only"), so Write both creates a new
// last.json and updates an existing one the same way; unlike
// writeIdentityKeyAtomic in cmd/stunmesh-agent/keygen_cmd.go, Write
// must succeed against an existing path, because the caller writes
// last.json again after every successful apply (PLAN.md 6, step 7).
//
// Write does not create path's parent directory; the caller is
// responsible for that directory already existing (on OpenWrt,
// /etc/stunmesh/provd/, the same directory the identity key lives in).
//
// Write never logs or echoes state's content; on failure, its error
// names only path.
func Write(path string, state *State) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("last: marshal %s: %w", path, err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".last.json.tmp-*")
	if err != nil {
		return fmt.Errorf("last: create temporary file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Best effort: if anything below fails before the rename, remove
	// the temporary file so it does not linger. After a successful
	// rename, tmpPath no longer exists (rename consumed it), so this
	// is a silent no-op on the success path.
	defer os.Remove(tmpPath)

	if cerr := tmp.Chmod(0o600); cerr != nil {
		tmp.Close()
		return fmt.Errorf("last: chmod %s: %w", tmpPath, cerr)
	}
	if _, werr := tmp.Write(data); werr != nil {
		tmp.Close()
		return fmt.Errorf("last: write %s: %w", tmpPath, werr)
	}
	if serr := tmp.Sync(); serr != nil {
		tmp.Close()
		return fmt.Errorf("last: sync %s: %w", tmpPath, serr)
	}
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("last: close %s: %w", tmpPath, cerr)
	}

	if rerr := os.Rename(tmpPath, path); rerr != nil {
		return fmt.Errorf("last: rename %s to %s: %w", tmpPath, path, rerr)
	}

	return nil
}
