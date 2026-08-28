package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// maxDHTValueSize is the largest allowed size, in bytes, of the
// base64-encoded DHT value: base64(nonce || nacl/box(inner bundle
// JSON)) (PLAN.md 4.1, docs/format.md 4).
//
// 56 KiB is a placeholder. Stage 5 measures the real limit on a
// device and replaces this constant; nothing else in this file
// changes when it does.
const maxDHTValueSize = 56 * 1024

// naclBoxOverhead is the number of bytes golang.org/x/crypto/nacl/box
// adds on top of the plaintext: a 24-byte nonce plus box's 16-byte
// Poly1305 authenticator (PLAN.md 4.1, docs/format.md 4).
const naclBoxOverhead = 24 + 16

// maxInnerBundleSize is the largest allowed size, in bytes, of the
// inner bundle JSON, before it is ever encrypted.
//
// buildBundle runs before encryption (stage 2 item 7), so it cannot
// measure the true DHT value maxDHTValueSize describes. It measures a
// smaller threshold instead, derived by undoing the two encoding
// layers that stand between this file's output and the DHT value:
// nacl/box's fixed overhead, then base64 (4 output bytes per 3 input
// bytes, rounded up).
//
// Solving base64Len(plaintextLen+naclBoxOverhead) <= maxDHTValueSize
// for the largest safe plaintextLen gives:
//
//	plaintextLen <= 3*(maxDHTValueSize/4) - naclBoxOverhead
//
// The integer division above rounds down, which only ever makes this
// bound tighter (safer), never looser, so this holds even if
// maxDHTValueSize is not an exact multiple of 4.
const maxInnerBundleSize = 3*(maxDHTValueSize/4) - naclBoxOverhead

// errUneditedWGTemplate is returned by buildBundle when a node's
// wg.yaml is still the unedited template `node add` wrote (PLAN.md
// 7.4): a file that is entirely comments, or otherwise empty,
// converts to the YAML/JSON document `null`. bundle.Parse would
// otherwise reject it with the generic bundle.ErrNull, which does not
// tell an operator which file to fix or why.
var errUneditedWGTemplate = errors.New("wg.yaml is still the unedited template; fill in at least one WireGuard interface")

// assembledBundle is the wire shape buildBundle marshals to produce
// the inner bundle JSON that goes into bundle.Parse.
//
// WG is json.RawMessage, holding node.WG's bytes unchanged.
// json.Marshal copies a json.RawMessage's bytes into the output
// as-is (it does not re-encode them), so store's already-valid `wg`
// JSON (PLAN.md 4.2) is embedded verbatim: no double-encoding, no
// string concatenation, and no risk of the assembled document
// escaping wrong. Namespace, NodeID, and Stunmesh are plain Go
// strings, so encoding/json escapes them the normal, correct way.
//
// This is safer than building the JSON by hand with string
// concatenation (which would have to reimplement JSON string
// escaping for Namespace, NodeID, and Stunmesh) and safer than
// building a bundle.Bundle by hand field by field (which would skip
// bundle.Parse's phase-1 checks entirely; see the package doc for
// why that must never happen).
type assembledBundle struct {
	Version   int             `json:"version"`
	Namespace string          `json:"namespace"`
	NodeID    string          `json:"node_id"`
	Timestamp int64           `json:"timestamp"`
	WG        json.RawMessage `json:"wg"`
	Stunmesh  string          `json:"stunmesh"`
}

// buildBundle assembles and validates the inner bundle for one node
// (PLAN.md 7.2 steps 2-3, stage 2 item 6).
//
// now is stamped as the bundle's timestamp. buildBundle never reads
// the clock itself; the caller (stage 2 item 7's publish loop) passes
// env.Now() explicitly. This lets a test fix the timestamp, which
// matters because PLAN.md 4.5's canonical form excludes it: two
// builds of the same, unchanged node one round apart get different
// timestamps but must produce identical canonical bytes, and only an
// injected clock lets a test demonstrate that.
//
// buildBundle assembles the full inner bundle JSON (see
// assembledBundle) and always runs it through bundle.Parse and then
// (*bundle.Bundle).Validate, the same two-phase check
// stunmesh-agent applies after decryption (docs/format.md 7). It
// never builds a bundle.Bundle by hand, so it can never publish a
// bundle the agent would reject.
//
// A node whose wg.yaml is still the unedited template (PLAN.md 7.4)
// decodes to the JSON document `null` at the top level, which
// bundle.Parse would reject with the generic bundle.ErrNull.
// buildBundle checks for exactly that one shape -- the whole wg.yaml
// document is `null`, not some deeper field -- and reports
// errUneditedWGTemplate instead, naming the node and the file. A
// `null` anywhere else in an edited wg.yaml (for example, an explicit
// `mtu: null` on a filled-in interface) does not match this shape: it
// only ever shows up nested inside an object, never as the top-level
// document, so it still reaches bundle.Parse and is reported as the
// ordinary, correctly wrapped bundle.ErrNull.
//
// buildBundle also rejects an inner bundle whose JSON is larger than
// maxInnerBundleSize (see its doc comment for what that bound
// protects and why).
//
// No error buildBundle returns includes a file's content: wg.yaml
// holds a private key.
func buildBundle(namespace string, node *store.Node, now time.Time) (*bundle.Bundle, error) {
	if isJSONNull(node.WG) {
		return nil, fmt.Errorf("node %q: wg.yaml: %w", node.NodeID, errUneditedWGTemplate)
	}

	data, err := json.Marshal(assembledBundle{
		Version:   1,
		Namespace: namespace,
		NodeID:    node.NodeID,
		Timestamp: now.Unix(),
		WG:        node.WG,
		Stunmesh:  node.Stunmesh,
	})
	if err != nil {
		return nil, fmt.Errorf("node %q: assemble bundle: %w", node.NodeID, err)
	}

	b, err := bundle.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("node %q: %w", node.NodeID, err)
	}

	if err := b.Validate(namespace, node.NodeID); err != nil {
		return nil, fmt.Errorf("node %q: %w", node.NodeID, err)
	}

	// Measure the exact bytes buildBundle's caller (stage 2 item 7)
	// will encrypt: the validated bundle re-marshaled through its own
	// MarshalJSON, not the assembled `data` above. The two are
	// substantively the same content; re-marshaling the validated
	// value is the one guaranteed to match what actually gets
	// encrypted.
	wire, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("node %q: marshal bundle: %w", node.NodeID, err)
	}
	if len(wire) > maxInnerBundleSize {
		return nil, fmt.Errorf("node %q: bundle is %d bytes, exceeds the %d byte limit", node.NodeID, len(wire), maxInnerBundleSize)
	}

	return b, nil
}

// isJSONNull reports whether raw is exactly the JSON document `null`,
// ignoring leading and trailing whitespace. It is used only to
// recognize an unedited wg.yaml template (see buildBundle); it must
// not match a `null` nested inside a larger document, which always
// appears after some other byte (a brace, bracket, colon, or comma),
// never as the whole trimmed document.
func isJSONNull(raw []byte) bool {
	trimmed := trimJSONWhitespace(raw)
	return string(trimmed) == "null"
}

// trimJSONWhitespace trims the four whitespace bytes JSON permits
// between tokens (space, tab, newline, carriage return) from both
// ends of raw.
func trimJSONWhitespace(raw []byte) []byte {
	isSpace := func(b byte) bool {
		return b == ' ' || b == '\t' || b == '\n' || b == '\r'
	}
	start := 0
	for start < len(raw) && isSpace(raw[start]) {
		start++
	}
	end := len(raw)
	for end > start && isSpace(raw[end-1]) {
		end--
	}
	return raw[start:end]
}
