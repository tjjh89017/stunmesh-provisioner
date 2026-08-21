// Package bundle defines the inner bundle format (PLAN.md section 4.2, 4.3).
//
// A bundle is the plain-text configuration that the controller sends to
// one node through the DHT. It holds zero or more WireGuard interfaces
// and one stunmesh-go config text.
//
// The `timestamp` field is not content. It only picks the newest of
// several values (PLAN.md 4.6). Canonical drops it, so two bundles
// that differ only in `timestamp` compare equal.
//
// Validate checks the fields in PLAN.md 4.4: version, namespace,
// node_id, a positive timestamp, and structural presence of the
// required sub-fields. It does not check WireGuard key syntax
// (base64, length) or CIDR syntax. Those checks are out of scope for
// this package.
//
// Canonical form preserves the presence of empty containers exactly
// as received: a bundle parsed from JSON that explicitly has
// `"wg":{}`, `"routes":[]`, or `"options":{}` keeps that key in its
// canonical form, matching the `jq -S -c 'del(.timestamp)'` reference
// (PLAN.md 4.5). A key that was absent from the input stays absent.
//
// Presence is significant: an absent `wg` and an explicit empty `wg`
// canonicalize to different bytes, so Equal is false between them. A
// publisher must pick one form; this package recommends always
// emitting `wg`, even when empty.
//
// Canonical's output on a bundle that fails Validate (for example, a
// required list or map left nil) is unspecified; callers should call
// Validate before Canonical.
package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Bundle is the inner bundle (PLAN.md 4.2).
//
// The json struct tags below are used only for decoding (Parse decodes
// through the standard reflection path, so json.Decoder.
// DisallowUnknownFields keeps rejecting unknown keys at every level).
// Encoding always goes through MarshalJSON, which does not consult
// these tags.
type Bundle struct {
	Version   int                  `json:"version"`
	Namespace string               `json:"namespace"`
	NodeID    string               `json:"node_id"`
	Timestamp int64                `json:"timestamp"`
	WG        map[string]Interface `json:"wg"`
	// Stunmesh is *string, not string, so an absent `stunmesh` key
	// stays distinguishable from an explicit `""`: nil means absent,
	// a pointer to "" means the input had `"stunmesh":""`, which is
	// the legitimate "no stunmesh config" value (PLAN.md 4.5,
	// docs/format.md 5). `stunmesh` is required, so Validate rejects
	// nil with ErrStunmesh.
	Stunmesh *string `json:"stunmesh"`
}

// MarshalJSON emits `wg` only when WG is non-nil, so an absent map and
// an explicitly empty one (`{}`) stay distinguishable: nil omits the
// key, a non-nil empty map emits `"wg":{}`. This lets Canonical derive
// canonical form straight from struct state (see the package doc)
// instead of from bytes captured at Parse time.
//
// `stunmesh` is emitted only when Stunmesh is non-nil, so a bundle
// built without ever setting Stunmesh (and thus failing Validate)
// does not emit a synthetic `"stunmesh":""`; see the package doc on
// Canonical's output for a bundle that fails Validate.
func (b Bundle) MarshalJSON() ([]byte, error) {
	m := map[string]any{
		"version":   b.Version,
		"namespace": b.Namespace,
		"node_id":   b.NodeID,
		"timestamp": b.Timestamp,
	}
	if b.WG != nil {
		m["wg"] = b.WG
	}
	if b.Stunmesh != nil {
		m["stunmesh"] = *b.Stunmesh
	}
	return json.Marshal(m)
}

// Interface is one WireGuard interface inside a bundle (PLAN.md 4.3).
// See the Bundle doc comment: the json tags apply to decoding only.
type Interface struct {
	PrivateKey      string            `json:"private_key"`
	ListenPort      *int              `json:"listen_port,omitempty"`
	Addresses       []string          `json:"addresses"`
	MTU             *int              `json:"mtu,omitempty"`
	RouteAllowedIPs *bool             `json:"route_allowed_ips,omitempty"`
	Routes          []Route           `json:"routes,omitempty"`
	Options         map[string]string `json:"options,omitempty"`
	Peers           map[string]Peer   `json:"peers"`
}

// MarshalJSON emits `routes`, `options`, and `peers` only when the
// corresponding field is non-nil, preserving explicit-empty vs.
// absent (see the package doc). `private_key` and `addresses` are
// required and always emitted; the remaining scalar fields are
// omitted when nil, like a plain `omitempty` struct tag.
//
// Peers is required by Validate, so a nil Peers here means the
// interface has not been validated (or was built directly in code
// without one); Canonical on such an interface is unspecified (see
// the package doc), and this method simply omits the key rather than
// emitting `"peers":null`.
func (i Interface) MarshalJSON() ([]byte, error) {
	m := map[string]any{
		"private_key": i.PrivateKey,
		"addresses":   i.Addresses,
	}
	if i.ListenPort != nil {
		m["listen_port"] = i.ListenPort
	}
	if i.MTU != nil {
		m["mtu"] = i.MTU
	}
	if i.RouteAllowedIPs != nil {
		m["route_allowed_ips"] = i.RouteAllowedIPs
	}
	if i.Routes != nil {
		m["routes"] = i.Routes
	}
	if i.Options != nil {
		m["options"] = i.Options
	}
	if i.Peers != nil {
		m["peers"] = i.Peers
	}
	return json.Marshal(m)
}

// RouteAllowedIPsOrDefault returns RouteAllowedIPs, or the default value
// true when it is absent (PLAN.md 4.3).
func (i Interface) RouteAllowedIPsOrDefault() bool {
	if i.RouteAllowedIPs == nil {
		return true
	}
	return *i.RouteAllowedIPs
}

// Route is one static route on an interface (PLAN.md 4.3).
//
// Gateway is a *string, not a string with `omitempty`, so an
// explicit `""` in the input stays distinguishable from an absent
// key: nil means absent, a pointer to "" means the input had
// `"gateway":""`. See the Bundle doc comment for why presence
// matters to Canonical.
type Route struct {
	CIDR    string  `json:"cidr"`
	Gateway *string `json:"gateway,omitempty"`
	Metric  *int    `json:"metric,omitempty"`
}

// Peer is one WireGuard peer inside an interface (PLAN.md 4.3). See
// the Bundle doc comment: the json tags apply to decoding only.
//
// PresharedKey and Endpoint are *string, not string with
// `omitempty`, so an explicit `""` in the input stays distinguishable
// from an absent key: nil means absent, a pointer to "" means the
// input had `"preshared_key":""` / `"endpoint":""`. See the Bundle
// doc comment for why presence matters to Canonical. Validate treats
// a present-but-empty value as an error: an empty preshared key or
// endpoint is never meaningful.
type Peer struct {
	PublicKey           string            `json:"public_key"`
	PresharedKey        *string           `json:"preshared_key,omitempty"`
	AllowedIPs          []string          `json:"allowed_ips"`
	Endpoint            *string           `json:"endpoint,omitempty"`
	PersistentKeepalive *int              `json:"persistent_keepalive,omitempty"`
	Options             map[string]string `json:"options,omitempty"`
}

// MarshalJSON emits `options` only when Options is non-nil, preserving
// explicit-empty vs. absent (see the package doc). `public_key` and
// `allowed_ips` are required and always emitted; `preshared_key` and
// `endpoint` are emitted whenever non-nil, including a pointer to
// `""`, so an explicit empty value round-trips; the remaining scalar
// fields are omitted when nil, like a plain `omitempty` struct tag.
func (p Peer) MarshalJSON() ([]byte, error) {
	m := map[string]any{
		"public_key":  p.PublicKey,
		"allowed_ips": p.AllowedIPs,
	}
	if p.PresharedKey != nil {
		m["preshared_key"] = *p.PresharedKey
	}
	if p.Endpoint != nil {
		m["endpoint"] = *p.Endpoint
	}
	if p.PersistentKeepalive != nil {
		m["persistent_keepalive"] = p.PersistentKeepalive
	}
	if p.Options != nil {
		m["options"] = p.Options
	}
	return json.Marshal(m)
}

// errParse is the generic Parse failure. Its message never carries a
// bundle field value. A specific decode error may add safe detail (a
// field name only) through wrapping.
var errParse = errors.New("bundle: invalid bundle JSON")

// Parse decodes an inner bundle from JSON.
//
// Parse rejects any key that is not in the field table of PLAN.md 4.3,
// at any level, and rejects data that follows the JSON object. Parse
// never puts a field value in its error message; the bundle may hold
// private keys.
func Parse(data []byte) (*Bundle, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var b Bundle
	if err := dec.Decode(&b); err != nil {
		// The stdlib "unknown field" error names only the field, never
		// a value. It is safe to report as-is.
		if isUnknownFieldError(err) {
			return nil, fmt.Errorf("bundle: %v", err)
		}
		return nil, errParse
	}

	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the JSON object", errParse)
	}

	return &b, nil
}

// isUnknownFieldError reports whether err is the stdlib "unknown field"
// decode error. encoding/json does not export a type for it.
func isUnknownFieldError(err error) bool {
	const prefix = "json: unknown field "
	return strings.HasPrefix(err.Error(), prefix)
}

// Sentinel errors from Validate. Each is wrapped with context that
// names the failing interface or peer key, never a value.
var (
	// ErrVersion means the bundle version is not 1.
	ErrVersion = errors.New("bundle: version is not 1")
	// ErrNamespace means the bundle namespace does not match.
	ErrNamespace = errors.New("bundle: namespace does not match")
	// ErrNodeID means the bundle node_id does not match.
	ErrNodeID = errors.New("bundle: node_id does not match")
	// ErrTimestamp means the bundle timestamp is not a positive value.
	ErrTimestamp = errors.New("bundle: timestamp is not positive")
	// ErrStunmesh means the bundle stunmesh field is absent. An
	// explicit empty string is valid; only a missing key is not.
	ErrStunmesh = errors.New("bundle: stunmesh is missing")
	// ErrInterface means a wg interface entry is invalid.
	ErrInterface = errors.New("bundle: invalid interface")
	// ErrPeer means a peer entry is invalid.
	ErrPeer = errors.New("bundle: invalid peer")
	// ErrRoute means a route entry is invalid.
	ErrRoute = errors.New("bundle: invalid route")
)

// Validate checks a decoded bundle against PLAN.md 4.4.
//
// Validate does not check WireGuard key syntax or CIDR syntax; that is
// out of scope for this package.
func (b *Bundle) Validate(namespace, nodeID string) error {
	if b.Version != 1 {
		return ErrVersion
	}
	if b.Namespace != namespace {
		return ErrNamespace
	}
	if b.NodeID != nodeID {
		return ErrNodeID
	}
	if b.Timestamp <= 0 {
		return ErrTimestamp
	}
	if b.Stunmesh == nil {
		return ErrStunmesh
	}

	for name, iface := range b.WG {
		if iface.PrivateKey == "" {
			return fmt.Errorf("%w %q: private_key is empty", ErrInterface, name)
		}
		if len(iface.Addresses) == 0 {
			return fmt.Errorf("%w %q: addresses has no entry", ErrInterface, name)
		}
		if iface.Peers == nil {
			return fmt.Errorf("%w %q: peers is missing", ErrInterface, name)
		}

		for pname, peer := range iface.Peers {
			if peer.PublicKey == "" {
				return fmt.Errorf("%w %q: public_key is empty", ErrPeer, pname)
			}
			if len(peer.AllowedIPs) == 0 {
				return fmt.Errorf("%w %q: allowed_ips has no entry", ErrPeer, pname)
			}
			if peer.PresharedKey != nil && *peer.PresharedKey == "" {
				return fmt.Errorf("%w %q: preshared_key is present but empty", ErrPeer, pname)
			}
			if peer.Endpoint != nil && *peer.Endpoint == "" {
				return fmt.Errorf("%w %q: endpoint is present but empty", ErrPeer, pname)
			}
		}

		for _, route := range iface.Routes {
			if route.CIDR == "" {
				return fmt.Errorf("%w on interface %q: cidr is empty", ErrRoute, name)
			}
			if route.Gateway != nil && *route.Gateway == "" {
				return fmt.Errorf("%w on interface %q: gateway is present but empty", ErrRoute, name)
			}
		}
	}

	return nil
}

// Canonical returns the bundle as canonical JSON for change detection
// (PLAN.md 4.5): the bundle without `timestamp`, with keys sorted
// recursively, no whitespace, and no trailing newline.
//
// When b was produced by Parse, Canonical works from the exact bytes
// Parse decoded, so the presence of an explicitly empty container
// (`"wg":{}`, `"routes":[]`, `"options":{}`) is preserved exactly as
// received; a key absent from the input stays absent. This matches
// the `jq -S -c 'del(.timestamp)'` reference bytes. Canonical derives
// this straight from the current struct state through MarshalJSON
// (see the package doc), so it always reflects any mutation made to b
// after Parse, and never needs bytes captured at decode time.
func (b *Bundle) Canonical() ([]byte, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("bundle: marshal: %w", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("bundle: unmarshal: %w", err)
	}
	delete(m, "timestamp")

	// json.Marshal HTML-escapes '&', '<', and '>' by default, which would
	// diverge from the `jq -S -c 'del(.timestamp)'` reference bytes
	// (PLAN.md 4.5). Use an Encoder with HTML escaping turned off instead.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("bundle: marshal canonical: %w", err)
	}
	// Encode always appends a trailing newline; the canonical form has none.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Equal reports whether two bundles have the same content, ignoring
// `timestamp` (PLAN.md 4.5).
func (b *Bundle) Equal(other *Bundle) (bool, error) {
	a, err := b.Canonical()
	if err != nil {
		return false, err
	}
	c, err := other.Canonical()
	if err != nil {
		return false, err
	}
	return bytes.Equal(a, c), nil
}
