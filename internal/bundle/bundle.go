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
// Every JSON number in the input must be a plain base-10 integer
// (ErrNumber; see its doc comment), and `timestamp`, `listen_port`,
// `mtu`, `routes[].metric`, and `persistent_keepalive` must each fall
// within the range documented in docs/format.md 5 (ErrRange).
//
// Canonical form preserves the presence of empty containers exactly
// as received: a bundle parsed from JSON that explicitly has
// `"wg":{}`, `"routes":[]`, or `"options":{}` keeps that key in its
// canonical form, matching the `jq -S -c 'del(.timestamp)'` reference
// (PLAN.md 4.5). A key that was absent from the input stays absent.
//
// Presence is significant: an absent `wg` and an explicit empty `wg`
// canonicalize to different bytes, so Equal is false between them.
// `wg` is required (PLAN.md 4.3): Validate rejects an absent `wg`
// with ErrWG. An explicit empty `wg` (`{}`) is valid; it means remove
// every interface.
//
// Parse rejects a JSON `null` anywhere in the input, at any depth, as
// an object value or an array element, with ErrNull. Omit a key
// instead of setting it to `null`.
//
// Canonical's output on a bundle that fails Validate (for example, a
// required list or map left nil) is unspecified; callers should call
// Validate before Canonical.
//
// Canonical also normalizes its output's character escapes to match
// jq's choices (a raw U+007F byte becomes `\u007f`, and raw
// U+2028/U+2029 bytes replace encoding/json's `\u2028`/`\u2029`
// escapes) so the result equals `jq -S -c 'del(.timestamp)'` byte for
// byte on every input Validate accepts.
package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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

// ErrNull means the JSON input has an explicit `null` value somewhere
// (the whole document, a field value, or an array element). A `null`
// is indistinguishable from an absent key once decoded into a Go
// struct, which would make Canonical silently omit a key that the
// input meant to keep. Omit the key instead of setting it to `null`.
var ErrNull = errors.New("bundle: null is not permitted; omit the key instead")

// ErrNumber means a JSON number literal somewhere in the input is not
// a plain base-10 integer that both Go and jq represent identically.
// Rejected spellings: a fraction (`1.0`), an exponent (`1e3`, `1E3`),
// `-0`, and any literal too large for a signed 64-bit integer. Go's
// `*int` decoding and jq's float64 arithmetic diverge on exactly
// these inputs (a `-0` literal decodes to Go `0` but jq keeps the
// sign; a value beyond 2^53 loses precision under jq's float64), so
// Parse rejects them outright rather than risk Canonical silently
// disagreeing with the `jq -S -c 'del(.timestamp)'` reference.
var ErrNumber = errors.New("bundle: number is not a plain base-10 integer")

// Parse decodes an inner bundle from JSON.
//
// Parse rejects any key that is not in the field table of PLAN.md 4.3,
// at any level, rejects data that follows the JSON object, rejects a
// `null` anywhere in the input (ErrNull), and rejects a JSON number
// literal that is not a plain base-10 integer representable exactly
// in both Go and jq (ErrNumber; see its doc comment). Parse never
// puts a field value in its error message; the bundle may hold
// private keys.
func Parse(data []byte) (*Bundle, error) {
	dec0 := json.NewDecoder(bytes.NewReader(data))
	dec0.UseNumber()
	var raw any
	if err := dec0.Decode(&raw); err != nil {
		return nil, errParse
	}
	if err := checkRaw(raw); err != nil {
		return nil, err
	}

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

// checkRaw walks v, decoded from JSON into `any` with
// json.Decoder.UseNumber(), and reports the first problem found: a
// `null` anywhere (ErrNull; as v itself, an object value, or an array
// element, at any depth) or a json.Number literal that is not a plain
// base-10 integer (ErrNumber; see its doc comment).
func checkRaw(v any) error {
	if v == nil {
		return ErrNull
	}
	switch t := v.(type) {
	case map[string]any:
		for _, val := range t {
			if err := checkRaw(val); err != nil {
				return err
			}
		}
	case []any:
		for _, val := range t {
			if err := checkRaw(val); err != nil {
				return err
			}
		}
	case json.Number:
		if err := checkNumber(t); err != nil {
			return err
		}
	}
	return nil
}

// checkNumber reports ErrNumber if n's literal text is not a plain
// base-10 integer: it contains `.`, `e`, or `E`, it starts with
// `-0`, or it does not parse with strconv.ParseInt(s, 10, 64). See
// ErrNumber's doc comment for why each of these is rejected.
func checkNumber(n json.Number) error {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return ErrNumber
	}
	if strings.HasPrefix(s, "-0") {
		return ErrNumber
	}
	if _, err := strconv.ParseInt(s, 10, 64); err != nil {
		return ErrNumber
	}
	return nil
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
	// ErrRange means a numeric field is present but outside the range
	// documented in docs/format.md 5: `timestamp` (upper bound only;
	// the lower bound is ErrTimestamp), `listen_port`, `mtu`,
	// `routes[].metric`, and `persistent_keepalive`. Each bound closes
	// a gap between Go's *int/int64 decoding and jq's float64
	// arithmetic: a value outside the bound would round differently
	// under jq than it decodes in Go, breaking the
	// `jq -S -c 'del(.timestamp)'` byte-equality contract of
	// Canonical (PLAN.md 4.5).
	ErrRange = errors.New("bundle: numeric field is out of range")
	// ErrStunmesh means the bundle stunmesh field is absent. An
	// explicit empty string is valid; only a missing key is not.
	ErrStunmesh = errors.New("bundle: stunmesh is missing")
	// ErrWG means the bundle wg field is absent. An explicit empty
	// map (`{}`) is valid; only a missing key is not.
	ErrWG = errors.New("bundle: wg is missing")
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
	// 2^53-1: the largest integer jq's float64 arithmetic represents
	// exactly. A larger timestamp would round under jq but not under
	// Go's int64, breaking Canonical's byte-equality with the jq
	// reference (PLAN.md 4.5).
	const maxSafeInteger = 9007199254740991
	if b.Timestamp > maxSafeInteger {
		return fmt.Errorf("%w: timestamp exceeds %d", ErrRange, maxSafeInteger)
	}
	if b.Stunmesh == nil {
		return ErrStunmesh
	}
	if b.WG == nil {
		return ErrWG
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
		if iface.ListenPort != nil && (*iface.ListenPort < 1 || *iface.ListenPort > 65535) {
			return fmt.Errorf("%w %q: listen_port must be between 1 and 65535", ErrRange, name)
		}
		if iface.MTU != nil && (*iface.MTU < 576 || *iface.MTU > 65535) {
			return fmt.Errorf("%w %q: mtu must be between 576 and 65535", ErrRange, name)
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
			if peer.PersistentKeepalive != nil && (*peer.PersistentKeepalive < 0 || *peer.PersistentKeepalive > 65535) {
				return fmt.Errorf("%w %q: persistent_keepalive must be between 0 and 65535", ErrRange, pname)
			}
		}

		for _, route := range iface.Routes {
			if route.CIDR == "" {
				return fmt.Errorf("%w on interface %q: cidr is empty", ErrRoute, name)
			}
			if route.Gateway != nil && *route.Gateway == "" {
				return fmt.Errorf("%w on interface %q: gateway is present but empty", ErrRoute, name)
			}
			if route.Metric != nil {
				if m := int64(*route.Metric); m < 0 || m > 4294967295 {
					return fmt.Errorf("%w on interface %q: metric must be between 0 and 4294967295", ErrRange, name)
				}
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
	// encoding/json and jq -S -c disagree on the escape spelling of a
	// handful of bytes; normalizeEscapes rewrites Go's output to jq's
	// choices so Canonical matches the `jq -S -c 'del(.timestamp)'`
	// reference byte for byte (PLAN.md 4.5).
	out := normalizeEscapes(buf.Bytes())
	// Encode always appends a trailing newline; the canonical form has none.
	return bytes.TrimRight(out, "\n"), nil
}

// normalizeEscapes rewrites the byte-level differences between
// encoding/json's and jq 1.8.2's escaping choices, so Canonical's
// output matches the `jq -S -c 'del(.timestamp)'` reference exactly.
// Two differences are known (found by sweeping every code point in
// 0x00-0x1F, 0x7F, U+2028, U+2029, `"`, `\`, `/`, and non-ASCII
// samples through both encoders): encoding/json emits U+007F (DEL) as
// a raw, unescaped byte where jq emits `\u007f`, and encoding/json
// always escapes U+2028/U+2029 as `\u2028`/`\u2029` where jq emits
// their raw UTF-8 bytes. Every other code point already agrees
// between the two encoders (both use the short forms `\b \f \n \r \t`
// for their respective bytes and `\u00XX` for the remaining control
// bytes).
func normalizeEscapes(data []byte) []byte {
	out := unescapeLineSeparators(data)
	out = escapeRawDEL(out)
	return out
}

// escapeRawDEL replaces every raw 0x7F (DEL) byte with the six-byte
// escape `\u007f`, matching jq's output. This is a plain byte-level
// replace, not a backslash-parity-aware scan like
// unescapeLineSeparators: 0x7F is a single byte that never occurs as
// a continuation byte of a multi-byte UTF-8 sequence (those all have
// the high bit set) and is not JSON-structural (quote, backslash), so
// every occurrence of the raw byte in encoding/json's output is
// genuinely an unescaped DEL character, never part of some other
// encoded sequence.
func escapeRawDEL(data []byte) []byte {
	if bytes.IndexByte(data, 0x7F) == -1 {
		return data
	}
	out := make([]byte, 0, len(data))
	for _, b := range data {
		if b == 0x7F {
			out = append(out, '\\', 'u', '0', '0', '7', 'f')
		} else {
			out = append(out, b)
		}
	}
	return out
}

// u2028Bytes and u2029Bytes are the raw UTF-8 encodings of U+2028
// LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR.
var (
	u2028Bytes = []byte{0xE2, 0x80, 0xA8}
	u2029Bytes = []byte{0xE2, 0x80, 0xA9}
)

// unescapeLineSeparators replaces the six-byte escape sequences
// `\u2028` and `\u2029` with their raw UTF-8 bytes, but only where the
// leading backslash genuinely starts that escape: where it is
// preceded by an even number of consecutive backslashes (0, 2, 4,
// ...). An odd count means the backslash itself is the second half of
// an escaped `\\` pair, so the following `u2028`/`u2029` text is
// literal input content, not an escape produced by the JSON encoder
// for an actual U+2028/U+2029 character, and is left unchanged.
func unescapeLineSeparators(data []byte) []byte {
	out := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		if data[i] == '\\' && i+6 <= len(data) {
			seq := data[i+1 : i+6]
			isSep := bytes.Equal(seq, []byte("u2028")) || bytes.Equal(seq, []byte("u2029"))
			if isSep {
				n := 0
				for j := i - 1; j >= 0 && data[j] == '\\'; j-- {
					n++
				}
				if n%2 == 0 {
					if seq[4] == '8' {
						out = append(out, u2028Bytes...)
					} else {
						out = append(out, u2029Bytes...)
					}
					i += 6
					continue
				}
			}
		}
		out = append(out, data[i])
		i++
	}
	return out
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
