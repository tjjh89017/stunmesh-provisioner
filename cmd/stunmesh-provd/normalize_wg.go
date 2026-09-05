package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// errFwmark means an interface's wg.yaml fwmark could not be turned
// into the bundle's required plain integer.
var errFwmark = errors.New("fwmark must be a decimal or 0x-hex integer, or a quoted string of one, and non-zero")

// errRoutingTable means an interface's wg.yaml routing_table.ipv4 or
// routing_table.ipv6 could not be turned into the bundle's required
// non-zero value.
var errRoutingTable = errors.New("routing_table.ipv4/ipv6 must be a string or a non-zero integer")

// normalizeWG rewrites wg.<iface>.fwmark and
// wg.<iface>.routing_table.ipv4/ipv6 in wgJSON so the embedded bundle
// only ever carries the plain-integer fwmark and string
// routing_table values internal/bundle accepts (docs/format.md 6).
// wg.yaml may spell fwmark as a quoted string (any base
// strconv.ParseUint(s, 0, 32) accepts) and routing_table.ipv4/ipv6 as
// a YAML integer; normalizeWG converts each to the bundle's expected
// type and leaves every other field in wgJSON untouched.
//
// It never prints a field's value: an error names only the
// interface and the field.
func normalizeWG(wgJSON []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(wgJSON))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("wg.yaml: %w", err)
	}

	ifaces, ok := raw.(map[string]any)
	if !ok {
		// Not an object; bundle.Parse reports its own error for this.
		return wgJSON, nil
	}

	for name, v := range ifaces {
		iface, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if err := normalizeFwmark(iface, name); err != nil {
			return nil, err
		}
		if err := normalizeRoutingTable(iface, name); err != nil {
			return nil, err
		}
	}

	return json.Marshal(ifaces)
}

// normalizeFwmark replaces iface["fwmark"] with a JSON integer when
// wg.yaml gave it as a string, parsed with strconv.ParseUint(s, 0,
// 32) (base 0: decimal, 0x hex, or leading-zero octal). A JSON number
// passes through unchanged; any other present type, a parse error, or
// zero is rejected.
func normalizeFwmark(iface map[string]any, name string) error {
	v, present := iface["fwmark"]
	if !present || v == nil {
		return nil
	}
	switch t := v.(type) {
	case json.Number:
		return nil
	case string:
		n, err := strconv.ParseUint(t, 0, 32)
		if err != nil || n == 0 {
			return fmt.Errorf("wg.yaml interface %q: fwmark: %w", name, errFwmark)
		}
		iface["fwmark"] = json.Number(strconv.FormatUint(n, 10))
		return nil
	default:
		return fmt.Errorf("wg.yaml interface %q: fwmark: %w", name, errFwmark)
	}
}

// normalizeRoutingTable replaces iface["routing_table"].ipv4/ipv6
// with its decimal string form when wg.yaml gave it as a YAML
// integer. A string passes through unchanged; any other present
// type, or zero, is rejected.
func normalizeRoutingTable(iface map[string]any, name string) error {
	v, present := iface["routing_table"]
	if !present || v == nil {
		return nil
	}
	rt, ok := v.(map[string]any)
	if !ok {
		// Not an object; bundle.Parse reports its own error for this.
		return nil
	}
	for _, field := range [...]string{"ipv4", "ipv6"} {
		fv, present := rt[field]
		if !present || fv == nil {
			continue
		}
		switch t := fv.(type) {
		case string:
			continue
		case json.Number:
			n, err := strconv.ParseUint(t.String(), 10, 64)
			if err != nil || n == 0 {
				return fmt.Errorf("wg.yaml interface %q: routing_table.%s: %w", name, field, errRoutingTable)
			}
			rt[field] = strconv.FormatUint(n, 10)
		default:
			return fmt.Errorf("wg.yaml interface %q: routing_table.%s: %w", name, field, errRoutingTable)
		}
	}
	return nil
}
