// Package yamlx converts YAML bytes to JSON bytes, the same
// YAML-as-JSON seam internal/store and cmd/stunmesh-agent's config
// loader need (docs/format.md; PLAN.md 4.4): presence survives
// because the conversion walks a yaml.Node tree instead of passing
// through a Go struct's zero value.
package yamlx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

// ErrMultipleDocuments means the input has more than one YAML
// document ("---" separated); only the first would be ambiguous to
// use, so this is rejected instead of silently picked.
var ErrMultipleDocuments = errors.New("yamlx: multiple yaml documents")

// ErrDuplicateKey means a mapping repeats the same string key; yaml.v3
// itself just keeps the last value, which would silently hide a typo
// in a config file, so ToJSON rejects it instead.
var ErrDuplicateKey = errors.New("yamlx: duplicate map key")

// ToJSON parses in as a single YAML document and marshals it as
// JSON. Empty input and a document that is only "null" both produce
// the JSON literal "null". A non-string mapping key is rejected,
// naming only the key's YAML type, never its value. A !!timestamp
// scalar is kept as its original string form instead of becoming a
// decoded time.Time, so an unquoted date stays a JSON string.
func ToJSON(in []byte) ([]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(in))

	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if err == io.EOF {
			return []byte("null"), nil
		}
		return nil, fmt.Errorf("yamlx: %w", err)
	}

	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, ErrMultipleDocuments
		}
		return nil, fmt.Errorf("yamlx: %w", err)
	}

	v, err := convert(&doc)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// convert walks node into a plain Go value (map[string]any, []any, or
// a scalar) suitable for encoding/json. It never routes through a
// full-document Unmarshal into interface{}, because that path decodes
// a !!timestamp scalar into time.Time instead of keeping its source
// text.
func convert(node *yaml.Node) (any, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) == 0 {
			return nil, nil
		}
		return convert(node.Content[0])
	case yaml.AliasNode:
		return convert(node.Alias)
	case yaml.MappingNode:
		return convertMapping(node)
	case yaml.SequenceNode:
		return convertSequence(node)
	case yaml.ScalarNode:
		return convertScalar(node)
	default:
		return nil, fmt.Errorf("yamlx: unsupported yaml node kind %d", node.Kind)
	}
}

// convertMapping requires every key to be a plain string scalar
// (docs/format.md's JSON object shape has no other kind of key); a
// present non-string key is rejected by its YAML tag name only. A
// repeated key is rejected too, instead of yaml.v3's default of
// silently keeping the last value.
func convertMapping(node *yaml.Node) (any, error) {
	m := make(map[string]any, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		if keyNode.Kind == yaml.AliasNode {
			keyNode = keyNode.Alias
		}
		if keyNode.Kind != yaml.ScalarNode || keyNode.ShortTag() != "!!str" {
			return nil, fmt.Errorf("yamlx: map key is not a string: %s", keyNode.ShortTag())
		}
		var key string
		if err := keyNode.Decode(&key); err != nil {
			return nil, fmt.Errorf("yamlx: line %d: cannot decode map key", keyNode.Line)
		}
		if _, dup := m[key]; dup {
			return nil, fmt.Errorf("%w: line %d", ErrDuplicateKey, keyNode.Line)
		}
		val, err := convert(node.Content[i+1])
		if err != nil {
			return nil, err
		}
		m[key] = val
	}
	return m, nil
}

func convertSequence(node *yaml.Node) (any, error) {
	s := make([]any, 0, len(node.Content))
	for _, c := range node.Content {
		v, err := convert(c)
		if err != nil {
			return nil, err
		}
		s = append(s, v)
	}
	return s, nil
}

// convertScalar decodes every scalar the way a full-document
// Unmarshal into interface{} would (native int/uint64 for integers,
// so a value above 2^53 keeps its exact digits through json.Marshal),
// except !!timestamp: node.Value is its original source text, kept
// as a string instead of yaml.v3's own time.Time decoding.
//
// A decode failure (for example an explicit "!!int" tag on text that
// is not a number) is reported by line and tag only: yaml.v3's own
// message for this case quotes the offending scalar text verbatim
// ("cannot decode !!str `...` as a !!int"), and wg.yaml scalars can be
// WireGuard private keys, so that text must never reach an error.
func convertScalar(node *yaml.Node) (any, error) {
	if node.ShortTag() == "!!timestamp" {
		return node.Value, nil
	}
	var v any
	if err := node.Decode(&v); err != nil {
		return nil, fmt.Errorf("yamlx: line %d: cannot decode scalar tagged %s", node.Line, node.ShortTag())
	}
	return v, nil
}
