package bundle_test

// Tests for ErrSurrogate: Parse must reject an escaped, unpaired
// UTF-16 high surrogate (jq rejects it too, so there is no reference
// for Canonical to match), while accepting every other surrogate
// spelling that both Go and jq decode to the same bytes.

import (
	"errors"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
)

// TestParseRejectsLoneHighSurrogateInStunmesh checks that a lone
// (unpaired) UTF-16 high-surrogate escape inside the `stunmesh` string
// value is rejected with ErrSurrogate.
func TestParseRejectsLoneHighSurrogateInStunmesh(t *testing.T) {
	data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"\ud800","wg":{}}`)
	_, err := bundle.Parse(data)
	if !errors.Is(err, bundle.ErrSurrogate) {
		t.Fatalf("Parse: got %v, want error wrapping ErrSurrogate", err)
	}
}

// TestParseRejectsLoneHighSurrogateInPeerNameKey checks that a lone
// high-surrogate escape inside a JSON object key (a peer name, not a
// string value) is also rejected with ErrSurrogate.
func TestParseRejectsLoneHighSurrogateInPeerNameKey(t *testing.T) {
	data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"","wg":{"wg0":{"private_key":"k","addresses":["1.1.1.1/32"],"peers":{"br\ud800vo":{"public_key":"p","allowed_ips":["1.1.1.2/32"]}}}}}`)
	_, err := bundle.Parse(data)
	if !errors.Is(err, bundle.ErrSurrogate) {
		t.Fatalf("Parse: got %v, want error wrapping ErrSurrogate", err)
	}
}

// TestParseAcceptsValidSurrogatePair checks that a correctly paired
// high+low surrogate escape (encoding U+1F600 GRINNING FACE) is
// accepted and that Canonical matches the jq reference.
func TestParseAcceptsValidSurrogatePair(t *testing.T) {
	jqPath := jqOrSkip(t)

	data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"😀","wg":{}}`)
	b := mustParse(t, data)
	if err := b.Validate("n", "a"); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}
	wantJQCanonical(t, jqPath, data, got)
}

// TestParseAcceptsLoneLowSurrogate checks that a lone (unpaired) LOW
// surrogate escape is accepted: both Go and jq decode it to U+FFFD
// (the replacement character), so there is no divergence to guard
// against, unlike a lone high surrogate.
func TestParseAcceptsLoneLowSurrogate(t *testing.T) {
	jqPath := jqOrSkip(t)

	data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"\udc00","wg":{}}`)
	b := mustParse(t, data)
	if err := b.Validate("n", "a"); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}
	wantJQCanonical(t, jqPath, data, got)
}

// TestParseAcceptsLiteralBackslashUD800Text checks that the literal
// text `\ud800` (an escaped backslash followed by literal characters,
// spelled `\\ud800` in the JSON source) is accepted: the leading
// backslash of `ud800` is not a real escape introducer, so this is
// not a surrogate escape at all.
func TestParseAcceptsLiteralBackslashUD800Text(t *testing.T) {
	jqPath := jqOrSkip(t)

	data := []byte(`{"version":1,"namespace":"n","node_id":"a","timestamp":1,"stunmesh":"\\ud800","wg":{}}`)
	b := mustParse(t, data)
	if err := b.Validate("n", "a"); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}
	wantJQCanonical(t, jqPath, data, got)
}
