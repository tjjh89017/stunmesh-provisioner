package main

import (
	"fmt"
	"os"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
)

// loadIdentityKey reads the node identity private key from path
// (PLAN.md section 2.3: it decrypts the bundle and is never used for
// WireGuard). The error never includes key material, only the path.
func loadIdentityKey(path string) (crypto.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return crypto.Key{}, fmt.Errorf("read identity key %s: %w", path, err)
	}
	key, err := crypto.ParseKey(string(data))
	if err != nil {
		return crypto.Key{}, fmt.Errorf("identity key %s: not a valid key", path)
	}
	return key, nil
}

// selectStats counts what decryptAndSelect skipped, for a caller to
// log a summary. It never records which value was skipped or why: a
// skipped value may be a bundle meant for another node, third-party
// junk, or a value the node's build cannot parse, and naming any of
// that would add noise without telling the operator anything they can
// act on.
type selectStats struct {
	// Undecrypted counts values that did not authenticate and decrypt
	// with the node's identity key and the controller's public key.
	// PLAN.md 4.6 treats this as normal, not an error: a value under
	// the node's DHT key can be an old republish, junk from a third
	// party, or (in principle) a hash collision with a value for a
	// different recipient.
	Undecrypted int
	// Unparsed counts values that decrypted -- so nacl/box already
	// authenticated them as sealed by the holder of the controller's
	// private key -- but did not parse as bundle JSON (bundle.Parse).
	// This is treated the same as Undecrypted rather than as a hard
	// failure: a controller running a newer or older format than this
	// node understands must not stop the node from using the newest
	// value it CAN read, if there is one among several. The single
	// summary log line in doFetch mentions this count only when it
	// selects nothing at all.
	Unparsed int
}

// decryptAndSelect tries to open every value in values with senderPub
// (the controller's public key) and recipientPriv (this node's
// identity private key), and keeps the bundle with the largest
// Timestamp among the ones that decrypt and parse (PLAN.md 4.6).
//
// decryptAndSelect only calls bundle.Parse, not Validate: reading
// Timestamp to compare values is all selection needs. The PLAN.md 4.4
// phase 2 checks (namespace, node_id, and the rest) run on the single
// bundle decryptAndSelect returns, one later item's job, not here --
// running them on every candidate would reject a value for a
// different node before it even entered the comparison, but that
// value was never going to win regardless, since it also fails to
// decrypt with this node's key in the overwhelmingly common case.
//
// # Timestamp ties
//
// On an exact Timestamp tie, decryptAndSelect keeps the first value
// encountered in values' order and does not replace it with a later
// tied one. values' order is whatever the dhtproxy response happened
// to list, which PLAN.md does not define, so this rule is arbitrary
// but deterministic. It rarely matters in practice: two bundles that
// share a Timestamp came from the same publish round, and a publish
// round seals one identical plaintext for a node (PLAN.md 7.2), so
// tied values normally carry the same content anyway.
//
// decryptAndSelect returns a nil *bundle.Bundle if no value decrypts
// and parses; stats always reports the counts.
func decryptAndSelect(values [][]byte, senderPub, recipientPriv crypto.Key) (*bundle.Bundle, selectStats) {
	var best *bundle.Bundle
	var stats selectStats

	for _, v := range values {
		plain, err := crypto.Open(v, senderPub, recipientPriv)
		if err != nil {
			stats.Undecrypted++
			continue
		}

		b, err := bundle.Parse(plain)
		if err != nil {
			stats.Unparsed++
			continue
		}

		if best == nil || b.Timestamp > best.Timestamp {
			best = b
		}
	}

	return best, stats
}
