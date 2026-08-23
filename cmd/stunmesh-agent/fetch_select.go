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
// log a summary. It never records which value was skipped or why in
// detail: a skipped value may be a bundle meant for another node,
// third-party junk, a value the node's build cannot parse, or a value
// that fails a PLAN.md 4.4 check, and naming any of that in full would
// add noise without telling the operator anything they can act on.
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
	// private key -- but failed a PLAN.md 4.4 phase 1 check
	// (bundle.Parse): malformed JSON, or JSON that breaks a structural
	// rule such as an unknown key or a `null`. This is treated the
	// same as Undecrypted rather than as a hard failure: a controller
	// running a newer or older format than this node understands must
	// not stop the node from using the newest value it CAN read, if
	// there is one among several.
	Unparsed int
	// Rejected counts values that parsed (phase 1 passed) but failed a
	// PLAN.md 4.4 phase 2 check (bundle.Validate): wrong namespace or
	// node_id, an out-of-range field, a missing required key, and so
	// on. A rejected value is never selected, even when it carries the
	// largest Timestamp seen (see decryptAndSelect's doc comment).
	Rejected int
}

// decryptAndSelect tries to open every value in values with senderPub
// (the controller's public key) and recipientPriv (this node's
// identity private key). For every value that decrypts, it runs the
// full PLAN.md 4.4 check set -- phase 1 (bundle.Parse) then phase 2
// (bundle.Validate(namespace, nodeID)) -- and keeps the bundle with
// the largest Timestamp among the ones that pass every check
// (PLAN.md 4.6).
//
// # A newer value that fails a check never wins
//
// PLAN.md 4.4 says a value that fails a check is rejected outright:
// it is not "a decrypted bundle" any more, it is discarded. PLAN.md
// 4.6 then says the node keeps the decrypted bundle with the largest
// Timestamp. Read together, the Timestamp comparison of 4.6 runs only
// over the values that 4.4 has not already discarded: a rejected
// value cannot become "the decrypted bundle with the largest
// Timestamp" because it is not a candidate at all.
//
// decryptAndSelect implements that reading: it runs every check on
// every candidate before comparing Timestamps, so a newer value that
// fails a check (for example, the wrong namespace, or a range
// violation) never displaces an older value that passes every check.
// The alternative reading -- compare Timestamps first, run checks
// only on the winner -- would let one malformed or misdirected
// republish blind the node to a good, older bundle it already has
// every reason to trust; nothing in PLAN.md 4.6 asks for that, and
// 4.4's unconditional "the node rejects the value" reads against it.
//
// # Timestamp ties
//
// On an exact Timestamp tie among values that pass every check,
// decryptAndSelect keeps the first one encountered in values' order
// and does not replace it with a later tied one. values' order is
// whatever the dhtproxy response happened to list, which PLAN.md does
// not define, so this rule is arbitrary but deterministic. It rarely
// matters in practice: two bundles that share a Timestamp came from
// the same publish round, and a publish round seals one identical
// plaintext for a node (PLAN.md 7.2), so tied values normally carry
// the same content anyway.
//
// decryptAndSelect returns a nil *bundle.Bundle if no value decrypts
// and passes every check; stats always reports the counts.
func decryptAndSelect(values [][]byte, senderPub, recipientPriv crypto.Key, namespace, nodeID string) (*bundle.Bundle, selectStats) {
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

		if err := b.Validate(namespace, nodeID); err != nil {
			stats.Rejected++
			continue
		}

		if best == nil || b.Timestamp > best.Timestamp {
			best = b
		}
	}

	return best, stats
}
