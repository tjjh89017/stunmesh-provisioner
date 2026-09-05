package main

import (
	"fmt"
	"os"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
)

// loadIdentityKey reads the node identity private key from path. It
// decrypts the bundle and is never used for WireGuard. The error
// never includes key material, only the path.
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
// that fails a check, and naming any of that in full would add noise
// without telling the operator anything they can act on.
type selectStats struct {
	// Undecrypted counts values that did not authenticate and decrypt
	// with the node's identity key and the controller's public key.
	// This is normal, not an error: a value under the node's DHT key
	// can be an old republish, junk from a third party, or (in
	// principle) a hash collision with a value for a different
	// recipient.
	Undecrypted int
	// Unparsed counts values that decrypted -- so nacl/box already
	// authenticated them as sealed by the holder of the controller's
	// private key -- but failed a phase 1 check (bundle.Parse,
	// docs/format.md 7): malformed JSON, or JSON that breaks a
	// structural rule such as an unknown key or a `null`. This is
	// treated the same as Undecrypted rather than as a hard failure: a
	// controller running a newer or older format than this node
	// understands must not stop the node from using the newest value
	// it CAN read, if there is one among several.
	Unparsed int
	// Rejected counts values that parsed (phase 1 passed) but failed a
	// phase 2 check (bundle.Validate, docs/format.md 7): wrong
	// namespace or node_id, an out-of-range field, a missing required
	// key, and so on. A rejected value is never selected, even when it
	// carries the largest Timestamp seen (see decryptAndSelect's doc
	// comment).
	Rejected int
}

// decryptAndSelect tries to open every value in values with senderPub
// (the controller's public key) and recipientPriv (this node's
// identity private key). For every value that decrypts, it runs the
// full check set (docs/format.md 7) -- phase 1 (bundle.Parse) then
// phase 2 (bundle.Validate(namespace, nodeID)) -- and keeps the
// bundle with the largest Timestamp among the ones that pass every
// check (docs/format.md 9).
//
// Every check runs before the timestamps are compared, so a rejected
// value never displaces a good older value. An exact tie keeps the
// first value in response order.
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
