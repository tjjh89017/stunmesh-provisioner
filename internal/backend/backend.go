// Package backend declares the rendezvous storage contract: the small
// surface a deployment publishes a sealed bundle to, and a node fetches
// one from. internal/dhtproxy is the first, and so far only,
// implementation (docs/format.md section 3).
//
// This package holds only the contract (Store, Result). Every
// implementation-specific concern -- proxy lists, HTTP status
// handling, key format, partial-outage reporting -- stays in the
// implementing package. Callers that only need to read or write a
// value should depend on Store, not on a concrete client type.
package backend

import "context"

// TypeDHTProxy is the "type" value that selects the dhtproxy plugin
// in a provd.yaml backend selection (docs/format.md section 3) and
// stunmesh-agent's --backend flag. It is the only backend type this
// module implements. It lives here, in the shared contract package,
// so store.BackendConfig, stunmesh-agent's Config, and the
// internal/backend/dial constructor all compare against the same
// string instead of each hard-coding "dhtproxy" separately.
const TypeDHTProxy = "dhtproxy"

// Store is the rendezvous storage a deployment publishes to and a
// node fetches from.
//
// Get and Put both take key, the same DHT key format
// internal/dhtkey produces: a key is part of a rendezvous secret, so
// an implementation must never put a key, or the data associated with
// it, into an error message.
type Store interface {
	// Get fetches the values stored under key. An implementation
	// documents its own rules for what an absent value, a partial
	// outage, and a hard failure look like; see internal/dhtproxy's
	// Client.Get for the first implementation's rules.
	Get(ctx context.Context, key string) (Result, error)

	// Put stores data under key. An implementation documents its own
	// rules for partial success across multiple backing hosts; see
	// internal/dhtproxy's Client.Put for the first implementation's
	// rules.
	Put(ctx context.Context, key string, data []byte) error
}

// Result is the outcome of a successful Get.
type Result struct {
	// Values holds the decoded value bytes, in the order they were
	// returned, up to the implementation's own cap on value count.
	Values [][]byte
	// Skipped counts values that could not be parsed by the
	// implementation (malformed encoding, missing fields).
	Skipped int
	// Dropped counts valid values received after the implementation's
	// cap was reached.
	Dropped int
	// URL is the address of the backing host that answered the
	// request.
	URL string
}
