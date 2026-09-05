// Command fakeproxy is a minimal stand-in for a dhtproxy instance, used
// only by the OpenWrt e2e harness (test/e2e/openwrt). It speaks the same
// wire shape internal/dhtproxy.Client expects:
//
//	GET  /{key}   the last value PUT under key, as one line of JSON with
//	              a "data" field. 404 when key has never been PUT.
//	POST /{key}   stores the request body verbatim as that key's value.
//	              Any 2xx status is success; this always answers 200.
//
// See internal/dhtproxy's package doc for the protocol this mirrors.
//
// This is deliberately not the real dhtproxy: it keeps one value per key
// in a process-local map, never expires anything, and never talks to
// OpenDHT. That is exactly what the e2e harness needs: something for the
// real `stunmesh-provd publish` to put a bundle to, and for the harness
// and the guest's stunmesh-agent to read it back from, all inside the
// trusted network QEMU's slirp already provides.
//
// No TLS: the guest reaches the host only at 10.0.2.2 through QEMU's
// user-mode networking (slirp), a link that never leaves the host
// machine. There is no channel here worth encrypting, and adding HTTPS
// would only mean minting a throwaway CA and trusting it into the guest
// for no security benefit -- the bundle payload itself is already sealed
// end-to-end with nacl/box before it ever reaches this proxy.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "address to listen on")
	getDelay := flag.Duration("get-delay", 0, "delay before answering a GET, for e2e lock-contention tests")
	flag.Parse()

	s := newStore(*getDelay)
	log.Printf("fakeproxy: listening on %s", *addr)
	if err := http.ListenAndServe(*addr, s); err != nil { //nolint:gosec // e2e-only, no timeouts needed
		log.Fatalf("fakeproxy: %v", err)
	}
}

// store is the in-memory value table, keyed by the DHT key (the request
// path with its leading "/" stripped). It never inspects or logs a
// value's content: a stored value is sealed ciphertext, and the DHT key
// itself is part of a rendezvous secret (internal/dhtproxy's package
// doc), so nothing beyond a request's method and path is ever logged.
//
// getDelay, when non-zero, is slept at the start of every GET (see
// get): it holds the lock open long enough for a second, real
// `stunmesh-agent --oneshot` run to reliably overlap the first.
type store struct {
	mu       sync.Mutex
	values   map[string][]byte // key -> the exact PUT request body
	getDelay time.Duration
}

func newStore(getDelay time.Duration) *store {
	return &store{values: map[string][]byte{}, getDelay: getDelay}
}

func (s *store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/")
	switch r.Method {
	case http.MethodGet:
		s.get(w, key)
	case http.MethodPost:
		s.put(w, r, key)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// get answers a GET the way the real dhtproxy does for a known key: the
// stored PUT body, verbatim, as one newline-delimited JSON line
// (dhtproxy.Client.Get reads a "data" field per line; the stored body
// already has exactly that shape, since put keeps the untouched body a
// real dhtproxy.Client.Put sent -- {"data": "<base64>"}). An unknown key
// answers 404, which Client.Get treats as "no value here yet", not an
// error.
func (s *store) get(w http.ResponseWriter, key string) {
	if s.getDelay > 0 {
		time.Sleep(s.getDelay)
	}
	s.mu.Lock()
	value, ok := s.values[key]
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(value)
	_, _ = w.Write([]byte("\n"))
}

// put stores r's body verbatim under key. It does not decode the body at
// all: forwarding it unmodified is exactly right, since get serves the
// identical shape back out. An empty key (a POST to "/") is rejected: it
// can never be a real dhtkey (internal/dhtkey.Key never produces one),
// and storing under it would only ever be a caller's bug.
func (s *store) put(w http.ResponseWriter, r *http.Request, key string) {
	if key == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.values[key] = body
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}
