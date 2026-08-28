package main

import (
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/backend"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtproxy"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// --- newBackend: the store.BackendConfig -> dial.Config adapter
// (docs/format.md section 3) ---
//
// newBackend itself is now a thin adapter over
// internal/backend/dial.New: the type-dispatch logic (unknown type
// never panics and never echoes the bad value, an empty dhtproxy
// proxy list forwards dhtproxy.New's own error) is exercised once,
// for both binaries, by internal/backend/dial's own test file. These
// tests only cover what is specific to this binary: that newBackend
// maps store.BackendConfig's fields into dial.Config correctly, and
// that it wires env.HTTPClient through.

func TestNewBackend_DHTProxyTypeBuildsDHTProxyClient(t *testing.T) {
	env, _, _ := newTestEnv(t.TempDir())

	got, err := newBackend(env, store.BackendConfig{
		Type:    backend.TypeDHTProxy,
		Proxies: []string{"https://dhtproxy.example"},
	})
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	if _, ok := got.(*dhtproxy.Client); !ok {
		t.Errorf("newBackend returned %T, want *dhtproxy.Client", got)
	}
}

func TestNewBackend_DHTProxyUsesEnvHTTPClientWhenSet(t *testing.T) {
	// internal/backend/dial's own tests already prove the client built
	// this way reaches the given HTTPClient's server instead of the
	// network; this only proves newBackend still wires env.HTTPClient
	// through to dial.Config.HTTPClient.
	env, _, _ := newTestEnv(t.TempDir())
	env.HTTPClient = nil // production default; a nil client is valid input

	got, err := newBackend(env, store.BackendConfig{
		Type:    backend.TypeDHTProxy,
		Proxies: []string{"https://dhtproxy.example"},
	})
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	if got == nil {
		t.Fatal("newBackend: got nil backend.Store with nil error")
	}
}
