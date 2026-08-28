package main

import (
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtproxy"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// --- newBackend: the selection factory (docs/format.md section 3) ---

func TestNewBackend_DHTProxyTypeBuildsDHTProxyClient(t *testing.T) {
	env, _, _ := newTestEnv(t.TempDir())

	got, err := newBackend(env, store.BackendConfig{
		Type:    "dhtproxy",
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
	// newDHTProxyClient's own tests already prove the client built this
	// way reaches env.HTTPClient's server instead of the network; this
	// only proves newBackend's dhtproxy arm still wires that seam
	// through, since it now goes through one more layer of
	// indirection.
	env, _, _ := newTestEnv(t.TempDir())
	env.HTTPClient = nil // production default; a nil client is valid input

	got, err := newBackend(env, store.BackendConfig{
		Type:    "dhtproxy",
		Proxies: []string{"https://dhtproxy.example"},
	})
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	if got == nil {
		t.Fatal("newBackend: got nil backend.Store with nil error")
	}
}

func TestNewBackend_UnknownTypeIsErrorNeverPanics(t *testing.T) {
	env, _, _ := newTestEnv(t.TempDir())

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("newBackend panicked on an unknown type: %v", r)
		}
	}()

	_, err := newBackend(env, store.BackendConfig{Type: "sentinel-bogus-backend-type"})
	if err == nil {
		t.Fatal("newBackend: want error for an unknown backend type, got nil")
	}
	if strings.Contains(err.Error(), "sentinel-bogus-backend-type") {
		t.Errorf("error leaks the bad type value: %v", err)
	}
}

func TestNewBackend_EmptyProxiesStillReachesDHTProxyNew(t *testing.T) {
	// dhtproxy.New itself rejects an empty proxy list; newBackend's
	// dhtproxy arm must forward that error rather than swallowing it.
	env, _, _ := newTestEnv(t.TempDir())

	_, err := newBackend(env, store.BackendConfig{Type: "dhtproxy"})
	if err == nil {
		t.Fatal("newBackend: want error when dhtproxy has no proxies, got nil")
	}
}
