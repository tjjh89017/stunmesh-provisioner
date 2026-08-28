package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/backend"
	"github.com/tjjh89017/stunmesh-provisioner/internal/backend/dial"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtproxy"
)

// --- newBackend: the *Config -> dial.Config adapter (docs/format.md
// section 3) ---
//
// newBackend itself is now a thin adapter over
// internal/backend/dial.New: the type-dispatch logic (unknown type
// never panics and never echoes the bad value, an empty dhtproxy
// proxy list forwards dhtproxy.New's own error) is exercised once,
// for both binaries, by internal/backend/dial's own test file. These
// tests only cover what is specific to this binary: that newBackend
// maps Config's fields into dial.Config correctly, including
// fetchProxyTimeout, which only this binary's newBackend passes.

func TestNewBackend_DHTProxyTypeBuildsDHTProxyClient(t *testing.T) {
	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)

	got, err := newBackend(env, &Config{
		Backend: backend.TypeDHTProxy,
		Proxies: []string{"https://dhtproxy.example"},
	})
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	if _, ok := got.(*dhtproxy.Client); !ok {
		t.Errorf("newBackend returned %T, want *dhtproxy.Client", got)
	}
}

// TestBackendDialConfig_MapsFieldsAndFetchProxyTimeout is a fast,
// network-free check on backendDialConfig, the pure mapping step
// newBackend calls before dial.New: it must carry cfg.Backend,
// cfg.Proxies, and env.HTTPClient through unchanged, and it must
// always set Timeout to fetchProxyTimeout -- the one field only this
// binary's mapping sets (cmd/stunmesh-provd's newBackend never sets
// dial.Config.Timeout; see its own backend_factory_test.go).
func TestBackendDialConfig_MapsFieldsAndFetchProxyTimeout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	client := &http.Client{}
	env.HTTPClient = client

	cfg := &Config{
		Backend: backend.TypeDHTProxy,
		Proxies: []string{"https://dhtproxy.example"},
	}

	got := backendDialConfig(env, cfg)
	want := dial.Config{
		Type:       backend.TypeDHTProxy,
		Proxies:    cfg.Proxies,
		HTTPClient: client,
		Timeout:    fetchProxyTimeout,
	}

	if got.Type != want.Type {
		t.Errorf("Type = %q, want %q", got.Type, want.Type)
	}
	if len(got.Proxies) != len(want.Proxies) || (len(got.Proxies) > 0 && got.Proxies[0] != want.Proxies[0]) {
		t.Errorf("Proxies = %v, want %v", got.Proxies, want.Proxies)
	}
	if got.HTTPClient != want.HTTPClient {
		t.Errorf("HTTPClient = %p, want %p (env.HTTPClient)", got.HTTPClient, want.HTTPClient)
	}
	if got.Timeout != want.Timeout {
		t.Errorf("Timeout = %v, want %v (fetchProxyTimeout)", got.Timeout, want.Timeout)
	}
}
