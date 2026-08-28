package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtproxy"
)

// --- newBackend: the selection factory (docs/format.md section 3) ---

func TestNewBackend_DHTProxyTypeBuildsDHTProxyClient(t *testing.T) {
	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)

	got, err := newBackend(env, &Config{
		Backend: "dhtproxy",
		Proxies: []string{"https://dhtproxy.example"},
	})
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	if _, ok := got.(*dhtproxy.Client); !ok {
		t.Errorf("newBackend returned %T, want *dhtproxy.Client", got)
	}
}

func TestNewBackend_UnknownTypeIsErrorNeverPanics(t *testing.T) {
	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("newBackend panicked on an unknown type: %v", r)
		}
	}()

	_, err := newBackend(env, &Config{Backend: "sentinel-bogus-backend-type"})
	if err == nil {
		t.Fatal("newBackend: want error for an unknown backend type, got nil")
	}
	if strings.Contains(err.Error(), "sentinel-bogus-backend-type") {
		t.Errorf("error leaks the bad type value: %v", err)
	}
}

func TestNewBackend_EmptyProxiesStillReachesDHTProxyNew(t *testing.T) {
	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)

	_, err := newBackend(env, &Config{Backend: "dhtproxy"})
	if err == nil {
		t.Fatal("newBackend: want error when dhtproxy has no proxies, got nil")
	}
}
