package dial_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/backend"
	"github.com/tjjh89017/stunmesh-provisioner/internal/backend/dial"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtproxy"
)

func TestNew_DHTProxyTypeBuildsDHTProxyClient(t *testing.T) {
	got, err := dial.New(dial.Config{
		Type:    backend.TypeDHTProxy,
		Proxies: []string{"https://dhtproxy.example"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := got.(*dhtproxy.Client); !ok {
		t.Errorf("New returned %T, want *dhtproxy.Client", got)
	}
}

func TestNew_UnknownTypeIsErrorNeverPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("New panicked on an unknown type: %v", r)
		}
	}()

	_, err := dial.New(dial.Config{Type: "sentinel-bogus-backend-type"})
	if err == nil {
		t.Fatal("New: want error for an unknown backend type, got nil")
	}
	if strings.Contains(err.Error(), "sentinel-bogus-backend-type") {
		t.Errorf("error leaks the bad type value: %v", err)
	}
}

func TestNew_EmptyProxiesForwardsDHTProxyNewError(t *testing.T) {
	// dhtproxy.New itself rejects an empty proxy list; New's dhtproxy
	// arm must forward that error rather than swallowing it.
	_, err := dial.New(dial.Config{Type: backend.TypeDHTProxy})
	if err == nil {
		t.Fatal("New: want error when dhtproxy has no proxies, got nil")
	}
}

func TestNew_HTTPClientReachesTheBuiltClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got, err := dial.New(dial.Config{
		Type:       backend.TypeDHTProxy,
		Proxies:    []string{srv.URL},
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := got.Get(context.Background(), strings.Repeat("a", 40)); err != nil {
		t.Fatalf("Get: %v, want the built client to reach the httptest server", err)
	}
}

func TestNew_TimeoutSetsThePerRequestTimeoutWhenNoHTTPClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got, err := dial.New(dial.Config{
		Type:    backend.TypeDHTProxy,
		Proxies: []string{srv.URL},
		Timeout: 1 * time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := got.Get(context.Background(), strings.Repeat("a", 40)); err == nil {
		t.Fatal("Get: want a timeout error, got nil")
	}
}

func TestNew_HTTPClientOverridesTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got, err := dial.New(dial.Config{
		Type:       backend.TypeDHTProxy,
		Proxies:    []string{srv.URL},
		Timeout:    1 * time.Nanosecond,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := got.Get(context.Background(), strings.Repeat("a", 40)); err != nil {
		t.Fatalf("Get: %v (HTTPClient should have overridden the 1ns timeout)", err)
	}
}
