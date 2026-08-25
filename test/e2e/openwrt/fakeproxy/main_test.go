package main

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtkey"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtproxy"
)

// These tests drive store through the real internal/dhtproxy.Client,
// the same client stunmesh-provd and stunmesh-agent use, instead of
// hand-rolled HTTP calls. That is the one claim this file needs to
// prove: whatever store.ServeHTTP does, dhtproxy.Client can Put to it
// and Get the same bytes back.

func testKey(t *testing.T) string {
	t.Helper()
	key, err := dhtkey.Key("ns", "node")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}
	return key
}

func TestStore_PutThenGetRoundTrips(t *testing.T) {
	srv := httptest.NewServer(newStore())
	defer srv.Close()

	client, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("dhtproxy.New: %v", err)
	}

	key := testKey(t)
	want := []byte("sealed-bundle-bytes")

	if err := client.Put(context.Background(), key, want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	result, err := client.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(result.Values) != 1 {
		t.Fatalf("len(Values) = %d, want 1", len(result.Values))
	}
	if string(result.Values[0]) != string(want) {
		t.Fatalf("Values[0] = %q, want %q", result.Values[0], want)
	}
}

func TestStore_GetUnknownKeyIsEmptyNotError(t *testing.T) {
	srv := httptest.NewServer(newStore())
	defer srv.Close()

	client, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("dhtproxy.New: %v", err)
	}

	result, err := client.Get(context.Background(), testKey(t))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(result.Values) != 0 {
		t.Fatalf("len(Values) = %d, want 0 for a key never PUT", len(result.Values))
	}
}

func TestStore_SecondPutOverwritesTheFirst(t *testing.T) {
	srv := httptest.NewServer(newStore())
	defer srv.Close()

	client, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("dhtproxy.New: %v", err)
	}

	key := testKey(t)
	if err := client.Put(context.Background(), key, []byte("first")); err != nil {
		t.Fatalf("Put(first): %v", err)
	}
	if err := client.Put(context.Background(), key, []byte("second")); err != nil {
		t.Fatalf("Put(second): %v", err)
	}

	result, err := client.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(result.Values) != 1 || string(result.Values[0]) != "second" {
		t.Fatalf("Values = %v, want [\"second\"]", result.Values)
	}
}
