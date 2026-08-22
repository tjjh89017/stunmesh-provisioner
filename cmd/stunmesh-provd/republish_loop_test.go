package main

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtkey"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// editedWGYAML is filledWGYAML with a different address, so a test can
// prove a content edit changes the published bytes without going
// through an invalid document.
const editedWGYAML = `wg0:
  private_key: cGxhY2Vob2xkZXItcHJpdmF0ZS1rZXktMzItYnl0ZXMh
  addresses:
    - 10.0.0.9/24
  peers:
    bravo:
      public_key: cGxhY2Vob2xkZXItcHVibGljLWtleS0zMi1ieXRlcyE=
      allowed_ips:
        - 10.0.0.2/32
`

// setRepublishInterval rewrites namespace's provd.yaml with the same
// proxies it already has and interval as its republish_interval. It
// keeps controller.key/controller.pub untouched.
func setRepublishInterval(t *testing.T, env *Env, namespace, interval string) {
	t.Helper()
	deployment, err := store.ReadDeployment(env.Dir, namespace)
	if err != nil {
		t.Fatalf("ReadDeployment: %v", err)
	}
	var b strings.Builder
	b.WriteString("proxies:\n")
	for _, u := range deployment.Proxies {
		b.WriteString("  - " + u + "\n")
	}
	b.WriteString("republish_interval: " + interval + "\n")
	mustWriteFile(t, filepath.Join(env.Dir, namespace, "provd.yaml"), b.String())
}

// runLoopRounds drives runRepublishLoop for exactly n rounds with a
// fake Sleep that never really waits: it counts calls, invokes onTick
// (if given) with the 1-based round number just finished, and cancels
// the loop's context after the nth call so the loop stops cleanly
// right after that round -- no real wall-clock time passes anywhere
// in this function.
func runLoopRounds(t *testing.T, env *Env, ns string, n int, onTick func(round int)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	calls := 0
	env.Sleep = func(ctx context.Context, d time.Duration) error {
		calls++
		if onTick != nil {
			onTick(calls)
		}
		if calls >= n {
			cancel()
			return ctx.Err()
		}
		return nil
	}

	code := runRepublishLoop(ctx, env, ns)
	if code != ExitOK {
		t.Fatalf("runRepublishLoop: code = %d, want %d", code, ExitOK)
	}
	if calls != n {
		t.Fatalf("loop ran %d round(s), want exactly %d", calls, n)
	}
}

func TestRunRepublishLoop_UnchangedContentPutsIdenticalBytesAcrossRounds(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	setRepublishInterval(t, env, namespace, "1ns")
	addPublishTestNode(t, env, namespace, "alpha")

	wantKey, err := dhtkey.Key(namespace, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}

	runLoopRounds(t, env, "", 3, nil)

	fields := proxy.dataFieldsFor(wantKey)
	if len(fields) != 3 {
		t.Fatalf("proxy received %d puts, want 3", len(fields))
	}
	for i := 1; i < len(fields); i++ {
		if fields[i] != fields[0] {
			t.Fatalf("round %d put different bytes than round 0 over unchanged files:\nround0=%q\nround%d=%q", i, fields[0], i, fields[i])
		}
	}
}

func TestRunRepublishLoop_ContentChangeReseals(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	setRepublishInterval(t, env, namespace, "1ns")
	addPublishTestNode(t, env, namespace, "alpha")

	wantKey, err := dhtkey.Key(namespace, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}
	wgPath := filepath.Join(env.Dir, namespace, "nodes", "alpha", "wg.yaml")

	runLoopRounds(t, env, "", 2, func(round int) {
		if round == 1 {
			mustWriteFile(t, wgPath, editedWGYAML)
		}
	})

	fields := proxy.dataFieldsFor(wantKey)
	if len(fields) != 2 {
		t.Fatalf("proxy received %d puts, want 2", len(fields))
	}
	if fields[0] == fields[1] {
		t.Fatal("wg.yaml changed between rounds but the put bytes stayed identical")
	}
}

func TestRunRepublishLoop_IdentityKeyChangeReseals(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	setRepublishInterval(t, env, namespace, "1ns")
	addPublishTestNode(t, env, namespace, "alpha")

	wantKey, err := dhtkey.Key(namespace, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}
	identityPath := filepath.Join(env.Dir, namespace, "nodes", "alpha", "identity.pub")

	_, newPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	runLoopRounds(t, env, "", 2, func(round int) {
		if round == 1 {
			mustWriteFile(t, identityPath, newPub.String()+"\n")
		}
	})

	fields := proxy.dataFieldsFor(wantKey)
	if len(fields) != 2 {
		t.Fatalf("proxy received %d puts, want 2", len(fields))
	}
	if fields[0] == fields[1] {
		t.Fatal("identity.pub changed between rounds but the put bytes stayed identical")
	}
}

// TestRunRepublishLoop_RespectsPerNamespaceInterval checks that a
// namespace configured with a longer republish_interval is not
// republished on every round of a faster namespace's schedule. It
// uses a fake clock that advances by exactly the duration the loop
// asks Sleep to wait, so the due-time arithmetic is exercised without
// any real waiting.
func TestRunRepublishLoop_RespectsPerNamespaceInterval(t *testing.T) {
	fastProxy := newCapturingProxy()
	fastSrv := fastProxy.server()
	defer fastSrv.Close()
	slowProxy := newCapturingProxy()
	slowSrv := slowProxy.server()
	defer slowSrv.Close()

	env, fastNS, _ := setupPublishTestNamespace(t, []string{fastSrv.URL})
	setRepublishInterval(t, env, fastNS, "10s")
	addPublishTestNode(t, env, fastNS, "alpha")

	slowNS := "slowns"
	if code := runInit(env, []string{slowNS}); code != ExitOK {
		t.Fatalf("runInit(%s): code=%d", slowNS, code)
	}
	var b strings.Builder
	b.WriteString("proxies:\n  - " + slowSrv.URL + "\n")
	b.WriteString("republish_interval: 100s\n")
	mustWriteFile(t, filepath.Join(env.Dir, slowNS, "provd.yaml"), b.String())
	addPublishTestNode(t, env, slowNS, "bravo")

	fastKey, err := dhtkey.Key(fastNS, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}
	slowKey, err := dhtkey.Key(slowNS, "bravo")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}

	now := fixedNow()
	env.Now = func() time.Time { return now }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const rounds = 10 // 10 * 10s = 100s of simulated time
	calls := 0
	env.Sleep = func(ctx context.Context, d time.Duration) error {
		calls++
		now = now.Add(d)
		if calls >= rounds {
			cancel()
			return ctx.Err()
		}
		return nil
	}

	if code := runRepublishLoop(ctx, env, ""); code != ExitOK {
		t.Fatalf("runRepublishLoop: code = %d", code)
	}

	fastPuts := len(fastProxy.dataFieldsFor(fastKey))
	slowPuts := len(slowProxy.dataFieldsFor(slowKey))

	// The fast namespace (10s) is due every round; the slow namespace
	// (100s) is due only once, at the very first round (t=0), across
	// 100s of simulated time. fastPuts must be strictly greater, and
	// slowPuts must be small, or the two intervals were not honored
	// independently.
	if fastPuts <= slowPuts {
		t.Fatalf("fastPuts=%d slowPuts=%d, want the 10s namespace published strictly more often than the 100s one", fastPuts, slowPuts)
	}
	if slowPuts < 1 || slowPuts > 2 {
		t.Fatalf("slowPuts=%d, want 1 or 2 over 100s of simulated time with a 100s interval", slowPuts)
	}
}

func TestRunRepublishLoop_UnknownNamespaceIsError(t *testing.T) {
	root := t.TempDir()
	env, _, _ := newTestEnv(root)
	if code := runInit(env, nil); code != ExitOK {
		t.Fatalf("runInit: code=%d", code)
	}
	env.Sleep = func(ctx context.Context, d time.Duration) error {
		t.Fatal("Sleep called; runRepublishLoop should have failed before its first wait")
		return nil
	}

	code := runRepublishLoop(context.Background(), env, "does-not-exist")
	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
}

func TestRunRepublishLoop_NodeAddedMidRunIsPublished(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	setRepublishInterval(t, env, namespace, "1ns")
	addPublishTestNode(t, env, namespace, "alpha")

	betaKey, err := dhtkey.Key(namespace, "beta")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}

	runLoopRounds(t, env, "", 2, func(round int) {
		if round == 1 {
			addPublishTestNode(t, env, namespace, "beta")
		}
	})

	if len(proxy.dataFieldsFor(betaKey)) != 1 {
		t.Fatal("node added mid-run was not published on the next round")
	}
}

// hangingProxyListener opens a raw TCP listener that accepts exactly
// one connection, reads whatever the client sends, and never writes a
// response: it models an unreachable dhtproxy (PLAN.md 7.2's "10 nodes
// and unreachable proxies" scenario from Defect 2's report) at the
// transport level, with no HTTP server framework in the way to
// complicate connection-close accounting. accepted fires once the
// connection is established, so a test can wait for the request to be
// in flight before acting.
func hangingProxyListener(t *testing.T) (url string, accepted <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ch := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		close(ch)
		// Read and discard whatever the client sends; never respond.
		// The connection is intentionally leaked past this goroutine's
		// lifetime -- ln.Close() above stops new accepts, and the test
		// process exits without waiting for this goroutine, which is
		// fine because nothing here holds a reference the runtime
		// needs to collect.
		buf := make([]byte, 4096)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
	return "http://" + ln.Addr().String(), ch
}

// TestRunRepublishLoop_AbandonsPromptlyOnContextCancelDuringRound proves
// Defect 2's fix: a SIGTERM-equivalent context cancellation reaching
// runRepublishLoop while a round is stuck inside one node's DHT put
// aborts that put at once instead of waiting out the rest of
// putTimeout (30s). The fake proxy never responds, so the only way
// this test finishes quickly is if runRepublishLoop's ctx argument
// reached all the way into putSealed's http request and aborted it
// client-side.
//
// No real sleep drives the loop itself: the only real waiting in this
// test is synchronization on a channel to know the request is in
// flight before cancelling, and on the loop's own goroutine to
// finish -- not a fixed sleep standing in for the behavior under
// test.
func TestRunRepublishLoop_AbandonsPromptlyOnContextCancelDuringRound(t *testing.T) {
	proxyURL, accepted := hangingProxyListener(t)

	env, namespace, _ := setupPublishTestNamespace(t, []string{proxyURL})
	addPublishTestNode(t, env, namespace, "alpha")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- runRepublishLoop(ctx, env, "") }()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("round never reached the fake proxy; test setup is broken")
	}

	cancelledAt := time.Now()
	cancel()

	select {
	case code := <-done:
		if code != ExitOK {
			t.Fatalf("code = %d, want %d (clean shutdown)", code, ExitOK)
		}
		if elapsed := time.Since(cancelledAt); elapsed > 2*time.Second {
			t.Fatalf("runRepublishLoop took %v to stop after its context was cancelled, want well under putTimeout (%v)", elapsed, putTimeout)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runRepublishLoop did not stop after its context was cancelled; it is still waiting out the put")
	}
}
