package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtkey"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// capturingProxy is a fake dhtproxy server. It records every PUT body
// by key so a test can decode and decrypt what publish actually sent.
type capturingProxy struct {
	mu   sync.Mutex
	puts map[string][]string // key -> raw request bodies, in arrival order
	fail bool                // when true, every request gets a 500
}

func newCapturingProxy() *capturingProxy {
	return &capturingProxy{puts: map[string][]string{}}
}

func (p *capturingProxy) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/")
		buf, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.puts[key] = append(p.puts[key], string(buf))
		p.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
}

func (p *capturingProxy) dataFieldsFor(key string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	bodies := p.puts[key]
	out := make([]string, 0, len(bodies))
	for _, body := range bodies {
		var obj struct {
			Data string `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &obj); err != nil {
			continue
		}
		out = append(out, obj.Data)
	}
	return out
}

// setupPublishTestNamespace creates a namespace with a controller key
// pair and provd.yaml pointing at proxyURLs, through the same
// runInit/runNodeAdd path an operator uses. It returns the Env, the
// namespace name, and the controller's public key (for decrypting
// what publish sends).
func setupPublishTestNamespace(t *testing.T, proxyURLs []string) (env *Env, namespace string, controllerPub crypto.Key) {
	t.Helper()
	root := t.TempDir()
	env, _, stderr := newTestEnv(root)

	namespace = "myns"
	if code := runInit(env, []string{namespace}); code != ExitOK {
		t.Fatalf("runInit: code=%d stderr=%q", code, stderr.String())
	}

	deployment, err := store.ReadDeployment(root, namespace)
	if err != nil {
		t.Fatalf("ReadDeployment: %v", err)
	}
	controllerPub = deployment.ControllerPublicKey

	writePublishTestProvdYAML(t, env, namespace, proxyURLs)

	return env, namespace, controllerPub
}

// writePublishTestProvdYAML points a namespace's provd.yaml at the
// fake proxy/proxies instead of the real Jami instances runInit wrote
// by default.
func writePublishTestProvdYAML(t *testing.T, env *Env, namespace string, proxyURLs []string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("proxies:\n")
	for _, u := range proxyURLs {
		b.WriteString("  - " + u + "\n")
	}
	b.WriteString("republish_interval: 5m\n")
	mustWriteFile(t, filepath.Join(env.Dir, namespace, "provd.yaml"), b.String())
}

// addPublishTestNamespace creates one more namespace in env's existing
// tree, through the same runInit path an operator uses, and points its
// provd.yaml at proxyURLs.
func addPublishTestNamespace(t *testing.T, env *Env, namespace string, proxyURLs []string) {
	t.Helper()
	if code := runInit(env, []string{namespace}); code != ExitOK {
		t.Fatalf("runInit(%s): code=%d", namespace, code)
	}
	writePublishTestProvdYAML(t, env, namespace, proxyURLs)
}

// addPublishTestNode adds a node with a real, decryptable identity key
// pair and fills in wg.yaml/stunmesh.yaml with valid content. It
// returns the node's identity private key.
func addPublishTestNode(t *testing.T, env *Env, namespace, nodeID string) crypto.Key {
	t.Helper()

	identityPriv, identityPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	if code := runNodeAdd(env, []string{namespace, nodeID, identityPub.String()}); code != ExitOK {
		t.Fatalf("runNodeAdd(%s): code=%d", nodeID, code)
	}

	nodeDir := filepath.Join(env.Dir, namespace, "nodes", nodeID)
	mustWriteFile(t, filepath.Join(nodeDir, "wg.yaml"), filledWGYAML)
	mustWriteFile(t, filepath.Join(nodeDir, "stunmesh.yaml"), "interfaces: {}\n")

	return identityPriv
}

func TestPublishRound_PutsDecryptableBundleToEveryProxy(t *testing.T) {
	proxyA := newCapturingProxy()
	srvA := proxyA.server()
	defer srvA.Close()
	proxyB := newCapturingProxy()
	srvB := proxyB.server()
	defer srvB.Close()

	env, namespace, controllerPub := setupPublishTestNamespace(t, []string{srvA.URL, srvB.URL})
	nodePriv := addPublishTestNode(t, env, namespace, "alpha")

	reports, err := publishRound(context.Background(), env, "")
	if err != nil {
		t.Fatalf("publishRound: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("len(reports) = %d, want 1", len(reports))
	}
	if reports[0].Err != nil {
		t.Fatalf("reports[0].Err = %v, want nil", reports[0].Err)
	}

	wantKey, err := dhtkey.Key(namespace, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}
	if reports[0].Key != wantKey {
		t.Fatalf("reports[0].Key = %q, want %q", reports[0].Key, wantKey)
	}

	for _, proxy := range []*capturingProxy{proxyA, proxyB} {
		fields := proxy.dataFieldsFor(wantKey)
		if len(fields) != 1 {
			t.Fatalf("proxy received %d puts for key %s, want 1", len(fields), wantKey)
		}

		// The wire format is base64(nonce || nacl/box(inner bundle
		// JSON)) (docs/format.md 4), with dhtproxy.Put doing the
		// base64 encoding itself. Decoding the captured "data" field
		// exactly once must therefore already be the sealed bytes,
		// not another layer of base64: base64-decoding it a second
		// time must fail, proving there is no double encoding.
		sealed, err := base64.StdEncoding.DecodeString(fields[0])
		if err != nil {
			t.Fatalf("data field is not valid base64: %v", err)
		}
		if _, err := base64.StdEncoding.DecodeString(string(sealed)); err == nil {
			t.Fatalf("data field decodes as base64 twice; it is double-encoded")
		}

		plain, err := crypto.Open(sealed, controllerPub, nodePriv)
		if err != nil {
			t.Fatalf("crypto.Open(captured value): %v", err)
		}

		var got map[string]any
		if err := json.Unmarshal(plain, &got); err != nil {
			t.Fatalf("decrypted plaintext is not valid JSON: %v", err)
		}
		if got["namespace"] != namespace {
			t.Errorf("decrypted namespace = %v, want %q", got["namespace"], namespace)
		}
		if got["node_id"] != "alpha" {
			t.Errorf("decrypted node_id = %v, want alpha", got["node_id"])
		}
	}
}

func TestPublishRound_SealedBytesMatchBundleCanonicalContent(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	addPublishTestNode(t, env, namespace, "alpha")

	reports, err := publishRound(context.Background(), env, "")
	if err != nil {
		t.Fatalf("publishRound: %v", err)
	}
	if len(reports) != 1 || reports[0].Err != nil {
		t.Fatalf("reports = %+v", reports)
	}
	if reports[0].Bundle == nil {
		t.Fatal("reports[0].Bundle is nil, item 8 needs it for change detection")
	}
	if len(reports[0].Sealed) == 0 {
		t.Fatal("reports[0].Sealed is empty, item 8 needs it to re-put unchanged content")
	}
	if reports[0].IdentityPublicKey == (crypto.Key{}) {
		t.Fatal("reports[0].IdentityPublicKey is unset, item 8 needs it for change detection")
	}
}

func TestPublishRound_OneBadNodeDoesNotAbortOthers(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	addPublishTestNode(t, env, namespace, "good")

	// "bad" gets the unedited wg.yaml template left in place: it must
	// fail buildBundle, but must not stop "good" from publishing.
	identityPriv, identityPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	_ = identityPriv
	if code := runNodeAdd(env, []string{namespace, "bad", identityPub.String()}); code != ExitOK {
		t.Fatalf("runNodeAdd(bad): code=%d", code)
	}

	reports, err := publishRound(context.Background(), env, "")
	if err != nil {
		t.Fatalf("publishRound: %v", err)
	}
	if len(reports) != 2 {
		t.Fatalf("len(reports) = %d, want 2", len(reports))
	}

	var goodReport, badReport *nodeReport
	for i := range reports {
		switch reports[i].NodeID {
		case "good":
			goodReport = &reports[i]
		case "bad":
			badReport = &reports[i]
		}
	}
	if goodReport == nil || badReport == nil {
		t.Fatalf("missing report(s): %+v", reports)
	}
	if goodReport.Err != nil {
		t.Fatalf("good node failed: %v", goodReport.Err)
	}
	if badReport.Err == nil {
		t.Fatal("bad node succeeded, want an error for the unedited template")
	}

	wantKey, err := dhtkey.Key(namespace, "good")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}
	if len(proxy.dataFieldsFor(wantKey)) != 1 {
		t.Fatalf("good node's value was not put to the proxy")
	}
}

func TestPublishRound_UnknownNamespaceIsError(t *testing.T) {
	root := t.TempDir()
	env, _, _ := newTestEnv(root)
	if code := runInit(env, nil); code != ExitOK {
		t.Fatalf("runInit: code=%d", code)
	}

	_, err := publishRound(context.Background(), env, "does-not-exist")
	if err == nil {
		t.Fatal("publishRound succeeded for an unknown namespace, want an error")
	}
	if !errors.Is(err, store.ErrNotExist) {
		t.Fatalf("error = %v, want it to wrap store.ErrNotExist", err)
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error %q does not name the namespace", err.Error())
	}
}

func TestPublishRound_NamespaceWithNoNodesIsNotAnError(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})

	reports, err := publishRound(context.Background(), env, namespace)
	if err != nil {
		t.Fatalf("publishRound: %v", err)
	}
	if len(reports) != 0 {
		t.Fatalf("len(reports) = %d, want 0", len(reports))
	}
}

func TestPublishRound_SecondRoundWithUnchangedFilesPutsIdenticalCanonicalContent(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	addPublishTestNode(t, env, namespace, "alpha")

	reports1, err := publishRound(context.Background(), env, "")
	if err != nil {
		t.Fatalf("publishRound #1: %v", err)
	}
	reports2, err := publishRound(context.Background(), env, "")
	if err != nil {
		t.Fatalf("publishRound #2: %v", err)
	}

	equal, err := reports1[0].Bundle.Equal(reports2[0].Bundle)
	if err != nil {
		t.Fatalf("Bundle.Equal: %v", err)
	}
	if !equal {
		t.Fatal("canonical content differs across two rounds over unchanged files")
	}

	// The sealed bytes themselves differ every round (crypto.Seal
	// picks a random nonce each call): publishRound always reseals.
	// It is item 8's job to notice the canonical content did not
	// change and skip the reseal, re-putting the cached bytes instead.
	if string(reports1[0].Sealed) == string(reports2[0].Sealed) {
		t.Fatal("two calls to publishRound produced identical Sealed bytes; Seal's nonce is not random")
	}
}

func TestRunPublish_ExitOKOnFullSuccess(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	addPublishTestNode(t, env, namespace, "alpha")

	code := runPublish(env, []string{"--once"})
	if code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", code, ExitOK, env.Stderr.(interface{ String() string }).String())
	}
}

func TestRunPublish_ExitErrorWhenANodeFails(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	_, identityPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	if code := runNodeAdd(env, []string{namespace, "bad", identityPub.String()}); code != ExitOK {
		t.Fatalf("runNodeAdd: code=%d", code)
	}

	stderr := env.Stderr.(interface{ String() string })

	code := runPublish(env, []string{"--once"})
	if code != ExitError {
		t.Fatalf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "1 of 1 node(s) failed") {
		t.Errorf("stderr %q does not contain the end-of-round summary", stderr.String())
	}
}

func TestRunPublish_ExitErrorOnPartialProxyFailure(t *testing.T) {
	ok := newCapturingProxy()
	srvOK := ok.server()
	defer srvOK.Close()

	failing := newCapturingProxy()
	failing.fail = true
	srvFail := failing.server()
	defer srvFail.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srvOK.URL, srvFail.URL})
	addPublishTestNode(t, env, namespace, "alpha")

	code := runPublish(env, []string{"--once"})
	if code != ExitError {
		t.Fatalf("code = %d, want %d: a value reaching one of two proxies is a failure", code, ExitError)
	}

	wantKey, err := dhtkey.Key(namespace, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}
	if len(ok.dataFieldsFor(wantKey)) != 1 {
		t.Fatal("the reachable proxy did not receive the value even though it was up")
	}
}

// TestRunPublish_NamespaceFlagPublishesOnlyThatNamespace pins the
// positive half of --namespace's contract: the named namespace's
// nodes are published, and every other namespace's nodes are left
// alone. (TestPublishRound_UnknownNamespaceIsError covers the
// negative half.) Without this, resolveNamespaces could keep its
// existence check but return every namespace, and no test would
// notice.
func TestRunPublish_NamespaceFlagPublishesOnlyThatNamespace(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, ns1, _ := setupPublishTestNamespace(t, []string{srv.URL})
	addPublishTestNode(t, env, ns1, "alpha")

	addPublishTestNamespace(t, env, "otherns", []string{srv.URL})
	addPublishTestNode(t, env, "otherns", "beta")

	code := runPublish(env, []string{"--namespace", ns1, "--once"})
	if code != ExitOK {
		t.Fatalf("code = %d, want %d; stderr=%q", code, ExitOK, env.Stderr.(interface{ String() string }).String())
	}

	ns1Key, err := dhtkey.Key(ns1, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key(%s): %v", ns1, err)
	}
	if got := len(proxy.dataFieldsFor(ns1Key)); got != 1 {
		t.Errorf("named namespace's node got %d put(s), want 1", got)
	}

	otherKey, err := dhtkey.Key("otherns", "beta")
	if err != nil {
		t.Fatalf("dhtkey.Key(otherns): %v", err)
	}
	if got := len(proxy.dataFieldsFor(otherKey)); got != 0 {
		t.Errorf("other namespace's node got %d put(s), want 0: --namespace did not filter", got)
	}
}

// TestRunPublish_BrokenNamespaceDoesNotAbortOthers exercises
// publishNamespace's failure isolation: a namespace whose provd.yaml
// does not parse becomes one namespace-level nodeReport, not an error
// that stops the round, so the healthy namespace still publishes and
// the exit code still reports the failure. The broken namespace is
// named to sort before the healthy one, so the round meets the
// failure first and must keep going.
func TestRunPublish_BrokenNamespaceDoesNotAbortOthers(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, healthy, _ := setupPublishTestNamespace(t, []string{srv.URL})
	addPublishTestNode(t, env, healthy, "alpha")

	addPublishTestNamespace(t, env, "aaa-broken", []string{srv.URL})
	mustWriteFile(t, filepath.Join(env.Dir, "aaa-broken", "provd.yaml"), "proxies: [broken\n")

	stderr := env.Stderr.(interface{ String() string })

	code := runPublish(env, []string{"--once"})
	if code != ExitError {
		t.Fatalf("code = %d, want %d: the broken namespace is a failure", code, ExitError)
	}

	healthyKey, err := dhtkey.Key(healthy, "alpha")
	if err != nil {
		t.Fatalf("dhtkey.Key: %v", err)
	}
	if got := len(proxy.dataFieldsFor(healthyKey)); got != 1 {
		t.Fatalf("healthy namespace's node got %d put(s), want 1: the broken namespace aborted the round", got)
	}

	if !strings.Contains(stderr.String(), "aaa-broken") {
		t.Errorf("stderr %q does not report the broken namespace", stderr.String())
	}
	// One namespace-level report for the broken namespace plus one node
	// report for the healthy node: the summary must count both.
	if !strings.Contains(stderr.String(), "1 of 2 node(s) failed") {
		t.Errorf("stderr %q does not contain the end-of-round summary", stderr.String())
	}
}

// TestRunPublish_NothingToPublishMessage pins the --once message for a
// round that had zero nodes to attempt: an operator running publish
// against an empty tree must see that it was a no-op, not silence.
func TestRunPublish_NothingToPublishMessage(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, _, _ := setupPublishTestNamespace(t, []string{srv.URL})
	stdout := env.Stdout.(interface{ String() string })

	code := runPublish(env, []string{"--once"})
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout.String(), "nothing to publish") {
		t.Errorf("stdout %q does not say nothing to publish", stdout.String())
	}
}

// TestRunPublish_WithoutOnceRunsUntilSignaled exercises the real
// process entry point for the republish loop (runPublishLoop's
// signal.NotifyContext wiring), not just runRepublishLoop's pure
// logic (see republish_loop_test.go for that). It delivers SIGTERM to
// this same process, the way systemd stops a running
// `stunmesh-provd publish` service, and checks the loop returns ExitOK
// instead of hanging or exiting with an error code.
func TestRunPublish_WithoutOnceRunsUntilSignaled(t *testing.T) {
	root := t.TempDir()
	env, _, _ := newTestEnv(root)
	if code := runInit(env, nil); code != ExitOK {
		t.Fatalf("runInit: code=%d", code)
	}

	// Deterministic handshake: the loop's first env.Sleep call happens
	// strictly after runPublishLoop's signal.NotifyContext registration,
	// so blocking on sleeping before signaling guarantees the handler is
	// installed when SIGTERM arrives. A wall-clock sleep here would
	// race: SIGTERM delivered before registration takes the default
	// disposition and kills the whole test binary.
	sleeping := make(chan struct{})
	var once sync.Once
	env.Sleep = func(ctx context.Context, d time.Duration) error {
		once.Do(func() { close(sleeping) })
		<-ctx.Done()
		return ctx.Err()
	}

	done := make(chan int, 1)
	go func() { done <- runPublish(env, nil) }()

	select {
	case <-sleeping:
	case <-time.After(5 * time.Second):
		t.Fatal("republish loop never reached its first Sleep call")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	select {
	case code := <-done:
		if code != ExitOK {
			t.Fatalf("code = %d, want %d (clean shutdown)", code, ExitOK)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runPublish(nil) did not stop after SIGTERM")
	}
}

func TestRunPublish_NoSecretInOutput(t *testing.T) {
	proxy := newCapturingProxy()
	srv := proxy.server()
	defer srv.Close()

	env, namespace, _ := setupPublishTestNamespace(t, []string{srv.URL})
	nodePriv := addPublishTestNode(t, env, namespace, "alpha")

	stdout := env.Stdout.(interface{ String() string })
	stderr := env.Stderr.(interface{ String() string })

	code := runPublish(env, []string{"--once"})
	if code != ExitOK {
		t.Fatalf("code = %d, stderr=%q", code, stderr.String())
	}

	controllerKeyPath := filepath.Join(env.Dir, namespace, "controller.key")
	controllerKeyBytes, err := os.ReadFile(controllerKeyPath)
	if err != nil {
		t.Fatalf("read controller.key: %v", err)
	}

	for _, secret := range []string{nodePriv.String(), strings.TrimSpace(string(controllerKeyBytes))} {
		if strings.Contains(stdout.String(), secret) {
			t.Fatalf("stdout contains secret key material")
		}
		if strings.Contains(stderr.String(), secret) {
			t.Fatalf("stderr contains secret key material")
		}
	}
}
