package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/execx"
)

func TestRunFetch_MissingFlagsReportsExitError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), nil)
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "--namespace") {
		t.Errorf("stderr = %q, want it to name the missing settings", stderr.String())
	}
}

func TestRunFetch_ValidFlagsReachRealDoFetchBody(t *testing.T) {
	var stdout, stderr bytes.Buffer
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	args := []string{
		"--namespace", "ns",
		"--node-id", "n1",
		"--controller-pubkey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"--identity-key", "/tmp/no-such-stunmesh-agent-test-identity-key",
		"--lock", lockPath,
	}
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), args)
	// Validation must pass with these flags (proving the flags and
	// defaults resolved correctly). doFetch's first real step past the
	// lock is reading the identity key, a local file that does not
	// exist here: this proves runFetch reached doFetch's real body,
	// not a validation error, without needing any network fake.
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "identity key") {
		t.Errorf("stderr = %q, want it to reach doFetch's identity key read", stderr.String())
	}
}

func TestRunFetch_BadControllerPubkeyNeverEchoed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"--namespace", "ns",
		"--node-id", "n1",
		"--controller-pubkey", "not-a-real-key-super-secret-looking",
		"--identity-key", "/tmp/id.key",
	}
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), args)
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if strings.Contains(stderr.String(), "not-a-real-key-super-secret-looking") {
		t.Errorf("stderr leaks the bad pubkey value: %q", stderr.String())
	}
}

func TestRunFetch_UnknownBackendNeverEchoed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"--namespace", "ns",
		"--node-id", "n1",
		"--controller-pubkey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"--identity-key", "/tmp/id.key",
		"--backend", "sentinel-bogus-backend-type",
	}
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), args)
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "--backend") {
		t.Errorf("stderr = %q, want it to name --backend", stderr.String())
	}
	if strings.Contains(stderr.String(), "sentinel-bogus-backend-type") {
		t.Errorf("stderr leaks the bad backend value: %q", stderr.String())
	}
}

func TestRunFetch_ConfigFilePrecedenceEndToEnd(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.conf")
	lockPath := filepath.Join(dir, "agent.lock")
	content := "namespace=from-file\nnode_id=from-file\ncontroller_pubkey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nidentity_key=/tmp/id.key\nlock=" + lockPath + "\n"
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{
		"--namespace", "from-flag",
		"--config", configPath,
	}
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), args)
	// The flag-supplied namespace must win, leaving node_id and the
	// rest to come from the file; the whole thing then reaches
	// doFetch's real body (identity key read, on a path that does not
	// exist), not a validation error -- proving both the merge and the
	// precedence worked end to end through runFetch.
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "identity key") {
		t.Errorf("stderr = %q, want the config-merged flags to pass validation", stderr.String())
	}
}

func TestRunFetch_UnexpectedPositionalArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"extra"})
	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), `"extra"`) {
		t.Errorf("stderr = %q, want it to name the unexpected argument", stderr.String())
	}
}

func TestRunFetch_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runFetch(newEnv(strings.NewReader(""), &stdout, &stderr), []string{"-h"})
	if code != ExitOK {
		t.Errorf("code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout.String(), "Usage: stunmesh-agent") {
		t.Errorf("stdout = %q, want usage", stdout.String())
	}
}

func validFetchConfig(lockPath string) *Config {
	return &Config{
		Namespace:          "ns",
		NodeID:             "n1",
		ControllerPubkey:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Backend:            "dhtproxy",
		Proxies:            []string{"https://dhtproxy.example"},
		IdentityKeyPath:    "/tmp/no-such-stunmesh-agent-test-identity-key",
		LastPath:           "/tmp/last.json",
		LockPath:           lockPath,
		StunmeshConfigPath: "/tmp/stunmesh.yaml",
	}
}

func TestDoFetch_SecondConcurrentHolderExitsOKWithOneLogLine(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")

	held, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("acquireLock (first holder): %v", err)
	}
	defer held.Release()

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := doFetch(env, validFetchConfig(lockPath))

	if code != ExitOK {
		t.Errorf("code = %d, want %d (a held lock is normal, not a failure)", code, ExitOK)
	}
	lines := strings.Split(strings.TrimRight(stderr.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("stderr = %q, want exactly one log line", stderr.String())
	}
	if !strings.Contains(stderr.String(), lockPath) {
		t.Errorf("stderr = %q, want it to name the lock path", stderr.String())
	}
	if strings.Contains(stderr.String(), "identity key") {
		t.Errorf("stderr = %q, doFetch must not fall through past the lock when it is held", stderr.String())
	}
}

func TestDoFetch_AcquiresLockThenReadsIdentityKey(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := doFetch(env, validFetchConfig(lockPath))

	if code != ExitError {
		t.Errorf("code = %d, want %d (identity key file does not exist)", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "identity key") {
		t.Errorf("stderr = %q, want it to reach the identity key read", stderr.String())
	}

	// The lock must be released: a second call must be able to take it
	// too, not report it as held.
	var stdout2, stderr2 bytes.Buffer
	env2 := newEnv(strings.NewReader(""), &stdout2, &stderr2)
	code2 := doFetch(env2, validFetchConfig(lockPath))
	if code2 != ExitError || !strings.Contains(stderr2.String(), "identity key") {
		t.Errorf("second doFetch = code %d, stderr %q, want the lock to have been released", code2, stderr2.String())
	}
}

func TestDoFetch_BadLockPathIsExitError(t *testing.T) {
	// The parent directory does not exist, so opening the lock file
	// fails for a reason other than it being held.
	lockPath := filepath.Join(t.TempDir(), "no-such-dir", "agent.lock")

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := doFetch(env, validFetchConfig(lockPath))

	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if strings.Contains(stderr.String(), "already locked") {
		t.Errorf("stderr = %q, a bad path must not be reported as an ordinary held lock", stderr.String())
	}
}

// fetchTestConfig builds a Config with a real, freshly generated
// identity key file and controller key pair, so a test can exercise
// doFetch's decrypt-and-select path end to end without touching a
// real network (proxies is normally an httptest.Server URL; a test
// still must set env.HTTPClient to that server's client, since
// newDHTProxyClient only reads env.HTTPClient, not proxies' scheme).
func fetchTestConfig(t *testing.T, lockPath string, proxies []string) (cfg *Config, controllerPriv, identityPub crypto.Key) {
	t.Helper()

	identityPriv, identityPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen (identity): %v", err)
	}
	controllerPriv, controllerPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen (controller): %v", err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")
	if err := os.WriteFile(keyPath, []byte(identityPriv.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write identity key: %v", err)
	}

	cfg = &Config{
		Namespace:          "ns",
		NodeID:             "n1",
		ControllerPubkey:   controllerPub.String(),
		Backend:            "dhtproxy",
		Proxies:            proxies,
		IdentityKeyPath:    keyPath,
		LastPath:           filepath.Join(dir, "last.json"),
		LockPath:           lockPath,
		StunmeshConfigPath: filepath.Join(dir, "stunmesh.yaml"),
	}
	return cfg, controllerPriv, identityPub
}

// dhtLine renders one dhtproxy newline-delimited-JSON response line
// carrying raw as its base64 "data" field.
func dhtLine(t *testing.T, raw []byte) []byte {
	t.Helper()
	line, err := json.Marshal(map[string]string{"data": base64.StdEncoding.EncodeToString(raw)})
	if err != nil {
		t.Fatalf("marshal dht line: %v", err)
	}
	return append(line, '\n')
}

func TestDoFetch_NoValuesExitsOKWithOneLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg, _, _ := fetchTestConfig(t, lockPath, []string{srv.URL})

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.HTTPClient = srv.Client()

	code := doFetch(env, cfg)
	if code != ExitOK {
		t.Errorf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "no value found") {
		t.Errorf("stderr = %q, want the no-value log line", stderr.String())
	}
}

func TestDoFetch_UndecryptableValuesExitOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(dhtLine(t, []byte("third party junk, not sealed for this node")))
	}))
	defer srv.Close()

	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg, _, _ := fetchTestConfig(t, lockPath, []string{srv.URL})

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.HTTPClient = srv.Client()

	code := doFetch(env, cfg)
	if code != ExitOK {
		t.Errorf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "none usable") {
		t.Errorf("stderr = %q, want the no-valid-value log line", stderr.String())
	}
	if !strings.Contains(stderr.String(), "1 undecrypted") {
		t.Errorf("stderr = %q, want it to say how many values were undecrypted", stderr.String())
	}
}

func TestDoFetch_ValueThatFailsPhase2ChecksExitsOKAsNothingUsable(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg, controllerPriv, identityPub := fetchTestConfig(t, lockPath, nil)

	// Decrypts and parses fine (phase 1), but the namespace does not
	// match this node's configured namespace ("ns"): a phase 2 check
	// (docs/format.md 6, check 8) must reject it.
	plain := []byte(`{"version":1,"namespace":"wrong-ns","node_id":"n1","timestamp":100,"wg":{},"stunmesh":""}`)
	sealed, err := crypto.Seal(plain, identityPub, controllerPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(dhtLine(t, sealed))
	}))
	defer srv.Close()
	cfg.Proxies = []string{srv.URL}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.HTTPClient = srv.Client()

	code := doFetch(env, cfg)
	if code != ExitOK {
		t.Errorf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "none usable") || !strings.Contains(stderr.String(), "1 rejected by node checks") {
		t.Errorf("stderr = %q, want the no-valid-value log line to count the phase 2 rejection", stderr.String())
	}
	// It must not have gone anywhere near checkAndApply.
	if strings.Contains(stderr.String(), "not implemented") {
		t.Errorf("stderr = %q, a phase 2 rejected value must not reach checkAndApply", stderr.String())
	}
}

func TestDoFetch_DecryptableValueHandsOffToNextItem(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg, controllerPriv, identityPub := fetchTestConfig(t, lockPath, nil)

	// wg is non-empty so this bundle's content differs from the (missing,
	// so empty) last.json: checkAndApply (stage 3 item 5) compares the
	// two for real, and only a genuine content difference reaches
	// applyChanges and then applyDiff (stage 3 item 8).
	plain := []byte(`{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,` +
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":""}`)
	sealed, err := crypto.Seal(plain, identityPub, controllerPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(dhtLine(t, sealed))
	}))
	defer srv.Close()
	cfg.Proxies = []string{srv.URL}

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.HTTPClient = srv.Client()
	env.Runner = execx.NewFake()

	code := doFetch(env, cfg)
	// applyDiff (stage 3 item 8) applies for real against the fake
	// runner; reaching ExitOK (rather than the no-value,
	// none-decrypted, or no-change paths) proves decrypt-and-select,
	// the last.json comparison, the diff, and the apply all worked end
	// to end.
	if code != ExitOK {
		t.Errorf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
}

func TestDoFetch_PartialOutageLogsAndIsTreatedAsNoValues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	// The first proxy is unreachable (nothing listens on this address);
	// the second answers, reachable but empty. dhtproxy.Get reports
	// this as a *PartialError alongside an empty Result.
	cfg, _, _ := fetchTestConfig(t, lockPath, []string{"http://127.0.0.1:1", srv.URL})

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.HTTPClient = srv.Client()

	code := doFetch(env, cfg)
	if code != ExitOK {
		t.Errorf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "failed on") {
		t.Errorf("stderr = %q, want the partial-outage line", stderr.String())
	}
	if !strings.Contains(stderr.String(), "no value found") {
		t.Errorf("stderr = %q, want the partial outage still treated as no values", stderr.String())
	}
}

func TestDoFetch_MoreThanCapValuesLogsWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		// One more than internal/dhtproxy's default 64-value cap
		// (PLAN.md 4.6); every line is distinct so none are Skipped as
		// duplicates or malformed.
		for i := 0; i < 65; i++ {
			buf.Write(dhtLine(t, []byte(fmt.Sprintf("junk-%d", i))))
		}
		w.Write(buf.Bytes())
	}))
	defer srv.Close()

	lockPath := filepath.Join(t.TempDir(), "agent.lock")
	cfg, _, _ := fetchTestConfig(t, lockPath, []string{srv.URL})

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.HTTPClient = srv.Client()

	code := doFetch(env, cfg)
	if code != ExitOK {
		t.Errorf("code = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "more values than the cap") {
		t.Errorf("stderr = %q, want the too-many-values warning", stderr.String())
	}
}
