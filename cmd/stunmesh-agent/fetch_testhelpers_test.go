package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// runFetchApplyForTest wraps runFetchApply the way runOneshot and the
// daemon loop call and log it (fetch.go, daemon.go), reducing the
// result to a single exit code: ExitOK for a nil error (including
// every "nothing to do" case: no value, nothing usable, no change),
// ExitError otherwise, with the error text written to env.Stderr the
// same way runOneshot writes it.
func runFetchApplyForTest(env *Env, cfg *Config, forceAll bool) int {
	_, err := runFetchApply(env, cfg, forceAll)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// applyDiffForTest wraps applyDiff (fetch_apply.go) and reduces its
// error result to an exit code, for tests that assert on a code.
func applyDiffForTest(env *Env, cfg *Config, diff *Diff, state *last.State) int {
	if err := applyDiff(env, cfg, diff, state); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: apply: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// validFetchConfig builds a syntactically complete Config (every
// field set to something, none of it wired to a real network or a
// real identity key) for a test that only cares about a specific
// early failure (a held lock, a bad lock path) and needs the rest of
// the Config to not be the reason runFetchApply fails.
func validFetchConfig(lockPath string) *Config {
	return &Config{
		Namespace:        "ns",
		NodeID:           "n1",
		ControllerPubkey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Backend:          "dhtproxy",
		Proxies:          []string{"https://dhtproxy.example"},
		IdentityKeyPath:  "/tmp/no-such-stunmesh-agent-test-identity-key",
		LastPath:         "/tmp/last.json",
		LockPath:         lockPath,
		Stunmesh:         StunmeshConfig{WritePath: "/tmp/stunmesh.yaml"},
	}
}

// fetchTestConfig builds a Config with a real, freshly generated
// identity key file and controller key pair, so a test can exercise
// runFetchApply's decrypt-and-select path end to end without touching
// a real network (proxies is normally an httptest.Server URL; a test
// still must set env.HTTPClient to that server's client, since
// newBackend only reads env.HTTPClient, not proxies' scheme).
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
		Namespace:        "ns",
		NodeID:           "n1",
		ControllerPubkey: controllerPub.String(),
		Backend:          "dhtproxy",
		Proxies:          proxies,
		IdentityKeyPath:  keyPath,
		LastPath:         filepath.Join(dir, "last.json"),
		LockPath:         lockPath,
		Stunmesh:         StunmeshConfig{WritePath: filepath.Join(dir, "stunmesh.yaml")},
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

// TestRunOneshot_SecondConcurrentHolderExitsOKWithOneLogLine and its
// two siblings below pin runOneshot's lock handling (daemon.go): the
// caller (runOneshot or runDaemon), not runFetchApply, holds the lock.
func TestRunOneshot_SecondConcurrentHolderExitsOKWithOneLogLine(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")

	held, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("acquireLock (first holder): %v", err)
	}
	defer func() { _ = held.Release() }()

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := runOneshot(env, validFetchConfig(lockPath))

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
		t.Errorf("stderr = %q, runOneshot must not fall through past the lock when it is held", stderr.String())
	}
}

func TestRunOneshot_AcquiresLockThenReadsIdentityKey(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "agent.lock")

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := runOneshot(env, validFetchConfig(lockPath))

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
	code2 := runOneshot(env2, validFetchConfig(lockPath))
	if code2 != ExitError || !strings.Contains(stderr2.String(), "identity key") {
		t.Errorf("second runOneshot = code %d, stderr %q, want the lock to have been released", code2, stderr2.String())
	}
}

func TestRunOneshot_BadLockPathIsExitError(t *testing.T) {
	// The parent directory does not exist, so opening the lock file
	// fails for a reason other than it being held.
	lockPath := filepath.Join(t.TempDir(), "no-such-dir", "agent.lock")

	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	code := runOneshot(env, validFetchConfig(lockPath))

	if code != ExitError {
		t.Errorf("code = %d, want %d", code, ExitError)
	}
	if strings.Contains(stderr.String(), "already locked") {
		t.Errorf("stderr = %q, a bad path must not be reported as an ordinary held lock", stderr.String())
	}
}
