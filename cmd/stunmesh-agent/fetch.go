package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/backend"
	"github.com/tjjh89017/stunmesh-provisioner/internal/backend/dial"
	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtkey"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtproxy"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// fetchProxyTimeout bounds one HTTP request to one proxy. It is
// passed to dhtproxy.New via WithTimeout when env.HTTPClient is nil
// (a real run); it has no effect when a test supplies its own
// env.HTTPClient (see newBackend). 10s matches internal/dhtproxy's own
// default; it is set explicitly here so this binary's timeout policy
// does not depend on that default staying what it is today.
const fetchProxyTimeout = 10 * time.Second

// fetchTimeout bounds the whole dhtproxy.Client.Get call: every
// configured proxy, tried in order, until one answers with a value
// (internal/dhtproxy's package doc). fetchTimeout is deliberately
// larger than fetchProxyTimeout so the common case (the first proxy
// answers) is never cut short, but it still caps the worst case
// regardless of how many proxies are configured.
const fetchTimeout = 30 * time.Second

// fetchOutcome is what one runFetchApply cycle produced, for the
// caller (the daemon loop, runOneshot) to log and to decide what to
// do with the embedded stunmesh-go app.
type fetchOutcome struct {
	// Applied is true only when applyDiff actually ran a full apply.
	// It is false, with no error, for every "nothing to do" case: no
	// DHT value found, no usable value among what was found, or (when
	// forceAll is false) a newest bundle whose content is identical to
	// last.json. None of these are failures.
	Applied bool
	// Diff is set only when Applied is true. The caller inspects
	// Diff.Stunmesh to decide whether the embedded stunmesh-go app
	// needs to be rebuilt (see manageEmbeddedApp in daemon.go).
	Diff *Diff
}

// runFetchApply runs one full fetch -> decrypt -> validate -> diff ->
// apply cycle (PLAN.md 4-6, docs/format.md sections 4-8), shared by
// the daemon loop and --oneshot. It does not take cfg.LockPath itself:
// the caller (runOneshot, the daemon) holds the lock for its own
// duration (a single cycle for --oneshot, the whole process lifetime
// for the daemon).
//
// forceAll skips the "no change since last.json" shortcut and makes
// computeDiff classify every interface present on both sides as
// changed and every non-empty stunmesh text as changed (see
// computeDiff's doc comment): --oneshot always sets it true (the CLI
// no longer has a "no change" exit code, see cli.go), and the daemon
// sets it true only on its periodic full-apply tick.
//
// A "nothing to do" outcome (no value published yet, no value this
// node's key can use, or no change) is reported as fetchOutcome{} with
// a nil error: it is normal, not a failure the caller should log as
// one. Every other problem -- a bad identity key, a DHT error, a
// failed apply step -- is returned as an error for the caller to log
// and, for the daemon, to retry on the next tick.
func runFetchApply(env *Env, cfg *Config, forceAll bool) (fetchOutcome, error) {
	identityPriv, err := loadIdentityKey(cfg.IdentityKeyPath)
	if err != nil {
		return fetchOutcome{}, err
	}

	// buildConfig already parsed this once; parsing again here is cheap
	// and keeps runFetchApply self-contained for a caller that builds a
	// Config directly (as tests do).
	controllerPub, err := crypto.ParseKey(cfg.ControllerPubkey)
	if err != nil {
		return fetchOutcome{}, errors.New("controller_pubkey: not a valid key")
	}

	key, err := dhtkey.Key(cfg.Namespace, cfg.NodeID)
	if err != nil {
		// dhtkey.Key's error names only "namespace" or "node_id", never
		// the value; safe to return as-is.
		return fetchOutcome{}, err
	}

	proxy, err := newBackend(env, cfg)
	if err != nil {
		return fetchOutcome{}, fmt.Errorf("dht proxy: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	result, err := proxy.Get(ctx, key)
	var partial *dhtproxy.PartialError
	switch {
	case errors.As(err, &partial):
		// Some proxies were unreachable or errored, but at least one
		// that did answer had no value. Treating this as fatal would
		// make a routine, single-proxy blip stop every cycle; silently
		// ignoring it would hide a real partial outage from the
		// operator. runFetchApply logs it and proceeds as if the DHT
		// held nothing for this key.
		fmt.Fprintf(env.Stderr, "stunmesh-agent: %v\n", partial)
	case err != nil:
		return fetchOutcome{}, fmt.Errorf("get: %w", err)
	}

	if result.Dropped > 0 {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: dht returned more values than the cap; ignoring %d extra value(s)\n", result.Dropped)
	}
	if result.Skipped > 0 {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: %d malformed dht line(s) skipped\n", result.Skipped)
	}

	if len(result.Values) == 0 {
		fmt.Fprintln(env.Stderr, "stunmesh-agent: no value found for this node, nothing to do")
		return fetchOutcome{}, nil
	}

	best, stats := decryptAndSelect(result.Values, controllerPub, identityPriv, cfg.Namespace, cfg.NodeID)
	if best == nil {
		// One line, wide enough for an operator to debug without
		// leaking anything private: no bundle content, no key
		// material, no stunmesh text, and no DHT key.
		fmt.Fprintf(env.Stderr,
			"stunmesh-agent: %d value(s) found, none usable (%d undecrypted, %d unparsed, %d rejected by node checks), nothing to do\n",
			len(result.Values), stats.Undecrypted, stats.Unparsed, stats.Rejected)
		return fetchOutcome{}, nil
	}

	return checkAndApply(env, cfg, best, forceAll)
}

// newBackend builds the backend.Store fetch uses, selected by
// cfg.Backend (docs/format.md section 3), through
// internal/backend/dial's one shared construction point (also used by
// cmd/stunmesh-provd).
//
// It prefers env.HTTPClient when a test set one (see Env's doc), so a
// test tree points every proxy call at an httptest.Server instead of
// the real network; a production run leaves it nil and gets
// fetchProxyTimeout as its per-request timeout instead of
// internal/dhtproxy's own default.
func newBackend(env *Env, cfg *Config) (backend.Store, error) {
	return dial.New(backendDialConfig(env, cfg))
}

// backendDialConfig maps env and cfg into the dial.Config newBackend
// passes to dial.New. It is a pure, network-free mapping step, split
// out from newBackend so a test can assert the mapping without
// needing dial.New's own coverage of what each dial.Config field does.
func backendDialConfig(env *Env, cfg *Config) dial.Config {
	return dial.Config{
		Type:       cfg.Backend,
		Proxies:    cfg.Proxies,
		HTTPClient: env.HTTPClient,
		Timeout:    fetchProxyTimeout,
	}
}

// checkAndApply is the seam that reads last.json (PLAN.md 4.5),
// compares it with b's content (unless forceAll), computes the
// per-interface diff (fetch_diff.go), and runs the apply procedure
// (PLAN.md 6, fetch_apply.go). b has already passed every PLAN.md 4.4
// check inside decryptAndSelect, so checkAndApply never needs to call
// bundle.Validate again.
func checkAndApply(env *Env, cfg *Config, b *bundle.Bundle, forceAll bool) (fetchOutcome, error) {
	state, err := last.Read(cfg.LastPath)
	if err != nil {
		return fetchOutcome{}, err
	}

	if !forceAll {
		equal, err := sameContent(state, b)
		if err != nil {
			// sameContent's error comes from bundle.Canonical, which
			// never includes field values in its own errors; safe to
			// return as-is.
			return fetchOutcome{}, fmt.Errorf("compare with last.json: %w", err)
		}
		if equal {
			fmt.Fprintln(env.Stderr, "stunmesh-agent: no change since last apply")
			return fetchOutcome{}, nil
		}
	}

	diff, err := computeDiff(b, state, forceAll)
	if err != nil {
		// computeDiff's only error source is bundle.Bundle.Canonical
		// (via interfaceEqual), which never includes field values in
		// its own errors; safe to return as-is.
		return fetchOutcome{}, fmt.Errorf("diff: %w", err)
	}

	if err := applyDiff(env, cfg, diff, state); err != nil {
		return fetchOutcome{}, fmt.Errorf("apply: %w", err)
	}

	return fetchOutcome{Applied: true, Diff: diff}, nil
}
