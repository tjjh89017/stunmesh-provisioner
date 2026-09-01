package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/backend"
	"github.com/tjjh89017/stunmesh-provisioner/internal/backend/dial"
	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtkey"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtproxy"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// runFetch implements `stunmesh-agent fetch`'s flag parsing and
// validation (stage 3 item 1). It reads the same flags every
// subcommand accepts (registerFlags), merges in --config
// (resolveConfig), and checks that everything `fetch` needs is
// present (Config.ValidateFetch) before handing off to doFetch.
func runFetch(env *Env, args []string) int {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Run's usage constant covers -h/--help output.
	seam := registerFlags(fs)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(env.Stdout, usage)
			return ExitOK
		}
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: %v\n\n", err)
		fmt.Fprint(env.Stderr, usage)
		return ExitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: unexpected argument %q\n\n", fs.Arg(0))
		fmt.Fprint(env.Stderr, usage)
		return ExitError
	}

	cfg, err := resolveConfig(seam)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: %v\n", err)
		return ExitError
	}

	if err := cfg.ValidateFetch(); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: %v\n", err)
		return ExitError
	}

	return doFetch(env, cfg)
}

// fetchProxyTimeout bounds one HTTP request to one proxy. It is
// passed to dhtproxy.New via WithTimeout when env.HTTPClient is nil
// (a real run); it has no effect when a test supplies its own
// env.HTTPClient (see newDHTProxyClient). 10s matches
// internal/dhtproxy's own default; it is set explicitly here so
// fetch's timeout policy does not depend on that default staying what
// it is today.
const fetchProxyTimeout = 10 * time.Second

// fetchTimeout bounds the whole dhtproxy.Client.Get call: every
// configured proxy, tried in order, until one answers with a value
// (internal/dhtproxy's package doc). fetch runs from cron and from a
// WAN hotplug event on a router, holding cfg.LockPath the whole time
// (PLAN.md section 5); without an overall bound, a run of hung
// proxies -- each one eating its own fetchProxyTimeout -- could still
// add up to minutes and block every later fetch behind the lock.
// fetchTimeout is deliberately larger than fetchProxyTimeout so the
// common case (the first proxy answers) is never cut short, but it
// still caps the worst case regardless of how many proxies are
// configured.
const fetchTimeout = 30 * time.Second

// doFetch is the seam stage 3 items 2-10 fill in: taking the lock,
// getting and decrypting the DHT values, running the checks of
// PLAN.md 4.4, comparing with last.json, diffing, building and
// applying the UCI batch, and writing last.json.
//
// Stage 3 item 2 implemented the lock: acquireLock at cfg.LockPath,
// released on every return path through defer. Another instance
// already holding the lock is normal, not a failure (see acquireLock
// and errLockHeld); doFetch logs one line and returns ExitOK. Any
// other failure to acquire the lock is ExitError.
//
// Stage 3 item 4, first half, implemented the rest of "get, decrypt,
// select": read the identity key, get the DHT values through
// internal/dhtproxy, and hand them to decryptAndSelect.
//
// This item (stage 3 item 4, second half) makes decryptAndSelect run
// the full PLAN.md 4.4 check set -- phase 1 (bundle.Parse) and phase
// 2 (bundle.Validate(cfg.Namespace, cfg.NodeID)) -- on every candidate
// before it compares Timestamps (PLAN.md 4.6; see decryptAndSelect's
// doc comment for why checking-before-comparing is the correct
// reading). No value at all, or no value that passes every check:
// doFetch logs one line naming how many values were seen and broadly
// why each one was skipped, and returns ExitOK, changing nothing
// (PLAN.md stage 3 item 4). Once decryptAndSelect returns a bundle,
// that bundle has already passed every PLAN.md 4.4 check, so doFetch
// hands it to checkAndApply, the seam the next item (last.json
// comparison, diff, UCI apply) fills in.
func doFetch(env *Env, cfg *Config) int {
	lock, err := acquireLock(cfg.LockPath)
	if err != nil {
		if errors.Is(err, errLockHeld) {
			fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: %s: already locked by another instance, exiting\n", cfg.LockPath)
			return ExitOK
		}
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: %v\n", err)
		return ExitError
	}
	defer lock.Release()

	// Read the identity key first: it is a local file, cheap to check,
	// and there is no point contacting the network at all if it is
	// missing or malformed.
	identityPriv, err := loadIdentityKey(cfg.IdentityKeyPath)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: %v\n", err)
		return ExitError
	}

	// ValidateFetch (config.go) already parsed this once; parsing again
	// here is cheap and keeps doFetch self-contained for a caller that
	// builds a Config directly (as the tests do) instead of going
	// through runFetch.
	controllerPub, err := crypto.ParseKey(cfg.ControllerPubkey)
	if err != nil {
		fmt.Fprintln(env.Stderr, "stunmesh-agent: fetch: --controller-pubkey: not a valid key")
		return ExitError
	}

	key, err := dhtkey.Key(cfg.Namespace, cfg.NodeID)
	if err != nil {
		// dhtkey.Key's error names only "namespace" or "node_id", never
		// the value (see its doc comment): safe to print as-is.
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: %v\n", err)
		return ExitError
	}

	proxy, err := newBackend(env, cfg)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: dht proxy: %v\n", err)
		return ExitError
	}

	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	result, err := proxy.Get(ctx, key)
	var partial *dhtproxy.PartialError
	switch {
	case errors.As(err, &partial):
		// Some proxies were unreachable or errored, but at least one
		// that did answer had no value (dhtproxy.Get's doc comment).
		// Treating this as fatal would make a routine, single-proxy
		// blip stop every fetch; silently ignoring it would hide a
		// real partial outage from the operator. doFetch logs it as
		// its own line, distinct from the plain "no values" case
		// below, and then proceeds exactly as if the DHT held nothing
		// for this key: a reachable proxy answered "nothing here", and
		// there is no way to tell that apart from "nothing published
		// yet" without asking the unreachable proxies too.
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: %v\n", partial)
	case err != nil:
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: get: %v\n", err)
		return ExitError
	}

	if result.Dropped > 0 {
		// dhtproxy.Get already enforces the PLAN.md 4.6 cap and counted
		// what it dropped; fetch only surfaces that count, it does not
		// count values a second time.
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: dht returned more values than the cap; ignoring %d extra value(s)\n", result.Dropped)
	}
	if result.Skipped > 0 {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: %d malformed dht line(s) skipped\n", result.Skipped)
	}

	if len(result.Values) == 0 {
		fmt.Fprintln(env.Stderr, "stunmesh-agent: fetch: no value found for this node, nothing to do")
		return ExitOK
	}

	best, stats := decryptAndSelect(result.Values, controllerPub, identityPriv, cfg.Namespace, cfg.NodeID)
	if best == nil {
		// One line, wide enough for an operator to debug without
		// leaking anything private: no bundle content, no key
		// material, no stunmesh text, and no DHT key. The three
		// counts say broadly why each value was skipped (did not
		// decrypt with this node's key, decrypted but did not parse
		// as JSON, or parsed but failed a PLAN.md 4.4 phase 2 check
		// such as namespace or node_id) without naming which check or
		// showing any value.
		fmt.Fprintf(env.Stderr,
			"stunmesh-agent: fetch: %d value(s) found, none usable (%d undecrypted, %d unparsed, %d rejected by node checks), nothing to do\n",
			len(result.Values), stats.Undecrypted, stats.Unparsed, stats.Rejected)
		return ExitOK
	}

	return checkAndApply(env, cfg, best)
}

// newBackend builds the backend.Store fetch uses, selected by
// cfg.Backend (docs/format.md section 3), through
// internal/backend/dial's one shared construction point (also used by
// cmd/stunmesh-provd). ValidateFetch already rejects any cfg.Backend
// other than backend.TypeDHTProxy before runFetch ever reaches
// doFetch, so dial.New's default arm below only matters for a caller
// that builds a Config directly and skips ValidateFetch (as some
// tests do): it still returns an error, naming the field and not
// cfg.Backend's value, rather than picking a backend silently or
// panicking.
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
// out from newBackend so a test can assert the mapping (in particular,
// that fetchProxyTimeout -- the one piece of this mapping specific to
// this binary -- is forwarded) without needing dial.New's own
// coverage of what each dial.Config field does.
func backendDialConfig(env *Env, cfg *Config) dial.Config {
	return dial.Config{
		Type:       cfg.Backend,
		Proxies:    cfg.Proxies,
		HTTPClient: env.HTTPClient,
		Timeout:    fetchProxyTimeout,
	}
}

// checkAndApply is the seam stage 3 item 5 onward fills in: the
// last.json comparison (PLAN.md 4.5), the per-interface diff, the UCI
// batch, and the apply (PLAN.md 6). b is the bundle with the largest
// Timestamp among the values that passed every PLAN.md 4.4 check --
// both phase 1 (bundle.Parse) and phase 2
// (bundle.Validate(cfg.Namespace, cfg.NodeID)) already ran inside
// decryptAndSelect, so checkAndApply's caller (doFetch) never reaches
// this seam with an unchecked bundle. checkAndApply itself does not
// need to call Validate again.
//
// This item (stage 3 item 5) implements the last.json comparison: read
// last.json (a missing file reads as empty, PLAN.md 4.5 "Missing
// last.json"), compare its content with b's content (sameContent), and
// exit ExitNoChange, writing nothing, when they are equal. A read
// failure other than "missing" (last.ErrCorrupt) is a hard failure
// (ExitError); see internal/last's package doc "Corrupt or unreadable
// file" for why the agent must not guess at a corrupt last.json's
// content.
//
// When the content differs, checkAndApply hands off to applyChanges,
// the seam the next item (the per-interface diff) fills in.
//
// --full-apply (cfg.FullApply) skips the "equal" shortcut below
// entirely: a periodic full re-apply's whole point is to rewrite
// every step even when the newest bundle's content is byte-for-byte
// what last.json already has. The 24-hour schedule that sets this
// flag lives in the OpenWrt cron integration, not in this binary; see
// Config.FullApply's doc comment.
func checkAndApply(env *Env, cfg *Config, b *bundle.Bundle) int {
	state, err := last.Read(cfg.LastPath)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: %v\n", err)
		return ExitError
	}

	if !cfg.FullApply {
		equal, err := sameContent(state, b)
		if err != nil {
			// sameContent's error comes from bundle.Canonical, which never
			// includes field values in its own errors (see internal/bundle's
			// doc); safe to print as-is.
			fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: compare with last.json: %v\n", err)
			return ExitError
		}
		if equal {
			fmt.Fprintln(env.Stderr, "stunmesh-agent: fetch: no change since last apply")
			return ExitNoChange
		}
	}

	return applyChanges(env, cfg, b, state)
}
