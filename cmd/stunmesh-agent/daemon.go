package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/signal"
	"syscall"
	"time"

	stunmeshapp "github.com/tjjh89017/stunmesh-go/app"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// appFactory builds an embeddedApp from stunmeshapp.Options; it is
// appFactoryFor(env)'s return type, threaded through runAgent's
// helpers instead of env itself so those helpers do not need env for
// anything but this and Stderr.
type appFactory = func(stunmeshapp.Options) (embeddedApp, error)

// oneshotStunmeshTimeout bounds the embedded stunmesh-go app's
// RunOneshot call in --oneshot mode (both the normal daemon's
// --oneshot and --stunmesh-only --oneshot): RunOneshot "runs the
// daemon's publish/establish cycle three times" (stunmesh-go's own
// doc comment), which involves STUN and WireGuard handshakes over the
// network, so it is given more room than fetchTimeout.
const oneshotStunmeshTimeout = 2 * time.Minute

// runAgent is the default command: no subcommand at all (keygen is
// the only subcommand, and Run dispatches it before runAgent is ever
// called). It parses the flags every non-keygen invocation accepts
// and dispatches to the daemon (default), --oneshot's single
// full-apply cycle, or --stunmesh-only's embedded-app-alone mode.
func runAgent(env *Env, args []string, version string) int {
	fs := flag.NewFlagSet("stunmesh-agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var configFile string
	fs.StringVar(&configFile, "config", "", "exact config.yaml file to read (takes priority over --config-dir)")
	fs.StringVar(&configFile, "c", "", "shorthand for --config")
	configDir := fs.String("config-dir", defaultConfigDir, "directory searched for config.yaml or config.yml")
	oneshot := fs.Bool("oneshot", false, "run one full apply cycle, then exit (always a full apply, ignoring last.json's diff)")
	stunmeshOnly := fs.Bool("stunmesh-only", false, "skip the agent loop entirely; run only the embedded stunmesh-go app")
	showVersion := fs.Bool("version", false, "print the version and exit")

	if err := fs.Parse(args); err != nil {
		return handleFlagError(env, fs, err)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: unexpected argument %q\n", fs.Arg(0))
		return ExitError
	}
	if *showVersion {
		fmt.Fprintf(env.Stdout, "stunmesh-agent %s\n", version)
		return ExitOK
	}

	if *stunmeshOnly {
		return runStunmeshOnly(env, configFile, *configDir, *oneshot)
	}

	cfgPath, err := findConfigFile(configFile, *configDir)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: %v\n", err)
		return ExitError
	}
	if cfgPath == "" {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: no config.yaml (or config.yml) found in %s, and --config was not given; not provisioned yet\n", *configDir)
		return ExitError
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: %v\n", err)
		return ExitError
	}

	if *oneshot {
		return runOneshot(env, cfg)
	}
	return runDaemon(env, cfg)
}

// runOneshot runs exactly one fetch/apply cycle, always a full apply
// (forceAll=true: --oneshot has no "no change" shortcut and no exit
// code for it -- see cli.go's ExitOK/ExitError doc comment), and then,
// if that cycle touched the stunmesh text or any interface, runs the
// embedded stunmesh-go app's own RunOneshot cycle once before exiting.
// A run that decrypts nothing usable, or applies nothing new (a
// timing coincidence a "full apply" can still surface, e.g. the
// stunmesh text simply carries no interface content) is not a
// failure: it still exits ExitOK.
func runOneshot(env *Env, cfg *Config) int {
	lock, err := acquireLock(cfg.LockPath)
	if err != nil {
		if errors.Is(err, errLockHeld) {
			fmt.Fprintf(env.Stderr, "stunmesh-agent: %s: already locked by another instance, exiting\n", cfg.LockPath)
			return ExitOK
		}
		fmt.Fprintf(env.Stderr, "stunmesh-agent: %v\n", err)
		return ExitError
	}
	defer func() { _ = lock.Release() }()

	outcome, err := runFetchApply(env, cfg, true)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: %v\n", err)
		return ExitError
	}

	if outcome.Applied && needsEmbeddedRun(outcome.Diff) {
		factory := appFactoryFor(env)
		a, err := factory(cfg.Stunmesh.AppOptions)
		if err != nil {
			fmt.Fprintf(env.Stderr, "stunmesh-agent: embedded stunmesh-go: %v\n", err)
			return ExitError
		}
		defer a.Close()

		ctx, cancel := context.WithTimeout(context.Background(), oneshotStunmeshTimeout)
		defer cancel()
		if err := a.RunOneshot(ctx); err != nil {
			fmt.Fprintf(env.Stderr, "stunmesh-agent: embedded stunmesh-go: %v\n", err)
			return ExitError
		}
	}

	return ExitOK
}

// needsEmbeddedRun reports whether diff (a completed apply's Diff)
// means the embedded stunmesh-go app has something new to publish or
// establish: the stunmesh text itself changed, or any interface did
// (its endpoint or keys may be what stunmesh-go publishes/monitors).
// diff.Stunmesh == StunmeshEmpty means "no stunmesh config at all" --
// there is nothing to run the embedded app against, regardless of
// interface changes.
func needsEmbeddedRun(diff *Diff) bool {
	if diff == nil || diff.Stunmesh == StunmeshEmpty {
		return false
	}
	return diff.Stunmesh == StunmeshChanged || anyInterfaceChanged(diff)
}

// runDaemon is the default command: hold cfg.LockPath for the whole
// process lifetime (the daemon's multi-instance guard, replacing the
// old per-fetch lock now that there is no cron driving repeated
// short-lived runs), run one fetch/apply cycle immediately, then tick
// on cfg.RefreshInterval (a normal cycle) and, when
// cfg.FullApplyInterval is positive, on that interval too (a
// forceAll cycle). SIGINT and SIGTERM are the only signals handled:
// both mean a graceful shutdown (cancel the context, stop the
// embedded app, release the lock, exit 0). There is no SIGHUP reload:
// changing a running daemon's settings means restarting it (systemd
// or procd both already know how to do that), not signalling it --
// the daemon's own startup already does "reread config.yaml, run one
// cycle immediately", so a restart is exactly the reload an operator
// wants.
func runDaemon(env *Env, cfg *Config) int {
	lock, err := acquireLock(cfg.LockPath)
	if err != nil {
		if errors.Is(err, errLockHeld) {
			fmt.Fprintf(env.Stderr, "stunmesh-agent: %s: already locked by another instance, exiting\n", cfg.LockPath)
			return ExitOK
		}
		fmt.Fprintf(env.Stderr, "stunmesh-agent: %v\n", err)
		return ExitError
	}
	defer func() { _ = lock.Release() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	factory := appFactoryFor(env)
	var embedded *embeddedRunner
	defer func() {
		if embedded != nil {
			embedded.stop()
		}
	}()

	runCycle := func(forceAll bool, forceEmbeddedCheck bool) {
		outcome, err := runFetchApply(env, cfg, forceAll)
		if err != nil {
			// A single cycle's failure is logged and the loop keeps
			// running: only a broken config.yaml (already fatal, at
			// startup, before runDaemon is ever called) stops the
			// daemon outright.
			fmt.Fprintf(env.Stderr, "stunmesh-agent: %v\n", err)
			return
		}
		embedded = reconcileEmbedded(env, factory, cfg, embedded, outcome.Diff, forceEmbeddedCheck)
	}

	// The first cycle always checks the embedded app even if this run
	// applies nothing new: a restarted daemon (a config.yaml edit, a
	// crash, an upgrade) must resume running stunmesh-go against
	// whatever last.json already recorded, not wait for the next real
	// bundle change.
	runCycle(false, true)

	refresh := time.NewTicker(cfg.RefreshInterval)
	defer refresh.Stop()

	var fullApplyC <-chan time.Time
	if cfg.FullApplyInterval > 0 {
		fullApply := time.NewTicker(cfg.FullApplyInterval)
		defer fullApply.Stop()
		fullApplyC = fullApply.C
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(env.Stderr, "stunmesh-agent: shutting down")
			return ExitOK
		case <-refresh.C:
			runCycle(false, false)
		case <-fullApplyC:
			runCycle(true, false)
		}
	}
}

// runStunmeshOnly skips the whole agent loop (no fetch, no DHT, no
// UCI) and runs only the embedded stunmesh-go app, built from
// config.yaml's "stunmesh" section (or, when config.yaml does not
// exist at all, the built-in defaults -- config.yaml is optional in
// this mode, see findConfigFile). --oneshot runs the app's
// RunOneshot cycle once and exits; otherwise it runs Run(ctx) until
// SIGINT/SIGTERM.
func runStunmeshOnly(env *Env, configFile, configDir string, oneshot bool) int {
	cfgPath, err := findConfigFile(configFile, configDir)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: %v\n", err)
		return ExitError
	}

	stunmeshCfg, err := loadStunmeshOnlyConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: %v\n", err)
		return ExitError
	}

	factory := appFactoryFor(env)
	a, err := factory(stunmeshCfg.AppOptions)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: embedded stunmesh-go: %v\n", err)
		return ExitError
	}
	defer a.Close()

	if oneshot {
		ctx, cancel := context.WithTimeout(context.Background(), oneshotStunmeshTimeout)
		defer cancel()
		if err := a.RunOneshot(ctx); err != nil {
			fmt.Fprintf(env.Stderr, "stunmesh-agent: embedded stunmesh-go: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: embedded stunmesh-go: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// embeddedRunner is one running instance of the embedded stunmesh-go
// app, plus what stop needs to shut it down cleanly: cancel stops its
// Run(ctx) goroutine, and done is closed once that goroutine has
// actually returned, so stop never calls app.Close while Run might
// still be using the app's own resources (the vendored app.App's doc
// comment: Close "releases resources acquired by New").
type embeddedRunner struct {
	app    embeddedApp
	cancel context.CancelFunc
	done   chan struct{}
}

// startEmbedded builds a new embedded app with factory and opts, and
// runs it in its own goroutine until stop is called or it exits on
// its own. An error from Run (other than context cancellation, the
// normal way stop ends it) is logged to stderr; startEmbedded itself
// only reports an error from factory (app.New), before anything is
// running yet.
func startEmbedded(factory appFactory, opts stunmeshapp.Options, stderr io.Writer) (*embeddedRunner, error) {
	a, err := factory(opts)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := a.Run(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(stderr, "stunmesh-agent: embedded stunmesh-go: %v\n", err)
		}
	}()

	return &embeddedRunner{app: a, cancel: cancel, done: done}, nil
}

// stop cancels r's Run(ctx), waits for its goroutine to actually
// return, and then calls Close. It is a no-op on a nil r, so a caller
// does not need to guard every call with a nil check.
func (r *embeddedRunner) stop() {
	if r == nil {
		return
	}
	r.cancel()
	<-r.done
	r.app.Close()
}

// reconcileEmbedded decides whether the daemon's currently running
// embedded app (cur, possibly nil) still matches what should be
// running, and rebuilds it when it does not.
//
// checkAlways is set only for the daemon's very first cycle
// (runDaemon): a freshly (re)started daemon must resume running
// stunmesh-go against whatever last.json already recorded, even when
// this cycle's own diff is nil (nothing changed since last.json) or
// reports no interface/stunmesh change -- last.json is the source of
// truth for "should something be running right now", not this one
// cycle's diff.
//
// On every other cycle, reconcileEmbedded only acts when diff itself
// reports a stunmesh or interface change (see needsEmbeddedRun's
// sibling condition below): an unrelated cycle must not tear down and
// restart a perfectly good running app.
//
// Rebuilding always stops the old instance (if any) before starting
// the new one: the two must never run concurrently against the same
// config file.
func reconcileEmbedded(env *Env, factory appFactory, cfg *Config, cur *embeddedRunner, diff *Diff, checkAlways bool) *embeddedRunner {
	act := checkAlways
	if !act && diff != nil {
		act = diff.Stunmesh != StunmeshUnchanged || anyInterfaceChanged(diff)
	}
	if !act {
		return cur
	}

	wantRunning := false
	switch {
	case diff != nil:
		wantRunning = diff.Stunmesh != StunmeshEmpty
	default:
		// No diff this cycle (nothing applied): fall back to
		// last.json's own record, since a previous process run may
		// already have applied the stunmesh text before this daemon
		// (re)started.
		if state, err := last.Read(cfg.LastPath); err == nil {
			wantRunning = state.Stunmesh != ""
		}
	}

	if cur != nil {
		cur.stop()
		cur = nil
	}
	if !wantRunning {
		return nil
	}

	r, err := startEmbedded(factory, cfg.Stunmesh.AppOptions, env.Stderr)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: embedded stunmesh-go: %v\n", err)
		return nil
	}
	fmt.Fprintln(env.Stderr, "stunmesh-agent: embedded stunmesh-go: (re)started")
	return r
}
