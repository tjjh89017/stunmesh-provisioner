package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
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

// doFetch is the seam stage 3 items 2-10 fill in: taking the lock,
// getting and decrypting the DHT values, running the checks of
// PLAN.md 4.4, comparing with last.json, diffing, building and
// applying the UCI batch, and writing last.json.
//
// This item (stage 3 item 2) implements only the lock: acquireLock at
// cfg.LockPath, released on every return path through defer. Another
// instance already holding the lock is normal, not a failure (see
// acquireLock and errLockHeld); doFetch logs one line and returns
// ExitOK. Any other failure to acquire the lock is ExitError.
//
// Past the lock, doFetch is still a stub for the rest of stage 3: it
// does no work and always reports failure, which is correct until a
// later item replaces this body -- there is nothing yet for a caller
// to treat as success.
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

	fmt.Fprintln(env.Stderr, "stunmesh-agent: fetch: not implemented yet")
	return ExitError
}
