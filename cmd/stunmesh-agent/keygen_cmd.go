package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

// runKeygen implements `stunmesh-agent keygen`'s flag parsing and
// validation (stage 3 item 1). It accepts the same flags as fetch
// (registerFlags), merges in --config (resolveConfig), but only
// requires --identity-key (Config.ValidateKeygen): keygen writes one
// file and needs nothing else.
func runKeygen(env *Env, args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Run's usage constant covers -h/--help output.
	seam := registerFlags(fs)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(env.Stdout, usage)
			return ExitOK
		}
		fmt.Fprintf(env.Stderr, "stunmesh-agent: keygen: %v\n\n", err)
		fmt.Fprint(env.Stderr, usage)
		return ExitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: keygen: unexpected argument %q\n\n", fs.Arg(0))
		fmt.Fprint(env.Stderr, usage)
		return ExitError
	}

	cfg, err := resolveConfig(seam)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: keygen: %v\n", err)
		return ExitError
	}

	if err := cfg.ValidateKeygen(); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: keygen: %v\n", err)
		return ExitError
	}

	return doKeygen(env, cfg)
}

// doKeygen is the seam stage 3 item 3 fills in: generate an identity
// key pair, write the private key to cfg.IdentityKeyPath (mode
// 0600), and print the public key. This item stops after flag
// parsing and validation, so doKeygen is a stub: it does no work and
// always reports failure, which is correct until a later item
// replaces this body.
func doKeygen(env *Env, cfg *Config) int {
	_ = cfg
	fmt.Fprintln(env.Stderr, "stunmesh-agent: keygen: not implemented yet")
	return ExitError
}
