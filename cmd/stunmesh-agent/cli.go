package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

// Exit codes for stunmesh-agent.
//
//	0  ExitOK     the daemon shut down cleanly (SIGINT/SIGTERM), a
//	               --oneshot run applied the newest bundle (or found
//	               nothing usable to apply -- that is not a failure),
//	               or keygen ran to completion. --oneshot always runs a
//	               full apply, so a run that changes nothing exits 0,
//	               the same as one that does.
//	1  ExitError  a bad flag, a missing or malformed config.yaml, or a
//	               real failure while doing the work (I/O error, DHT
//	               get failed, decryption failed, an apply step
//	               failed).
const (
	ExitOK = iota
	ExitError
)

// Run is the real entry point. main forwards os.Args, os.Stdin,
// os.Stdout, and os.Stderr to it and does nothing else. Run parses no
// global state and calls os.Exit nowhere, so it is fully testable
// with fake args and buffers.
//
// keygen is stunmesh-agent's only subcommand (dispatched here, before
// any other flag parsing); every other invocation -- with or without
// flags -- runs the default command (runAgent): the daemon, or
// --oneshot's single full-apply cycle, or --stunmesh-only's embedded
// stunmesh-go daemon alone. See runAgent's doc comment for that
// command's own flags.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	env := newEnv(stdin, stdout, stderr)

	if len(args) > 0 && args[0] == "keygen" {
		return runKeygen(env, args[1:])
	}

	return runAgent(env, args, version)
}

// handleFlagError is the shared -h/--help and parse-error handling
// for every flag.FlagSet this binary parses (runAgent, runKeygen).
// fs must have been built with flag.ContinueOnError and SetOutput(io.Discard),
// so the flag package's own error/usage text never leaks past this
// function: -h/--help prints fs's usage (flag's own PrintDefaults,
// per this repository's "use flag's built-in --help" convention) to
// stdout and exits 0; any other parse error is a plain ExitError.
func handleFlagError(env *Env, fs *flag.FlagSet, err error) int {
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprintf(env.Stdout, "Usage of %s:\n", fs.Name())
		fs.SetOutput(env.Stdout)
		fs.PrintDefaults()
		return ExitOK
	}
	fmt.Fprintf(env.Stderr, "stunmesh-agent: %s: %v\n", fs.Name(), err)
	return ExitError
}
