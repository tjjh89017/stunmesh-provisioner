package main

import (
	"errors"
	"flag"
	"fmt"
)

const publishUsage = "usage: stunmesh-provd publish [--namespace <ns>] [--once]\n"

// runPublish implements `stunmesh-provd publish [--namespace <ns>] [--once]`.
//
// NOT YET IMPLEMENTED. Stage 2 items 4-6 fill this in: for each
// namespace (or only the given one) and each of its nodes, build the
// bundle, validate it, encrypt it to identity.pub, and put it to
// every proxy in provd.yaml (PLAN.md 7.2). --once runs one round and
// returns; without it, the command loops at the republish_interval
// from provd.yaml, keyed off env.Now.
func runPublish(env *Env, args []string) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() { fmt.Fprint(env.Stderr, publishUsage) }

	namespace := fs.String("namespace", "", "publish only this namespace")
	once := fs.Bool("once", false, "run one publish round and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}

	if fs.NArg() > 0 {
		fmt.Fprint(env.Stderr, publishUsage)
		return ExitUsage
	}

	fmt.Fprintf(env.Stderr, "stunmesh-provd: publish: not yet implemented (dir=%s namespace=%q once=%v)\n", env.Dir, *namespace, *once)
	return ExitError
}
