package main

import "fmt"

// runInit implements `stunmesh-provd init [<namespace>]`.
//
// NOT YET IMPLEMENTED. Stage 2 item 2 fills this in: write the root
// README.md if absent, create the namespace directory (random name
// when namespace is empty), write provd.yaml, and make the
// controller key pair (PLAN.md 7.3). Use env.Dir for the root, env.Now
// for any timestamp, and env.Rand for the key pair.
func runInit(env *Env, args []string) int {
	if len(args) > 1 {
		fmt.Fprint(env.Stderr, "usage: stunmesh-provd init [<namespace>]\n")
		return ExitUsage
	}

	namespace := ""
	if len(args) == 1 {
		namespace = args[0]
	}

	fmt.Fprintf(env.Stderr, "stunmesh-provd: init: not yet implemented (dir=%s namespace=%q)\n", env.Dir, namespace)
	return ExitError
}
