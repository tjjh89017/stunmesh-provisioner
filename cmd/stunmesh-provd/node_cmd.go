package main

import "fmt"

// runNode dispatches `stunmesh-provd node <subcommand>`. "add" is the
// only subcommand v1 defines (PLAN.md 7.4).
func runNode(env *Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, "usage: stunmesh-provd node add <namespace> <node_id>\n")
		return ExitUsage
	}

	switch args[0] {
	case "add":
		return runNodeAdd(env, args[1:])
	default:
		fmt.Fprintf(env.Stderr, "stunmesh-provd: node: unknown subcommand %q\n\n", args[0])
		fmt.Fprint(env.Stderr, "usage: stunmesh-provd node add <namespace> <node_id>\n")
		return ExitUsage
	}
}

// runNodeAdd implements `stunmesh-provd node add <namespace> <node_id>`.
//
// NOT YET IMPLEMENTED. Stage 2 item 3 fills this in: create the node
// directory, write identity.pub from the argument or stdin, write
// template wg.yaml and stunmesh.yaml, and print the node constants
// (PLAN.md 7.4). Use env.Dir for the root and env.Stdin when the
// identity key comes from standard input.
func runNodeAdd(env *Env, args []string) int {
	if len(args) != 2 {
		fmt.Fprint(env.Stderr, "usage: stunmesh-provd node add <namespace> <node_id>\n")
		return ExitUsage
	}

	namespace, nodeID := args[0], args[1]
	fmt.Fprintf(env.Stderr, "stunmesh-provd: node add: not yet implemented (dir=%s namespace=%q node_id=%q)\n", env.Dir, namespace, nodeID)
	return ExitError
}
