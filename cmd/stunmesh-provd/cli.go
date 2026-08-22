package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

// Exit codes for stunmesh-provd. Keep this list the single source of
// truth; document any addition here.
//
//	0  ExitOK     the command did what it was asked to do.
//	1  ExitError  the command tried and failed (I/O error, DHT put
//	              failed, validation rejected a file, and so on).
//	2  ExitUsage  the command line itself was wrong (bad flag, unknown
//	              command, wrong number of arguments). The process ran
//	              no work in this case.
const (
	ExitOK = iota
	ExitError
	ExitUsage
)

// defaultDir is the provisioning root when --dir is not given.
const defaultDir = "/etc/stunmesh/provd"

// commandFunc is the signature every subcommand implements. It reads
// its own flags and positional arguments from args and reports its
// outcome through the returned exit code. Later items replace each
// stub below with real behavior; the signature does not change.
type commandFunc func(env *Env, args []string) int

// commands maps a top-level command name to its handler. "node" is
// itself a small dispatcher for the "add" subcommand.
var commands = map[string]commandFunc{
	"init":    runInit,
	"node":    runNode,
	"publish": runPublish,
}

// usage is the full help text, shared by -h/--help and by every usage
// error so the two never drift apart.
const usage = `Usage: stunmesh-provd [--dir <path>] <command> [<args>]

Commands:
  init [<namespace>]
        create a namespace directory and its controller key pair
  node add <namespace> <node_id> [<identity_pub_key>]
        add a node to a namespace; reads the identity key from
        stdin when the key argument is omitted
  publish [--namespace <ns>] [--once]
        build, encrypt, and put bundles to the DHT; without --once,
        repeats until SIGINT or SIGTERM

Flags:
  --dir <path>  root of the provisioning tree (default ` + defaultDir + `)
  --version     print the version and exit
  -h, --help    print this usage and exit
`

// Run is the real entry point. main forwards os.Args, os.Stdin,
// os.Stdout, and os.Stderr to it and does nothing else. Run parses no
// global state and calls os.Exit nowhere, so it is fully testable
// with fake args and buffers.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	fs := flag.NewFlagSet("stunmesh-provd", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Run prints its own usage, once, below.

	dir := fs.String("dir", defaultDir, "root of the provisioning tree")
	showVersion := fs.Bool("version", false, "print the version and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return ExitOK
		}
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}

	if *showVersion {
		fmt.Fprintf(stdout, "stunmesh-provd %s\n", version)
		return ExitOK
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}

	name := rest[0]
	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(stderr, "stunmesh-provd: unknown command %q\n\n", name)
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}

	env := newEnv(stdin, stdout, stderr, *dir)
	return cmd(env, rest[1:])
}
