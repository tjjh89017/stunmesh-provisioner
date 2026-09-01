package main

import (
	"fmt"
	"io"
)

// Exit codes for stunmesh-agent. Keep this list the single source of
// truth; document any addition here.
//
//	0  ExitOK        fetch applied a change, fetch found nothing to
//	                 do, or keygen ran to completion.
//	1  ExitError     the command tried and failed: a bad flag, an
//	                 unknown command, a missing or malformed setting,
//	                 or a real failure while doing the work (I/O
//	                 error, DHT get failed, decryption failed, a
//	                 later item's checks rejected the bundle).
//	3  ExitNoChange  fetch decrypted a valid, newest bundle whose
//	                 content is identical to last.json. Nothing was
//	                 applied.
//
// stunmesh-agent has no separate "usage" code: a bad flag is a kind
// of failure to run the command, the same as any other, so it is
// ExitError like the rest (PLAN.md's stage 3 item 10 lists only these
// three codes).
const (
	ExitOK = iota
	ExitError
	_ // 2 is not used; kept out of the iota sequence intentionally
	ExitNoChange
)

// commandFunc is the signature every subcommand implements. It reads
// its own flags from args and reports its outcome through the
// returned exit code.
type commandFunc func(env *Env, args []string) int

// commands maps a subcommand name to its handler.
var commands = map[string]commandFunc{
	"fetch":  runFetch,
	"keygen": runKeygen,
}

// usage is the full help text, shared by -h/--help and by every usage
// error so the two never drift apart. It also states the precedence
// rule between a flag and the same setting in --config: see
// resolveConfig's doc comment in config.go for the reasoning.
var usage = `Usage: stunmesh-agent <command> [flags]

Commands:
  fetch     fetch, decrypt, check, and apply the newest config bundle
  keygen    generate a node identity key pair

Flags (fetch and keygen accept the same set; each requires only some
of them -- see below):
  --namespace <ns>            deployment namespace
  --node-id <id>               this node's ID
  --controller-pubkey <key>    controller public key, base64
  --backend <type>              storage backend (default ` + defaultBackend + `; the only type today)
  --proxy <url>                 dhtproxy base URL (repeatable; default: ` + defaultProxiesText + `)
  --identity-key <file>         node identity private key file
  --last <file>                 last-applied bundle file (default ` + defaultLastPath + `)
  --lock <file>                 lock file (default ` + defaultLockPath + `)
  --stunmesh-config <file>      stunmesh-go config file (default ` + defaultStunmeshConfigPath + `)
  --full-apply                  fetch only: skip the "no change" shortcut and
                                 rewrite every apply step even when nothing
                                 changed since last.json (PLAN.md 6)
  --config <file>               flat key=value file supplying any of the
                                 settings above (see docs for the file's
                                 grammar)

  -h, --help    print this usage and exit
  --version     print the version and exit

Precedence between a flag and --config: an explicit flag always wins.
A setting that neither a flag nor --config supplies falls back to its
default above, or, for --proxy, to the built-in list above. The
init.d script on OpenWrt reads UCI and always passes flags; --config
is for other systems that keep settings in a file instead.

fetch requires --namespace, --node-id, --controller-pubkey, and
--identity-key (directly or through --config). At least one --proxy
is always available, from a flag, --config, or the built-in default.

keygen requires --identity-key (directly or through --config). It
does not read or need any other setting.

stunmesh-agent never reads UCI. It reads settings only from flags and
--config.
`

// Run is the real entry point. main forwards os.Args, os.Stdin,
// os.Stdout, and os.Stderr to it and does nothing else. Run parses no
// global state and calls os.Exit nowhere, so it is fully testable
// with fake args and buffers.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitError
	}

	switch args[0] {
	case "-h", "--help":
		fmt.Fprint(stdout, usage)
		return ExitOK
	case "--version":
		fmt.Fprintf(stdout, "stunmesh-agent %s\n", version)
		return ExitOK
	}

	name := args[0]
	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(stderr, "stunmesh-agent: unknown command %q\n\n", name)
		fmt.Fprint(stderr, usage)
		return ExitError
	}

	env := newEnv(stdin, stdout, stderr)
	return cmd(env, args[1:])
}
