package main

import (
	"io"
	"net/http"
)

// Env carries the dependencies a subcommand needs. It replaces direct
// access to os.Stdin, os.Stdout, and os.Stderr, so tests can supply
// buffers instead of the real process streams.
//
// HTTPClient is the seam fetch uses to reach the dhtproxy proxies. A
// nil HTTPClient (the default for a real run, see newEnv) tells fetch
// to let internal/dhtproxy build its own client, with fetch's own
// per-request timeout (see fetchProxyTimeout in fetch_cmd.go). A test
// sets HTTPClient to point every proxy request at an httptest.Server
// instead of a real Jami instance.
//
// Later stage 3 items extend Env with further seams they need (a
// clock for last.json bookkeeping, an execx.Runner for uci/ubus/
// init.d calls).
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	HTTPClient *http.Client
}

// newEnv builds the Env for a real run.
func newEnv(stdin io.Reader, stdout, stderr io.Writer) *Env {
	return &Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	}
}
