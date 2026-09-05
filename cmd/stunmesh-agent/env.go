package main

import (
	"io"
	"net/http"

	stunmeshapp "github.com/tjjh89017/stunmesh-go/app"
	"github.com/tjjh89017/stunmesh-provisioner/internal/execx"
)

// Env carries the dependencies a subcommand needs. It replaces direct
// access to os.Stdin, os.Stdout, and os.Stderr, so tests can supply
// buffers instead of the real process streams.
//
// HTTPClient is the seam fetch uses to reach the dhtproxy proxies. A
// nil HTTPClient (the default for a real run, see newEnv) tells fetch
// to let internal/dhtproxy build its own client, with fetch's own
// per-request timeout (see fetchProxyTimeout in fetch.go). A test
// sets HTTPClient to point every proxy request at an httptest.Server
// instead of a real Jami instance.
//
// Runner is the seam the apply step (fetch_apply.go) uses for every
// uci and ubus call. A nil Runner (the default for a real run, see
// newEnv and runnerFor) tells the apply step to use execx.Exec, the
// real command runner. A test sets Runner to an *execx.Fake, so it
// never touches the real system and can assert the exact command
// sequence the apply step ran.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	HTTPClient *http.Client
	Runner     execx.Runner

	// NewApp is the seam for building the embedded stunmesh-go app
	// (embedded.go, daemon.go). A nil NewApp (the default for a real
	// run) tells the daemon and --oneshot/--stunmesh-only modes to use
	// newEmbeddedApp, the real app.New. A test sets NewApp to return a
	// fake embeddedApp instead of wiring a real stunmesh-go config.
	NewApp func(stunmeshapp.Options) (embeddedApp, error)
}

// newEnv builds the Env for a real run.
func newEnv(stdin io.Reader, stdout, stderr io.Writer) *Env {
	return &Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	}
}
