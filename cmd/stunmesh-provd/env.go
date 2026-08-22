package main

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"time"
)

// Env carries the dependencies a subcommand needs. It replaces direct
// access to os.Stdin, os.Stdout, os.Stderr, the clock, and the random
// source, so tests can supply fakes for all of them.
//
// Dir is the resolved provisioning root, after any --dir override.
// Every subcommand reads and writes through Dir. It never uses the
// default path constant directly.
//
// Now and Rand are seams for later items. Init makes a key pair with
// Rand. Init, node add, and publish stamp timestamps with Now. Fixing
// both in a test makes the output deterministic.
//
// HTTPClient is the seam publish uses to reach the dhtproxy proxies.
// A nil HTTPClient (the default for a real run, see newEnv) tells
// publish to let internal/dhtproxy build its own client. A test sets
// HTTPClient to point every proxy request at an httptest.Server
// instead of a real Jami instance.
//
// Sleep is the seam the republish loop (stage 2 item 8) uses to wait
// between rounds. It blocks until either d elapses or ctx is
// canceled, and returns ctx.Err() in the second case, nil in the
// first. A test replaces Sleep with a fake that returns at once
// instead of waiting, so a multi-round test of the loop takes no
// real wall-clock time; the fake can also advance a fake Now by d
// each call, so per-namespace interval math in the loop is exercised
// without a real clock either.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	Dir string

	Now  func() time.Time
	Rand io.Reader

	HTTPClient *http.Client

	Sleep func(ctx context.Context, d time.Duration) error
}

// newEnv builds the Env for a real run. dir is already resolved.
func newEnv(stdin io.Reader, stdout, stderr io.Writer, dir string) *Env {
	return &Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Dir:    dir,
		Now:    time.Now,
		Rand:   rand.Reader,
		Sleep:  sleepContext,
	}
}

// sleepContext is the real implementation of Env.Sleep: an
// interruptible wait, so the republish loop reacts to shutdown
// (SIGINT/SIGTERM, via the context runPublish builds) at once
// instead of finishing its current wait first.
func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
