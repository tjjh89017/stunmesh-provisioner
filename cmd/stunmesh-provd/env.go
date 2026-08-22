package main

import (
	"crypto/rand"
	"io"
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
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	Dir string

	Now  func() time.Time
	Rand io.Reader
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
	}
}
