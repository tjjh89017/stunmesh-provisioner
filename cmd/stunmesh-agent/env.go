package main

import "io"

// Env carries the dependencies a subcommand needs. It replaces direct
// access to os.Stdin, os.Stdout, and os.Stderr, so tests can supply
// buffers instead of the real process streams.
//
// Later stage 3 items extend Env with the seams they need (a clock
// for last.json bookkeeping, a random source for keygen, an
// execx.Runner for uci/ubus/init.d calls). This item adds only the
// three streams every subcommand already needs for its own output.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// newEnv builds the Env for a real run.
func newEnv(stdin io.Reader, stdout, stderr io.Writer) *Env {
	return &Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	}
}
