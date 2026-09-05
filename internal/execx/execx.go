// Package execx runs external system commands.
//
// stunmesh-agent never calls os/exec directly. Every system change --
// uci, ubus call network reload, ifup, /etc/init.d/firewall -- goes
// through the Runner interface this package defines. A test uses Fake instead
// of Exec, so it never touches the real system and can assert the
// exact sequence of commands the code under test ran (see "Fake" and
// "Exact-sequence assertions" below).
//
// # Secret policy
//
// stunmesh-agent's commands carry WireGuard private keys and
// preshared keys as arguments (for example
// "network.wg0.private_key=..."). A command's stdout or stderr can
// also echo those values back. This package follows one rule: an
// error from Exec.Run never contains an argument value, and never
// contains captured stdout or stderr.
//
// Exec.Run keeps to that rule two ways:
//
//   - It never captures stderr. The child process's stderr is
//     discarded (connected to /dev/null), so there is no stderr text
//     for an error message to leak, ever.
//   - On failure it builds a new error from only the command name and
//     the exit code, both safe to log. It does not wrap or embed the
//     underlying *exec.ExitError or *exec.Error, so a caller cannot
//     recover argument values or output through the error chain
//     (errors.As, a type switch, or otherwise).
//
// Run's returned stdout, on success, is not covered by this rule --
// it is the command's real output, handed to the caller so the
// caller can use it (for example, keygen reads a public key back
// this way). A caller must not log that stdout verbatim if the
// command could have echoed a secret.
package execx

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
)

// Runner runs one external command and returns its standard output.
//
// name is the program to run, for example "uci". args are its
// arguments, unexpanded and unquoted, exactly as a caller would pass
// them to os/exec.Command. Run does not run the command through a
// shell.
//
// Run returns the command's standard output as a string. It returns
// a non-nil error if the command cannot be started or exits with a
// non-zero status. See the package doc "Secret policy" section for
// what an error may and may not contain.
type Runner interface {
	Run(name string, args ...string) (stdout string, err error)
}

// ErrRunFailed is the error Exec.Run wraps every failure in. A
// caller checks errors.Is(err, ErrRunFailed) to tell a run failure
// apart from a programming error, without depending on the message
// text.
var ErrRunFailed = errors.New("execx: run failed")

// Exec is the real Runner. It runs commands with os/exec. The zero
// value is ready to use.
type Exec struct{}

// Run implements Runner. See the package doc for the secret policy
// this method follows.
func (Exec) Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	// cmd.Stderr is left nil on purpose: os/exec then discards the
	// child's stderr instead of capturing it. See the package doc
	// "Secret policy" section.

	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("execx: run %q: exit status %d: %w", name, exitErr.ExitCode(), ErrRunFailed)
		}
		return "", fmt.Errorf("execx: run %q: %w", name, ErrRunFailed)
	}

	return stdout.String(), nil
}
