// Package uci builds the UCI batch for one WireGuard interface, the
// delete list for an interface's recorded sections, and the batch
// that manages the shared "stunmesh" firewall zone every managed
// interface joins (see firewall.go).
//
// # Input and output
//
// BuildInterface takes one interface from a bundle.Bundle, already
// decrypted and checked, and returns a Batch: an ordered list of
// Command values. BuildDelete takes the section names last.Sections
// recorded for one interface and returns a Batch that deletes
// exactly those names, never a pattern.
// BuildFirewallZoneCreate, AddFirewallZoneNetwork,
// RemoveFirewallZoneNetwork, and DeleteFirewallZone (firewall.go) are
// the equivalent building blocks for the "stunmesh" firewall zone,
// which -- unlike an interface's own sections -- is one section shared
// by every managed interface, so the caller (cmd/stunmesh-agent's
// manageFirewall) composes these smaller pieces itself rather than
// getting one Batch per apply the way BuildInterface/BuildDelete work.
//
// # Command representation and the golden-file tension
//
// The stage spec asks for two things that pull in different
// directions: tests that compare the batch against golden text files,
// and an apply step that runs each command through
// internal/execx.Runner.Run(name string, args ...string), which never
// goes through a shell and so needs pre-split argument tokens, not a
// text blob it would have to re-split itself.
//
// This package resolves the tension by keeping the token form as the
// only real representation. A Command already holds Args, the exact
// []string a caller passes to Run("uci", cmd.Args...); Batch.Text
// renders that same data as text purely for golden-file comparison in
// this package's own tests. Text is a one-way, display-only
// projection -- nothing in this package or in a later apply step
// parses it back into a Command. Each argument here (a UCI key path,
// a WireGuard key, an address, a hostname) is a single token with no
// internal whitespace, so join-with-space and split-on-space would
// round-trip safely in this data set, but the apply step never
// exercises that path: it walks Batch directly and calls Run with
// each Command's Args, so no such round trip has to be safe in
// general.
//
// # Ordering
//
// A bundle.Interface stores Peers and every *.Options map as a Go
// map, which does not iterate in a stable order. The apply step and
// its integration test assert an exact command sequence, so
// BuildInterface fixes a deterministic order at every point that
// reads from a map:
//
//   - Peers: sorted by peer name, lexicographically (byte-wise
//     strings.Compare order, matching sort.Strings).
//   - Options (interface and peer): sorted by option key, the same
//     way.
//
// Every other input BuildInterface reads is already an ordered Go
// slice (Addresses, Routes, AllowedIPs), so it is emitted in the
// order the bundle gave it, unchanged.
//
// # Endpoint parsing
//
// A peer's Endpoint field is one string, `host:port` with the host
// bracketed for IPv6 (docs/format.md 6, matching net.JoinHostPort's
// own convention). BuildInterface splits it into the UCI
// endpoint_host and endpoint_port options with parseEndpoint; see its
// doc comment for the exact rule, including the case of an endpoint
// with no port.
//
// # Secrets
//
// A built Batch carries the interface's WireGuard private key and
// every peer's preshared key as plain Command.Args values, because
// that is what execx.Runner.Run needs to set them in UCI. This
// package never logs a Batch or a Command; nothing in this file calls
// a logger or formats an error that includes Args. A caller that logs
// must not log a Batch's Text or Args either.
package uci
