package main

import (
	"fmt"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// sameContent reports whether state and b hold the same content
// (PLAN.md 4.5): `wg` plus `stunmesh`, with `timestamp` excluded and
// the presence of every key -- absent versus an explicit empty
// container -- taken into account exactly.
//
// Both sides are canonicalized by the same code: sameContent builds a
// synthetic *bundle.Bundle from state (stateToBundle) and compares it
// with b through bundle.Bundle.Equal, which calls bundle.Canonical on
// each side. There is no separate canonicalization path for last.json
// content; reusing bundle.Canonical/Equal is the guarantee that both
// sides are canonicalized identically -- a hand-written comparison
// could not make that promise as cheaply or as verifiably.
//
// state.WG and state.Stunmesh, and b.WG and b.Stunmesh, are the only
// fields sameContent's answer depends on: stateToBundle copies b's
// own Version, Namespace, and NodeID onto the synthetic bundle, so
// those fields trivially agree on both sides and cannot affect the
// comparison.
func sameContent(state *last.State, b *bundle.Bundle) (bool, error) {
	return stateToBundle(state, b).Equal(b)
}

// stateToBundle builds the *bundle.Bundle that represents state's
// content, for canonicalization through bundle.Canonical alongside a
// freshly fetched bundle. It copies Version, Namespace, and NodeID
// from ref (the new bundle being compared against) rather than
// inventing values, so those fields can never be the reason two
// otherwise-identical contents compare unequal (see sameContent).
//
// state.WG's value type is last.Interface, which wraps a
// bundle.Interface (Content) and the recorded UCI section names
// (Sections, irrelevant to content comparison). stateToBundle takes
// only Content, unchanged, into the synthetic bundle's WG map: last.
// State documents that it stores Content exactly as decoded, with no
// canonicalization of its own, precisely so a later comparison like
// this one can canonicalize it the same way as the new bundle's own
// interfaces.
//
// state.WG is never nil (last.Read always returns a non-nil, possibly
// empty, map; see its doc comment "Missing file"), so the returned
// bundle's WG is always non-nil too -- an empty last.json reads as an
// explicit empty `wg`, matching a bundle with `"wg":{}`, not as an
// absent `wg` (which bundle.Validate would reject on a real bundle
// anyway).
func stateToBundle(state *last.State, ref *bundle.Bundle) *bundle.Bundle {
	wg := make(map[string]bundle.Interface, len(state.WG))
	for name, iface := range state.WG {
		wg[name] = iface.Content
	}
	stunmesh := state.Stunmesh
	return &bundle.Bundle{
		Version:   ref.Version,
		Namespace: ref.Namespace,
		NodeID:    ref.NodeID,
		WG:        wg,
		Stunmesh:  &stunmesh,
	}
}

// applyChanges computes the diff between b and state (stage 3 item 6,
// fetch_diff.go: computeDiff, Diff, InterfaceDiff) and hands it to
// applyDiff, the seam the next stage 3 item fills in: the UCI batch
// and the apply (PLAN.md 6). state is the last.json content
// checkAndApply already read, handed forward so neither this item nor
// the next one needs to read it again.
func applyChanges(env *Env, cfg *Config, b *bundle.Bundle, state *last.State) int {
	diff, err := computeDiff(b, state)
	if err != nil {
		// computeDiff's only error source is bundle.Bundle.Canonical
		// (via interfaceEqual), which never includes field values in
		// its own errors (see internal/bundle's doc); safe to print
		// as-is.
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: diff: %v\n", err)
		return ExitError
	}

	return applyDiff(env, cfg, diff)
}

// applyDiff is the seam the next stage 3 item fills in: building the
// UCI batch from diff (PLAN.md 6 "UCI layout") and applying it
// (`uci commit network`, `ubus call network reload`, the stunmesh
// config file, `/etc/init.d/stunmesh reload`/`stop`, and writing
// last.json on success).
//
// This item's body is a stub: it does no work and always reports
// failure, which is correct until the next item replaces it -- there
// is nothing yet for a caller to treat as success.
func applyDiff(env *Env, cfg *Config, diff *Diff) int {
	fmt.Fprintln(env.Stderr, "stunmesh-agent: fetch: not implemented yet")
	return ExitError
}
