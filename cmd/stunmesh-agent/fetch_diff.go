package main

import (
	"sort"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// InterfaceChange classifies one interface's difference between the
// new bundle and last.json (PLAN.md stage 3 item 6, PLAN.md 6 change
// table).
type InterfaceChange int

const (
	// InterfaceNew means the interface is in the bundle, not in
	// last.json.
	InterfaceNew InterfaceChange = iota
	// InterfaceChanged means the interface is in both, and its content
	// differs.
	InterfaceChanged
	// InterfaceUnchanged means the interface is in both, and its
	// content is identical.
	InterfaceUnchanged
	// InterfaceRemoved means the interface is in last.json, not in the
	// bundle.
	InterfaceRemoved
)

// String names c for logs and test failure messages. It never
// includes bundle content.
func (c InterfaceChange) String() string {
	switch c {
	case InterfaceNew:
		return "new"
	case InterfaceChanged:
		return "changed"
	case InterfaceUnchanged:
		return "unchanged"
	case InterfaceRemoved:
		return "removed"
	default:
		return "unknown"
	}
}

// StunmeshChange classifies the `stunmesh` section's difference
// between the new bundle and last.json (PLAN.md stage 3 item 6,
// PLAN.md 6 change table).
type StunmeshChange int

const (
	// StunmeshUnchanged means the new bundle's stunmesh text is
	// non-empty and equal to the text last.json recorded.
	StunmeshUnchanged StunmeshChange = iota
	// StunmeshChanged means the new bundle's stunmesh text is
	// non-empty and differs from the text last.json recorded.
	StunmeshChanged
	// StunmeshEmpty means the new bundle's stunmesh text is "". This is
	// a real instruction (PLAN.md 6): delete the stunmesh config file
	// and stop stunmesh-go. StunmeshEmpty always wins over
	// StunmeshUnchanged, even when last.json also recorded "": the
	// apply step must still ensure the file is gone and stunmesh-go is
	// stopped, and doing so again is safe (deleting an absent file and
	// stopping a stopped service are both no-ops).
	StunmeshEmpty
)

// String names c for logs and test failure messages. It never
// includes the stunmesh text.
func (c StunmeshChange) String() string {
	switch c {
	case StunmeshUnchanged:
		return "unchanged"
	case StunmeshChanged:
		return "changed"
	case StunmeshEmpty:
		return "empty"
	default:
		return "unknown"
	}
}

// InterfaceDiff is one interface's diff result. It carries everything
// the apply step (PLAN.md 6, the next stage 3 item) needs for that one
// interface, so the apply step never has to re-derive anything from
// the bundle or last.json itself.
type InterfaceDiff struct {
	// Name is the interface name: the bundle's `wg` key, and the UCI
	// interface section name (PLAN.md 6: "section name = netdev name =
	// bundle key").
	Name string
	// Change is this interface's change class.
	Change InterfaceChange
	// Content is the new bundle's content for this interface. It is
	// set for InterfaceNew and InterfaceChanged (the apply step creates
	// sections from it) and nil otherwise: InterfaceUnchanged has
	// nothing to create, and InterfaceRemoved has no new content at
	// all.
	Content *bundle.Interface
	// Sections names the UCI sections last.json recorded for this
	// interface. It is meaningful for InterfaceChanged and
	// InterfaceRemoved (the apply step deletes exactly these names,
	// PLAN.md 6 "Rules") and is the zero value otherwise.
	Sections last.Sections
}

// Diff is the full per-fetch diff result (PLAN.md stage 3 item 6): one
// InterfaceDiff for every interface name that appears in the new
// bundle, in last.json, or both, plus the stunmesh classification. It
// is the value the apply step (PLAN.md 6, the next stage 3 item)
// consumes directly.
type Diff struct {
	// Interfaces holds one entry for every interface name in the union
	// of the new bundle's `wg` and last.json's WG. The order is the
	// interface names sorted lexicographically (see computeDiff), so
	// that iterating Interfaces gives the same sequence on every run
	// for the same input -- an integration test asserts an exact
	// command sequence, and sorted name order is the simplest rule
	// that is both deterministic and independent of map iteration
	// order or of the arbitrary order values arrived from the DHT.
	Interfaces []InterfaceDiff
	// Stunmesh is the stunmesh section's change class.
	Stunmesh StunmeshChange
	// StunmeshContent is the new bundle's stunmesh text. It is "" when
	// Stunmesh is StunmeshEmpty, and the new text otherwise.
	StunmeshContent string
}

// computeDiff computes the diff between b, the new bundle (already
// past every PLAN.md 4.4 check), and state, the last.json content
// checkAndApply already read. Ordinarily (forceAll false) computeDiff
// assumes b and state do not carry identical content as a whole
// (checkAndApply's sameContent check already ruled that out); it does
// not special-case that possibility itself.
//
// forceAll is cfg.FullApply (PLAN.md section 3, "--full-apply"): when
// true, checkAndApply has deliberately skipped that sameContent check
// (a periodic full re-apply must run even when nothing changed), so
// computeDiff classifies every interface present in both b and state
// as InterfaceChanged -- never InterfaceUnchanged -- and every
// non-empty stunmesh text as StunmeshChanged, even when the content is
// byte-for-byte identical on both sides. This is what makes a full
// apply actually rewrite every step (PLAN.md 6): the apply procedure
// only does work for InterfaceNew/InterfaceChanged/InterfaceRemoved
// and for a Stunmesh value other than StunmeshUnchanged, so an
// InterfaceUnchanged/StunmeshUnchanged classification would otherwise
// make forceAll a no-op for any interface or stunmesh text that
// genuinely did not change. InterfaceNew and InterfaceRemoved are
// unaffected by forceAll: there is no "identical content" question for
// an interface that exists on only one side.
//
// state.WG is never nil (last.Read's doc comment, "Missing file"), so
// computeDiff ranges over it directly.
//
// Per-interface content comparison (when forceAll is false) goes
// through interfaceEqual, which reuses bundle.Bundle.Canonical/Equal
// -- the same canonicalization path sameContent (fetch_compare.go)
// already uses for the whole bundle -- so presence (an absent field
// versus an explicit empty container, PLAN.md 4.3) is respected
// exactly, and there is only one place in this codebase that decides
// what "equal content" means.
func computeDiff(b *bundle.Bundle, state *last.State, forceAll bool) (*Diff, error) {
	names := make(map[string]struct{}, len(b.WG)+len(state.WG))
	for name := range b.WG {
		names[name] = struct{}{}
	}
	for name := range state.WG {
		names[name] = struct{}{}
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	diffs := make([]InterfaceDiff, 0, len(sorted))
	for _, name := range sorted {
		newIface, inNew := b.WG[name]
		oldIface, inOld := state.WG[name]

		switch {
		case inNew && !inOld:
			content := newIface
			diffs = append(diffs, InterfaceDiff{
				Name:    name,
				Change:  InterfaceNew,
				Content: &content,
			})
		case inNew && inOld:
			equal := false
			if !forceAll {
				var err error
				equal, err = interfaceEqual(name, newIface, oldIface.Content)
				if err != nil {
					return nil, err
				}
			}
			if equal {
				diffs = append(diffs, InterfaceDiff{
					Name:   name,
					Change: InterfaceUnchanged,
				})
				continue
			}
			content := newIface
			diffs = append(diffs, InterfaceDiff{
				Name:     name,
				Change:   InterfaceChanged,
				Content:  &content,
				Sections: oldIface.Sections,
			})
		case !inNew && inOld:
			diffs = append(diffs, InterfaceDiff{
				Name:     name,
				Change:   InterfaceRemoved,
				Sections: oldIface.Sections,
			})
		}
	}

	newStunmesh := ""
	if b.Stunmesh != nil {
		// b already passed bundle.Validate (ErrStunmesh), so
		// b.Stunmesh is never nil in practice; the nil check only
		// guards a bundle built directly in a test without going
		// through Validate.
		newStunmesh = *b.Stunmesh
	}

	return &Diff{
		Interfaces:      diffs,
		Stunmesh:        diffStunmesh(newStunmesh, state.Stunmesh, forceAll),
		StunmeshContent: newStunmesh,
	}, nil
}

// diffStunmesh classifies the stunmesh section (see StunmeshChange).
// An empty newStunmesh always classifies as StunmeshEmpty, even when
// oldStunmesh is also "": PLAN.md 6 treats an empty stunmesh as a real
// instruction (delete the file, stop stunmesh-go), not as the absence
// of a change. forceAll (see computeDiff's doc comment) promotes an
// otherwise-StunmeshUnchanged non-empty text to StunmeshChanged, so a
// full apply rewrites the stunmesh config file and reloads stunmesh-go
// even when the text did not actually change.
func diffStunmesh(newStunmesh, oldStunmesh string, forceAll bool) StunmeshChange {
	if newStunmesh == "" {
		return StunmeshEmpty
	}
	if newStunmesh == oldStunmesh && !forceAll {
		return StunmeshUnchanged
	}
	return StunmeshChanged
}

// interfaceEqual reports whether a and b, the same-named interface
// from the new bundle and from last.json, have identical content.
//
// It wraps each side in a minimal *bundle.Bundle under the same key
// (name) and calls bundle.Bundle.Equal, so both sides run through
// bundle.Canonical -- the exact canonicalization path sameContent
// already uses for the whole bundle (fetch_compare.go) -- rather than
// through a second, hand-written comparison that could drift from it.
// Canonical's presence guarantee (an absent field and an explicit
// empty container never compare equal) carries over unchanged.
//
// Version, Namespace, NodeID, and Stunmesh are left at their zero
// values on both sides; they are equal to each other by construction,
// so they cannot affect Equal's answer, and only the WG entry under
// name does.
func interfaceEqual(name string, a, b bundle.Interface) (bool, error) {
	empty := ""
	left := &bundle.Bundle{
		WG:       map[string]bundle.Interface{name: a},
		Stunmesh: &empty,
	}
	right := &bundle.Bundle{
		WG:       map[string]bundle.Interface{name: b},
		Stunmesh: &empty,
	}
	return left.Equal(right)
}
