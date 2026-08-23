package main

import (
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

func TestComputeDiff_NewInterface(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}, Stunmesh: "text"}

	diff, err := computeDiff(b, state)
	if err != nil {
		t.Fatalf("computeDiff: %v", err)
	}
	if len(diff.Interfaces) != 1 {
		t.Fatalf("len(Interfaces) = %d, want 1", len(diff.Interfaces))
	}
	got := diff.Interfaces[0]
	if got.Name != "wg0" || got.Change != InterfaceNew {
		t.Errorf("got %+v, want Name=wg0 Change=InterfaceNew", got)
	}
	if got.Content == nil {
		t.Fatalf("Content = nil, want the new interface content")
	}
	if got.Content.PrivateKey != "pk" {
		t.Errorf("Content.PrivateKey = %q, want %q", got.Content.PrivateKey, "pk")
	}
}

func TestComputeDiff_ChangedInterface(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk-new","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)
	old := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":50,`+
		`"wg":{"wg0":{"private_key":"pk-old","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	sections := last.Sections{Interface: "wg0", Peers: []string{"wg0_p_alice"}}
	state := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"wg0": {Content: old.WG["wg0"], Sections: sections}},
		Stunmesh: "text",
	}

	diff, err := computeDiff(b, state)
	if err != nil {
		t.Fatalf("computeDiff: %v", err)
	}
	if len(diff.Interfaces) != 1 {
		t.Fatalf("len(Interfaces) = %d, want 1", len(diff.Interfaces))
	}
	got := diff.Interfaces[0]
	if got.Change != InterfaceChanged {
		t.Errorf("Change = %v, want InterfaceChanged", got.Change)
	}
	if got.Content == nil || got.Content.PrivateKey != "pk-new" {
		t.Errorf("Content = %+v, want the new interface content", got.Content)
	}
	if got.Sections.Interface != "wg0" || len(got.Sections.Peers) != 1 {
		t.Errorf("Sections = %+v, want the recorded sections", got.Sections)
	}
}

func TestComputeDiff_UnchangedInterface(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)
	state := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"wg0": {Content: b.WG["wg0"], Sections: last.Sections{Interface: "wg0"}}},
		Stunmesh: "text",
	}

	diff, err := computeDiff(b, state)
	if err != nil {
		t.Fatalf("computeDiff: %v", err)
	}
	if len(diff.Interfaces) != 1 {
		t.Fatalf("len(Interfaces) = %d, want 1", len(diff.Interfaces))
	}
	got := diff.Interfaces[0]
	if got.Change != InterfaceUnchanged {
		t.Errorf("Change = %v, want InterfaceUnchanged", got.Change)
	}
	if got.Content != nil {
		t.Errorf("Content = %+v, want nil for an unchanged interface", got.Content)
	}
}

func TestComputeDiff_RemovedInterface(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{},"stunmesh":"text"}`)
	old := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":50,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	sections := last.Sections{Interface: "wg0", Routes: []string{"wg0_r_0"}}
	state := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"wg0": {Content: old.WG["wg0"], Sections: sections}},
		Stunmesh: "text",
	}

	diff, err := computeDiff(b, state)
	if err != nil {
		t.Fatalf("computeDiff: %v", err)
	}
	if len(diff.Interfaces) != 1 {
		t.Fatalf("len(Interfaces) = %d, want 1", len(diff.Interfaces))
	}
	got := diff.Interfaces[0]
	if got.Change != InterfaceRemoved {
		t.Errorf("Change = %v, want InterfaceRemoved", got.Change)
	}
	if got.Content != nil {
		t.Errorf("Content = %+v, want nil for a removed interface", got.Content)
	}
	if got.Sections.Interface != "wg0" || len(got.Sections.Routes) != 1 {
		t.Errorf("Sections = %+v, want the recorded sections", got.Sections)
	}
}

// TestComputeDiff_AbsentVsExplicitEmptyIsChanged pins that presence is
// part of content for the per-interface diff too, the same rule
// internal/bundle documents and sameContent already enforces for the
// whole bundle.
func TestComputeDiff_AbsentVsExplicitEmptyIsChanged(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"options":{},"peers":{}}},"stunmesh":"text"}`)
	old := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":50,`+
		`"wg":{"wg0":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	state := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"wg0": {Content: old.WG["wg0"]}},
		Stunmesh: "text",
	}

	diff, err := computeDiff(b, state)
	if err != nil {
		t.Fatalf("computeDiff: %v", err)
	}
	if len(diff.Interfaces) != 1 || diff.Interfaces[0].Change != InterfaceChanged {
		t.Errorf("Interfaces = %+v, want one InterfaceChanged entry: absent options must not equal explicit empty options", diff.Interfaces)
	}
}

func TestComputeDiff_OrderIsSortedByInterfaceName(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,"wg":{`+
		`"zeta":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}},`+
		`"alpha":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}`+
		`},"stunmesh":"text"}`)
	old := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":50,`+
		`"wg":{"middle":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	state := &last.State{
		Version:  last.CurrentVersion,
		WG:       map[string]last.Interface{"middle": {Content: old.WG["middle"]}},
		Stunmesh: "text",
	}

	diff, err := computeDiff(b, state)
	if err != nil {
		t.Fatalf("computeDiff: %v", err)
	}
	if len(diff.Interfaces) != 3 {
		t.Fatalf("len(Interfaces) = %d, want 3", len(diff.Interfaces))
	}
	var names []string
	for _, d := range diff.Interfaces {
		names = append(names, d.Name)
	}
	want := []string{"alpha", "middle", "zeta"}
	for i, n := range want {
		if names[i] != n {
			t.Errorf("names = %v, want sorted order %v", names, want)
			break
		}
	}
}

func TestComputeDiff_StunmeshChanged(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,"wg":{},"stunmesh":"new text"}`)
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}, Stunmesh: "old text"}

	diff, err := computeDiff(b, state)
	if err != nil {
		t.Fatalf("computeDiff: %v", err)
	}
	if diff.Stunmesh != StunmeshChanged {
		t.Errorf("Stunmesh = %v, want StunmeshChanged", diff.Stunmesh)
	}
	if diff.StunmeshContent != "new text" {
		t.Errorf("StunmeshContent = %q, want %q", diff.StunmeshContent, "new text")
	}
}

func TestComputeDiff_StunmeshUnchanged(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,"wg":{},"stunmesh":"same text"}`)
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}, Stunmesh: "same text"}

	diff, err := computeDiff(b, state)
	if err != nil {
		t.Fatalf("computeDiff: %v", err)
	}
	if diff.Stunmesh != StunmeshUnchanged {
		t.Errorf("Stunmesh = %v, want StunmeshUnchanged", diff.Stunmesh)
	}
}

// TestComputeDiff_StunmeshEmptyBeatsUnchanged pins PLAN.md 6: an empty
// `stunmesh` is always the "delete and stop" instruction, even when
// last.json already recorded an empty stunmesh text. It is never
// folded into StunmeshUnchanged just because both sides are "".
func TestComputeDiff_StunmeshEmptyBeatsUnchanged(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,"wg":{},"stunmesh":""}`)
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}, Stunmesh: ""}

	diff, err := computeDiff(b, state)
	if err != nil {
		t.Fatalf("computeDiff: %v", err)
	}
	if diff.Stunmesh != StunmeshEmpty {
		t.Errorf("Stunmesh = %v, want StunmeshEmpty even though both sides were already \"\"", diff.Stunmesh)
	}
}

func TestComputeDiff_StunmeshEmptyFromNonEmpty(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,"wg":{},"stunmesh":""}`)
	state := &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}, Stunmesh: "old text"}

	diff, err := computeDiff(b, state)
	if err != nil {
		t.Fatalf("computeDiff: %v", err)
	}
	if diff.Stunmesh != StunmeshEmpty {
		t.Errorf("Stunmesh = %v, want StunmeshEmpty", diff.Stunmesh)
	}
	if diff.StunmeshContent != "" {
		t.Errorf("StunmeshContent = %q, want empty", diff.StunmeshContent)
	}
}

// TestComputeDiff_AllClassesTogether exercises new, changed, unchanged
// and removed interfaces in one bundle/state pair, matching the shape
// the integration test (item 12) will drive applyChanges with.
func TestComputeDiff_AllClassesTogether(t *testing.T) {
	b := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":100,"wg":{`+
		`"new_if":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}},`+
		`"changed_if":{"private_key":"pk-new","addresses":["10.0.0.1/24"],"peers":{}},`+
		`"same_if":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}`+
		`},"stunmesh":"text"}`)

	changedOld := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":1,`+
		`"wg":{"changed_if":{"private_key":"pk-old","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)
	sameOld := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":1,`+
		`"wg":{"same_if":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)
	removedOld := parseTestBundle(t, `{"version":1,"namespace":"ns","node_id":"n1","timestamp":1,`+
		`"wg":{"removed_if":{"private_key":"pk","addresses":["10.0.0.1/24"],"peers":{}}},"stunmesh":"text"}`)

	state := &last.State{
		Version: last.CurrentVersion,
		WG: map[string]last.Interface{
			"changed_if": {Content: changedOld.WG["changed_if"]},
			"same_if":    {Content: sameOld.WG["same_if"]},
			"removed_if": {Content: removedOld.WG["removed_if"]},
		},
		Stunmesh: "text",
	}

	diff, err := computeDiff(b, state)
	if err != nil {
		t.Fatalf("computeDiff: %v", err)
	}

	want := map[string]InterfaceChange{
		"changed_if": InterfaceChanged,
		"new_if":     InterfaceNew,
		"removed_if": InterfaceRemoved,
		"same_if":    InterfaceUnchanged,
	}
	if len(diff.Interfaces) != len(want) {
		t.Fatalf("len(Interfaces) = %d, want %d", len(diff.Interfaces), len(want))
	}
	wantOrder := []string{"changed_if", "new_if", "removed_if", "same_if"}
	for i, d := range diff.Interfaces {
		if d.Name != wantOrder[i] {
			t.Errorf("Interfaces[%d].Name = %q, want %q (sorted order)", i, d.Name, wantOrder[i])
		}
		if wc := want[d.Name]; d.Change != wc {
			t.Errorf("Interfaces[%d] (%s).Change = %v, want %v", i, d.Name, d.Change, wc)
		}
	}
	if diff.Stunmesh != StunmeshUnchanged {
		t.Errorf("Stunmesh = %v, want StunmeshUnchanged", diff.Stunmesh)
	}
}
