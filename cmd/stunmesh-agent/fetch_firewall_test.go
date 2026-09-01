package main

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/execx"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// TestManageFirewall_RemoveOneOfSeveralInterfacesKeepsZone pins the
// user-facing deletion semantics (PLAN.md 6 "Firewall zone"): when
// several interfaces share the "stunmesh" zone and only one is
// removed, manageFirewall removes that one interface's "network" list
// entry only. The zone section itself, and every other interface's
// membership, is left untouched -- it is not deleted and not
// recreated.
func TestManageFirewall_RemoveOneOfSeveralInterfacesKeepsZone(t *testing.T) {
	fake := execx.NewFake()
	have := last.FirewallState{ZoneOwned: true, Members: []string{"wg0", "wg1", "wg2"}}

	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceUnchanged},
			{Name: "wg1", Change: InterfaceRemoved, Sections: last.Sections{Interface: "wg1"}},
			{Name: "wg2", Change: InterfaceUnchanged},
		},
	}

	got, changed, err := manageFirewall(fake, diff, have)
	if err != nil {
		t.Fatalf("manageFirewall: %v", err)
	}
	if !changed {
		t.Fatalf("changed = false, want true (wg1's network entry was removed)")
	}

	want := []execx.Call{
		// Only wg1's own entry is removed -- del_list, not a whole
		// section delete, and no re-add for wg0 or wg2 (they were
		// already recorded members, so they are left alone). The exact
		// (not just "contains") comparison below is also the
		// kept-on-partial-delete assertion for the zone's three
		// forwarding sections: since they are only ever touched
		// alongside zone creation/deletion (never for a plain
		// membership change), no "uci set"/"uci delete" for any
		// "stunmesh_fwd_*" section appears here at all.
		{Name: "uci", Args: []string{"del_list", "firewall.stunmesh.network=wg1"}},
	}
	if calls := fake.Calls(); !reflect.DeepEqual(calls, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", calls, want)
	}

	if !got.ZoneOwned {
		t.Errorf("ZoneOwned = false, want true: the zone still has members and the agent still owns it")
	}
	wantMembers := []string{"wg0", "wg2"}
	if !reflect.DeepEqual(got.Members, wantMembers) {
		t.Errorf("Members = %v, want %v", got.Members, wantMembers)
	}
}

// TestManageFirewall_RemoveLastInterfaceDeletesZone pins the other
// half of the same rule: once the last agent-managed interface is
// removed, manageFirewall deletes the whole "stunmesh" zone section
// (by its exact, known name -- PLAN.md 6 "Rules"), rather than
// leaving an empty, agent-owned zone behind.
func TestManageFirewall_RemoveLastInterfaceDeletesZone(t *testing.T) {
	fake := execx.NewFake()
	have := last.FirewallState{ZoneOwned: true, Members: []string{"wg0"}}

	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceRemoved, Sections: last.Sections{Interface: "wg0"}},
		},
	}

	got, changed, err := manageFirewall(fake, diff, have)
	if err != nil {
		t.Fatalf("manageFirewall: %v", err)
	}
	if !changed {
		t.Fatalf("changed = false, want true (the zone was deleted)")
	}

	want := []execx.Call{
		// The three default forwardings share the zone's lifecycle
		// exactly: deleted here, before the zone itself, never left
		// behind on their own (uci.DeleteFirewallForwardings' doc
		// comment).
		{Name: "uci", Args: []string{"delete", "firewall.stunmesh_fwd_lan_stunmesh"}},
		{Name: "uci", Args: []string{"delete", "firewall.stunmesh_fwd_stunmesh_lan"}},
		{Name: "uci", Args: []string{"delete", "firewall.stunmesh_fwd_stunmesh_wan"}},
		{Name: "uci", Args: []string{"delete", "firewall.stunmesh"}},
	}
	if calls := fake.Calls(); !reflect.DeepEqual(calls, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", calls, want)
	}

	if got.ZoneOwned {
		t.Errorf("ZoneOwned = true, want false after deleting the zone")
	}
	if len(got.Members) != 0 {
		t.Errorf("Members = %v, want empty after deleting the zone", got.Members)
	}
}

// TestManageFirewall_RemovingUnrecordedMemberIsANoOp guards the
// invariant manageFirewall relies on (Members is only meaningful
// while ZoneOwned is true): removing an interface that was never
// recorded as a zone member -- because the zone was never owned --
// stages nothing.
func TestManageFirewall_RemovingUnrecordedMemberIsANoOp(t *testing.T) {
	fake := execx.NewFake()
	have := last.FirewallState{} // never owned, no members.

	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceRemoved, Sections: last.Sections{Interface: "wg0"}},
		},
	}

	got, changed, err := manageFirewall(fake, diff, have)
	if err != nil {
		t.Fatalf("manageFirewall: %v", err)
	}
	if changed {
		t.Errorf("changed = true, want false: nothing was ever recorded to remove")
	}
	if len(fake.Calls()) != 0 {
		t.Errorf("Calls() = %+v, want none", fake.Calls())
	}
	if got.ZoneOwned || len(got.Members) != 0 {
		t.Errorf("got = %+v, want the zero FirewallState", got)
	}
}

// TestManageFirewall_OperatorOwnedZoneIsNeverTouched pins the
// clobber-avoidance rule (PLAN.md 6 "Rules"): a firewall.stunmesh that
// already exists and is not recorded as agent-owned is left
// completely alone -- manageFirewall only probes it, stages no
// change, and last.json keeps recording "not owned" so a later apply
// probes again.
func TestManageFirewall_OperatorOwnedZoneIsNeverTouched(t *testing.T) {
	// The probe ("uci get firewall.stunmesh") is left unscripted, so it
	// defaults to success: the section is there.
	fake := execx.NewFake()
	have := last.FirewallState{}

	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceNew},
		},
	}

	got, changed, err := manageFirewall(fake, diff, have)
	if err != nil {
		t.Fatalf("manageFirewall: %v", err)
	}
	if changed {
		t.Errorf("changed = true, want false: an operator-owned zone must not be modified")
	}
	want := []execx.Call{
		{Name: "uci", Args: []string{"get", "firewall.stunmesh"}},
	}
	if calls := fake.Calls(); !reflect.DeepEqual(calls, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v (only the probe, nothing staged)", calls, want)
	}
	if got.ZoneOwned || len(got.Members) != 0 {
		t.Errorf("got = %+v, want the zero FirewallState (still not owned)", got)
	}
}

// TestApplyDiff_FullApplyMultipleInterfacesOneZoneNoDuplicates covers
// --full-apply (PLAN.md section 3, Config.FullApply) against three
// already-applied interfaces: computeDiff(forceAll=true) classifies
// every one of them as InterfaceChanged even though their content did
// not change (TestComputeDiff_ForceAllPromotesUnchangedToChanged
// already pins that classification on its own). This test drives the
// resulting Diff through applyDiff and pins what a full apply must do
// to the firewall zone: exactly one zone (created only once, not once
// per interface), all three interfaces present in its "network" list,
// and no interface's entry duplicated -- a full apply reruns every
// interface's UCI create batch, so a firewall step that is not
// itself idempotent would double every add_list on the very first
// --full-apply run after this feature ships.
func TestApplyDiff_FullApplyMultipleInterfacesOneZoneNoDuplicates(t *testing.T) {
	cfg := applyTestConfig(t)
	env := newEnv(strings.NewReader(""), new(strings.Builder), new(strings.Builder))
	// manageFirewall's "uci get firewall.stunmesh" probe (fetch_apply.go
	// firewallZonePresent) is made to fail regardless of when it runs
	// in the sequence, so it reads as "absent" and manageFirewall
	// creates the zone -- every other call defaults to success. This
	// avoids having to hand-count the index of the probe call among the
	// three interfaces' own delete/create batches (writeUCI runs
	// first).
	fake := &failMatching{
		fake: execx.NewFake(),
		match: func(name string, args []string) bool {
			return name == "uci" && len(args) == 2 && args[0] == "get" && args[1] == "firewall.stunmesh"
		},
	}
	env.Runner = fake

	wg0 := testInterface(t, `{"private_key":"wg0-key","addresses":["10.0.0.1/24"],"peers":{}}`)
	wg1 := testInterface(t, `{"private_key":"wg1-key","addresses":["10.0.1.1/24"],"peers":{}}`)
	wg2 := testInterface(t, `{"private_key":"wg2-key","addresses":["10.0.2.1/24"],"peers":{}}`)

	// Simulates computeDiff(b, state, true): every interface present in
	// both the bundle and last.json is InterfaceChanged, carrying its
	// recorded Sections forward, exactly as
	// TestComputeDiff_ForceAllPromotesUnchangedToChanged already pins
	// computeDiff itself does.
	diff := &Diff{
		Interfaces: []InterfaceDiff{
			{Name: "wg0", Change: InterfaceChanged, Content: &wg0, Sections: last.Sections{Interface: "wg0"}},
			{Name: "wg1", Change: InterfaceChanged, Content: &wg1, Sections: last.Sections{Interface: "wg1"}},
			{Name: "wg2", Change: InterfaceChanged, Content: &wg2, Sections: last.Sections{Interface: "wg2"}},
		},
		Stunmesh:        StunmeshChanged,
		StunmeshContent: "text",
	}
	state := &last.State{
		Version: last.CurrentVersion,
		WG: map[string]last.Interface{
			"wg0": {Content: wg0, Sections: last.Sections{Interface: "wg0"}},
			"wg1": {Content: wg1, Sections: last.Sections{Interface: "wg1"}},
			"wg2": {Content: wg2, Sections: last.Sections{Interface: "wg2"}},
		},
		Stunmesh: "text",
		// state.Firewall is the zero value: this models the very first
		// full apply after upgrading to this feature, where none of the
		// three pre-existing interfaces has a recorded zone membership
		// yet (see manageFirewall's doc comment "Membership
		// reconciliation" for the self-healing this exercises).
	}

	code := applyDiffForTest(env, cfg, diff, state)
	if code != ExitOK {
		t.Fatalf("code = %d, want %d", code, ExitOK)
	}

	// Exactly one zone-create batch: the 5 "uci set firewall.stunmesh..."
	// calls appear once, not once per interface.
	createCalls := 0
	for _, call := range fake.Calls() {
		if call.Name == "uci" && len(call.Args) == 2 && call.Args[0] == "set" && call.Args[1] == "firewall.stunmesh=zone" {
			createCalls++
		}
	}
	if createCalls != 1 {
		t.Errorf("firewall.stunmesh=zone created %d times, want exactly 1: %+v", createCalls, fake.Calls())
	}

	// Exactly one create for each of the three default forwardings too
	// -- created once alongside the zone, not once per interface and
	// not duplicated by a later, unrelated full-apply pass over an
	// already-owned zone.
	for _, section := range []string{"stunmesh_fwd_lan_stunmesh", "stunmesh_fwd_stunmesh_lan", "stunmesh_fwd_stunmesh_wan"} {
		count := 0
		want := "firewall." + section + "=forwarding"
		for _, call := range fake.Calls() {
			if call.Name == "uci" && len(call.Args) == 2 && call.Args[0] == "set" && call.Args[1] == want {
				count++
			}
		}
		if count != 1 {
			t.Errorf("%s created %d times, want exactly 1: %+v", want, count, fake.Calls())
		}
	}

	// Exactly one add_list per interface: no duplicates.
	addCounts := map[string]int{}
	for _, call := range fake.Calls() {
		if call.Name != "uci" || len(call.Args) != 2 || call.Args[0] != "add_list" {
			continue
		}
		const prefix = "firewall.stunmesh.network="
		if strings.HasPrefix(call.Args[1], prefix) {
			addCounts[strings.TrimPrefix(call.Args[1], prefix)]++
		}
	}
	for _, iface := range []string{"wg0", "wg1", "wg2"} {
		if addCounts[iface] != 1 {
			t.Errorf("add_list firewall.stunmesh.network=%s ran %d times, want exactly 1: %+v", iface, addCounts[iface], fake.Calls())
		}
	}

	st, err := last.Read(cfg.LastPath)
	if err != nil {
		t.Fatalf("last.Read: %v", err)
	}
	if !st.Firewall.ZoneOwned {
		t.Errorf("Firewall.ZoneOwned = false, want true")
	}
	members := append([]string(nil), st.Firewall.Members...)
	sort.Strings(members)
	want := []string{"wg0", "wg1", "wg2"}
	if !reflect.DeepEqual(members, want) {
		t.Errorf("Firewall.Members = %v, want exactly %v with no duplicates", st.Firewall.Members, want)
	}
}
