package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/execx"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
	"github.com/tjjh89017/stunmesh-provisioner/internal/uci"
)

// runnerFor returns env.Runner, or execx.Exec{} when env.Runner is
// nil. A real run leaves env.Runner nil (see newEnv) and gets the
// real command runner. A test sets env.Runner to an *execx.Fake, the
// same pattern Env already uses for HTTPClient (see newBackend
// in fetch.go).
func runnerFor(env *Env) execx.Runner {
	if env.Runner != nil {
		return env.Runner
	}
	return execx.Exec{}
}

// applyDiff runs the apply procedure for diff, the result of
// computeDiff, and writes cfg.LastPath on success. state is the
// last.json content checkAndApply already read; applyDiff needs it
// only to carry forward the recorded UCI sections of an unchanged
// interface into the new last.json (an InterfaceDiff for
// InterfaceUnchanged does not carry Sections; see fetch_diff.go).
//
// # Steps
//
// applyDiff runs the steps in this exact order:
//
//  1. Delete the recorded sections of every removed or changed
//     interface, then create the sections of every new or changed
//     interface (uciBatch, one interface at a time, in diff.Interfaces
//     order).
//     1a. Firewall zone reconciliation (manageFirewall): only when
//     step 1 touched at least one interface (anyInterfaceChanged).
//     Stages the "stunmesh" zone's creation or deletion, its three
//     default forwarding sections' creation or deletion (tied to the
//     zone's own lifecycle), and "network" list membership for every
//     interface that is now new or was just removed. This is staged,
//     like step 1; nothing here takes effect until the commits below.
//  2. "uci commit network", once.
//  3. "uci commit firewall", once, but only when step 1a staged a
//     change (see this function's doc comment "Firewall config
//     commits separately").
//  4. "ubus call network reload".
//  5. "ifup <iface>" for every new or changed interface, in
//     diff.Interfaces order. No removed interface gets one; see
//     ifupChangedInterfaces's doc comment for why step 4 alone is not
//     enough here, and why a removed interface needs nothing more.
//  6. "/etc/init.d/firewall reload", only when step 1a staged a
//     change.
//  7. Write cfg.Stunmesh.WritePath (mode 0600), or delete it when the
//     new stunmesh text is empty. The daemon rebuilds or stops the
//     embedded stunmesh-go app afterwards (reconcileEmbedded in
//     daemon.go), after inspecting the Diff this function's caller
//     (checkAndApply, fetch.go) returns.
//  8. Write cfg.LastPath (mode 0600, last.Write), only when every step
//     above succeeded. This is where the firewall zone's ZoneOwned
//     and Members (last.FirewallState) actually get recorded.
//
// applyDiff stops at the first failing step and returns an error. It
// never writes cfg.LastPath after a failure, so the next cycle sees
// the same diff and retries the same steps: the apply is idempotent.
//
// A failed step 1 reverts the staged UCI changes with "uci revert
// network"; deleteSections and clearListOptions make a retry
// idempotent by skipping a delete or list-append that already ran.
func applyDiff(env *Env, cfg *Config, diff *Diff, state *last.State) error {
	runner := runnerFor(env)

	if err := writeUCI(runner, diff); err != nil {
		revertUCI(runner, "network")
		return fmt.Errorf("uci: %w", err)
	}

	// Firewall zone reconciliation only has anything to do when
	// writeUCI just touched at least one
	// interface: an interface's membership in the "stunmesh" zone
	// depends only on whether it now exists (new/changed/unchanged)
	// or was just removed, never on the stunmesh section alone. See
	// manageFirewall's doc comment for the ownership and
	// self-healing rules.
	newFirewall := state.Firewall
	firewallChanged := false
	if anyInterfaceChanged(diff) {
		fw, changed, err := manageFirewall(runner, diff, state.Firewall)
		if err != nil {
			revertUCI(runner, "network")
			revertUCI(runner, "firewall")
			return fmt.Errorf("firewall: %w", err)
		}
		newFirewall = fw
		firewallChanged = changed
	}

	if _, err := runner.Run("uci", "commit", "network"); err != nil {
		revertUCI(runner, "network")
		revertUCI(runner, "firewall")
		return fmt.Errorf("uci commit: %w", err)
	}

	// The firewall config commits separately from network: the two
	// configs are staged and committed
	// independently by uci itself, and only firewallChanged interfaces
	// stage anything under "firewall" at all. Once "uci commit
	// network" above has succeeded, network is no longer revertible
	// (see the package doc "No revert after uci commit succeeds"), so
	// a failure here only reverts the still-staged firewall side.
	if firewallChanged {
		if _, err := runner.Run("uci", "commit", "firewall"); err != nil {
			revertUCI(runner, "firewall")
			return fmt.Errorf("uci commit firewall: %w", err)
		}
	}

	if _, err := runner.Run("ubus", "call", "network", "reload"); err != nil {
		return fmt.Errorf("network reload: %w", err)
	}

	if err := ifupChangedInterfaces(runner, diff); err != nil {
		return fmt.Errorf("ifup: %w", err)
	}

	// "/etc/init.d/firewall reload" runs after "ubus call network
	// reload" and every "ifup": the firewall reload should see every
	// interface's final state -- created, torn down, or re-pushed by
	// ifup -- rather than reload against network state that is still
	// mid-transition.
	if firewallChanged {
		if _, err := runner.Run("/etc/init.d/firewall", "reload"); err != nil {
			return fmt.Errorf("firewall reload: %w", err)
		}
	}

	// Step 7 writes or deletes the stunmesh config file. The daemon
	// rebuilds the embedded app afterwards.
	if err := applyStunmeshConfig(cfg.Stunmesh.WritePath, diff); err != nil {
		return fmt.Errorf("stunmesh config: %w", err)
	}

	newState := buildState(diff, state)
	newState.Firewall = newFirewall
	if err := last.Write(cfg.LastPath, newState); err != nil {
		return fmt.Errorf("last.json: %w", err)
	}

	return nil
}

// revertUCI discards every staged, uncommitted UCI change for config
// ("network" or "firewall"), so the next fetch starts clean (see
// applyDiff's doc comment "Recovery from a failure during step 1").
// It is best-effort: its own result is not checked, since a failure
// here gives applyDiff nothing safer to do than report the original
// failure and return, which it already does. Reverting a config with
// nothing staged (for example "firewall" when writeUCI itself failed
// before manageFirewall ever ran) is a harmless no-op.
func revertUCI(runner execx.Runner, config string) {
	_, _ = runner.Run("uci", "revert", config)
}

// manageFirewall runs the firewall half of step 1: stage the
// "stunmesh" zone's creation, deletion,
// and "network" list membership so every stunmesh-managed WireGuard
// interface -- new, changed, or unchanged -- ends up a member, and
// every removed interface does not. It stages only; the caller
// commits "firewall" separately from "network" (applyDiff's doc
// comment "Firewall config commits separately").
//
// have is state.Firewall, last.json's record of what a previous apply
// did. manageFirewall returns the FirewallState to record next, and
// whether it staged any change at all (so the caller knows whether
// "uci commit firewall" and "/etc/init.d/firewall reload" have
// anything to do).
//
// # Membership reconciliation
//
// manageFirewall computes membership from diff.Interfaces, not from a
// plain "this interface's Change is New/Removed" rule: any interface
// present in the new bundle (Change other than InterfaceRemoved) that
// is not yet in have.Members is added, even when its own Change is
// InterfaceChanged or InterfaceUnchanged. This is deliberate
// self-healing: an interface applied by a version of this agent
// before the firewall zone existed has no Members entry yet, and the
// first apply that touches any interface at all (this function only
// runs when anyInterfaceChanged is true) brings it into the zone
// without requiring a content change of its own. Every interface
// whose Change is InterfaceRemoved, and that have.Members still
// names, is removed.
//
// # Ownership
//
// manageFirewall never creates, modifies, or deletes firewall.stunmesh
// unless have.ZoneOwned is true (the agent created it) or the section
// does not exist yet (checked with "uci get", the same tolerant probe
// deleteIfPresent already uses). A firewall.stunmesh that already
// exists and is not recorded as agent-owned is a conflicting,
// operator-owned zone: manageFirewall stages nothing at all for it --
// no membership, no zone edit -- and returns the zero FirewallState,
// so last.json still records "not owned" and every later apply
// probes again (self-healing if the operator's section is later
// removed).
//
// # Retry safety
//
// Adding an interface re-stages "del_list" immediately before
// "add_list" for that same interface (RemoveFirewallZoneNetwork then
// AddFirewallZoneNetwork). uci's del_list on a value that is not
// present in the list is a normal, successful no-op -- it is not the
// same operation as "uci delete" or "uci get" on a whole section or
// option, which do fail on an absent path (see deleteIfPresent's doc
// comment for why that different operation needs a presence check
// first). This del_list-then-add_list pair makes adding a member
// idempotent the same way clearListOptions makes an interface's own
// list options idempotent (fetch_apply.go's doc comment "Retrying a
// create after a successful commit"): a retry after "uci commit
// firewall" already succeeded once, but a later step failed before
// last.json was rewritten, re-stages the same add for a member that
// may already be there, and must not end up listed twice.
//
// Removing the last member does not use RemoveFirewallZoneNetwork at
// all: manageFirewall deletes the whole zone section instead, by its
// exact recorded name, the same as BuildDelete does for an
// interface's own sections, since there is no reason to leave an
// empty, agent-owned zone behind.
func manageFirewall(runner execx.Runner, diff *Diff, have last.FirewallState) (last.FirewallState, bool, error) {
	haveMembers := make(map[string]bool, len(have.Members))
	for _, name := range have.Members {
		haveMembers[name] = true
	}

	var toAdd, toRemove []string
	remaining := 0
	for _, id := range diff.Interfaces {
		if id.Change == InterfaceRemoved {
			if haveMembers[id.Name] {
				toRemove = append(toRemove, id.Name)
			}
			continue
		}
		remaining++
		if !haveMembers[id.Name] {
			toAdd = append(toAdd, id.Name)
		}
	}

	if remaining == 0 {
		if !have.ZoneOwned {
			return last.FirewallState{}, false, nil
		}
		// The three forwardings share the zone's lifecycle exactly
		// (uci.DeleteFirewallForwardings' doc comment): deleted here,
		// alongside the zone itself, never independently of it.
		if err := runUCIBatch(runner, uci.DeleteFirewallForwardings()); err != nil {
			return last.FirewallState{}, false, fmt.Errorf("delete firewall forwardings: %w", err)
		}
		if _, err := runner.Run("uci", deleteFirewallZoneArgs()...); err != nil {
			return last.FirewallState{}, false, fmt.Errorf("delete firewall zone: %w", err)
		}
		return last.FirewallState{}, true, nil
	}

	if len(toAdd) == 0 && len(toRemove) == 0 {
		return have, false, nil
	}

	owned := have.ZoneOwned
	if !owned {
		present, err := firewallZonePresent(runner)
		if err != nil {
			return last.FirewallState{}, false, err
		}
		if present {
			// Operator-owned: leave it alone.
			return last.FirewallState{}, false, nil
		}
		if err := runFirewallZoneCreate(runner); err != nil {
			return last.FirewallState{}, false, fmt.Errorf("create firewall zone: %w", err)
		}
		owned = true
	}

	// toAdd or toRemove (or both) is non-empty here (the "nothing to
	// do" case already returned above), so this function always
	// stages at least one uci call from this point on: the return
	// below always reports changed as true.
	for _, name := range toRemove {
		if _, err := runner.Run("uci", removeFirewallNetworkArgs(name)...); err != nil {
			return last.FirewallState{}, false, fmt.Errorf("remove firewall network %s: %w", name, err)
		}
		delete(haveMembers, name)
	}
	for _, name := range toAdd {
		if _, err := runner.Run("uci", removeFirewallNetworkArgs(name)...); err != nil {
			return last.FirewallState{}, false, fmt.Errorf("clear firewall network %s: %w", name, err)
		}
		if _, err := runner.Run("uci", addFirewallNetworkArgs(name)...); err != nil {
			return last.FirewallState{}, false, fmt.Errorf("add firewall network %s: %w", name, err)
		}
		haveMembers[name] = true
	}

	members := make([]string, 0, len(haveMembers))
	for _, id := range diff.Interfaces {
		if id.Change != InterfaceRemoved && haveMembers[id.Name] {
			members = append(members, id.Name)
		}
	}

	return last.FirewallState{ZoneOwned: owned, Members: members}, true, nil
}

// firewallZonePresent reports whether firewall.stunmesh exists, using
// the same tolerant "uci get" probe deleteIfPresent already uses for
// a UCI section: a failed "uci get" means the section is not there.
func firewallZonePresent(runner execx.Runner) (bool, error) {
	_, err := runner.Run("uci", "get", "firewall."+uci.FirewallZoneName)
	return err == nil, nil
}

// runFirewallZoneCreate runs uci.BuildFirewallZoneCreate's batch, then
// uci.BuildFirewallForwardingsCreate's: the zone always exists before
// the forwardings that name it as their
// src or dest are created. The three forwardings share the zone's
// lifecycle exactly (see DeleteFirewallForwardings' doc comment), so
// they are always created here, together with the zone, never on
// their own.
func runFirewallZoneCreate(runner execx.Runner) error {
	if err := runUCIBatch(runner, uci.BuildFirewallZoneCreate()); err != nil {
		return err
	}
	return runUCIBatch(runner, uci.BuildFirewallForwardingsCreate())
}

func deleteFirewallZoneArgs() []string {
	return uci.DeleteFirewallZone().Args
}

func addFirewallNetworkArgs(iface string) []string {
	return uci.AddFirewallZoneNetwork(iface).Args
}

func removeFirewallNetworkArgs(iface string) []string {
	return uci.RemoveFirewallZoneNetwork(iface).Args
}

// writeUCI runs step 1 of the apply procedure: for every interface in
// diff.Interfaces, in order, delete its recorded sections
// (InterfaceRemoved, InterfaceChanged) and then create its sections
// from the new content (InterfaceNew, InterfaceChanged). It runs no
// network command; the caller runs "uci commit network" afterwards.
//
// The delete half goes through deleteSections, which tolerates an
// already-absent section. The create half clears each interface's
// list options first, through clearListOptions, so "uci add_list"
// never appends onto a list an earlier, partly-applied create already
// populated.
func writeUCI(runner execx.Runner, diff *Diff) error {
	for _, id := range diff.Interfaces {
		switch id.Change {
		case InterfaceRemoved:
			if err := deleteSections(runner, id.Sections); err != nil {
				return fmt.Errorf("delete %s: %w", id.Name, err)
			}
		case InterfaceChanged:
			if err := deleteSections(runner, id.Sections); err != nil {
				return fmt.Errorf("delete %s: %w", id.Name, err)
			}
			if err := createInterface(runner, id.Name, *id.Content); err != nil {
				return err
			}
		case InterfaceNew:
			if err := createInterface(runner, id.Name, *id.Content); err != nil {
				return err
			}
		case InterfaceUnchanged:
			// Nothing to do for an unchanged interface.
		}
	}
	return nil
}

// createInterface clears name's list options (clearListOptions), then
// runs its create batch (uci.BuildInterface). See applyDiff's doc
// comment "Retrying a create after a successful commit" for why the
// clear must run first.
func createInterface(runner execx.Runner, name string, iface bundle.Interface) error {
	if err := clearListOptions(runner, uci.ListOptions(name, iface)); err != nil {
		return fmt.Errorf("clear lists %s: %w", name, err)
	}
	if err := runUCIBatch(runner, uci.BuildInterface(name, iface)); err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	return nil
}

// clearListOptions deletes each "network.<path>" in options if it is
// currently there, through deleteIfPresent, so a create never lets
// "uci add_list" append onto values a previous partial run left
// behind.
func clearListOptions(runner execx.Runner, options []string) error {
	for _, option := range options {
		if err := deleteIfPresent(runner, option); err != nil {
			return err
		}
	}
	return nil
}

// deleteSections runs the delete half of step 1 for one interface's
// recorded sections: peer sections, then route sections, then the
// interface section last, the same order uci.BuildDelete builds (see
// its doc comment). It deletes only the exact names sections records,
// never a pattern.
//
// Unlike a plain uci.BuildDelete batch run through runUCIBatch,
// deleteSections checks each section with deleteIfPresent first and
// skips a section that is not there, so a retry does not fail on a
// section an earlier, partly-applied commit already removed.
func deleteSections(runner execx.Runner, sections last.Sections) error {
	for _, peer := range sections.Peers {
		if err := deleteIfPresent(runner, peer); err != nil {
			return err
		}
	}
	for _, route := range sections.Routes {
		if err := deleteIfPresent(runner, route); err != nil {
			return err
		}
	}
	if sections.Interface != "" {
		if err := deleteIfPresent(runner, sections.Interface); err != nil {
			return err
		}
	}
	return nil
}

// deleteIfPresent deletes UCI path "network.<name>" only if it is
// currently there. name may name a whole section ("wg0") or one
// option inside a section ("wg0.addresses"); "uci get" and "uci
// delete" both accept either form, so deleteIfPresent needs no
// separate case for the two. It runs "uci get network.<name>" first.
// A failed "uci get" here means the path is not there: deleteIfPresent
// returns nil without attempting the delete. See applyDiff's doc
// comments "Retrying a delete after a successful commit" and
// "Retrying a create after a successful commit" for why reading the
// failure this way does not need execx to expose why the command
// failed.
//
// When "uci get" succeeds, deleteIfPresent runs "uci delete
// network.<name>" and returns that call's result unchanged: a real
// failure to delete a path that is there is not tolerated.
func deleteIfPresent(runner execx.Runner, name string) error {
	if _, err := runner.Run("uci", "get", "network."+name); err != nil {
		return nil
	}
	_, err := runner.Run("uci", "delete", "network."+name)
	return err
}

// runUCIBatch runs every Command in batch, in order, through
// runner.Run("uci", cmd.Args...). It stops and returns the first
// error, running no further command in batch.
func runUCIBatch(runner execx.Runner, batch uci.Batch) error {
	for _, cmd := range batch {
		if _, err := runner.Run("uci", cmd.Args...); err != nil {
			return err
		}
	}
	return nil
}

// ifupChangedInterfaces runs step 4 of the apply procedure: "ifup
// <iface>" for every interface in diff.Interfaces whose Change is
// InterfaceNew or InterfaceChanged, in diff.Interfaces order. It runs
// after "ubus call network reload" already ran (step 3).
//
// "network reload" does not push a peer-only change into the kernel;
// a changed interface needs an explicit "ifup". A removed interface
// gets none: reload already tears its netdev down, and step 1 already
// deleted its UCI section, so there is no config left to bring up.
// InterfaceUnchanged gets none either.
//
// A failing "ifup" is fatal, the same as a failing reload immediately
// before it: ifupChangedInterfaces returns the error, and applyDiff
// stops without writing last.json. UCI is already committed to the
// new state by this point, so the next fetch recomputes the same diff
// and retries the same "ifup" call; "ifup" on an interface that is
// already up is a normal, idempotent netifd operation.
func ifupChangedInterfaces(runner execx.Runner, diff *Diff) error {
	for _, id := range diff.Interfaces {
		if id.Change != InterfaceNew && id.Change != InterfaceChanged {
			continue
		}
		if _, err := runner.Run("ifup", id.Name); err != nil {
			return fmt.Errorf("ifup %s: %w", id.Name, err)
		}
	}
	return nil
}

// anyInterfaceChanged reports whether diff.Interfaces holds at least
// one interface whose Change is not InterfaceUnchanged. The caller
// (daemon.go's reconcileEmbedded) rebuilds the embedded stunmesh-go
// app when the stunmesh text or any interface changed; this is the
// "any interface changed" half of that condition.
func anyInterfaceChanged(diff *Diff) bool {
	for _, id := range diff.Interfaces {
		if id.Change != InterfaceUnchanged {
			return true
		}
	}
	return false
}

// applyStunmeshConfig runs step 5 of the apply procedure: write path
// (mode 0600) with diff.StunmeshContent when the stunmesh
// text changed, delete path when the new stunmesh text is empty, or
// do nothing when the text is unchanged. Deleting a path that is
// already absent is not an error (os.IsNotExist is treated as
// success).
func applyStunmeshConfig(path string, diff *Diff) error {
	switch diff.Stunmesh {
	case StunmeshEmpty:
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	case StunmeshChanged:
		return writeStunmeshConfigAtomic(path, diff.StunmeshContent)
	default: // StunmeshUnchanged
		return nil
	}
}

// writeStunmeshConfigAtomic writes content to path so that a crash at
// any point leaves path either absent, still holding its previous
// content, or holding the new content in full -- never truncated or
// partially written -- and never briefly at a mode wider than 0600.
// It follows the same create-temp-file/chmod/write/sync/close/rename
// sequence as internal/last.Write, and, like that function (and
// unlike keygen_cmd.go's writeIdentityKeyAtomic), uses os.Rename, not
// os.Link, because it must succeed whether or not path already
// exists: applyStunmeshConfig calls it every time the stunmesh text
// changed, not only the first time.
//
// writeStunmeshConfigAtomic never logs or echoes content; on failure,
// its error names only a path.
func writeStunmeshConfigAtomic(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".stunmesh-config.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Best effort: if anything below fails before the rename, remove
	// the temporary file so it does not linger. After a successful
	// rename, tmpPath no longer exists, so this is a silent no-op on
	// the success path.
	defer func() { _ = os.Remove(tmpPath) }()

	if cerr := tmp.Chmod(0o600); cerr != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpPath, cerr)
	}
	if _, werr := tmp.WriteString(content); werr != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpPath, werr)
	}
	if serr := tmp.Sync(); serr != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpPath, serr)
	}
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("close %s: %w", tmpPath, cerr)
	}

	if rerr := os.Rename(tmpPath, path); rerr != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, path, rerr)
	}

	return nil
}

// buildState builds the last.json content to write after a
// successful apply: every interface's section names. For
// InterfaceNew and InterfaceChanged, it records the sections
// BuildInterface just created (sectionsFor). For InterfaceUnchanged,
// it carries forward the sections already recorded in state (the new
// diff never touched that interface, so its recorded sections still
// name what is in UCI). InterfaceRemoved interfaces are dropped:
// their sections are gone.
func buildState(diff *Diff, state *last.State) *last.State {
	wg := make(map[string]last.Interface, len(diff.Interfaces))
	for _, id := range diff.Interfaces {
		switch id.Change {
		case InterfaceNew, InterfaceChanged:
			wg[id.Name] = last.Interface{
				Content:  *id.Content,
				Sections: sectionsFor(id.Name, *id.Content),
			}
		case InterfaceUnchanged:
			wg[id.Name] = state.WG[id.Name]
		case InterfaceRemoved:
			// Omitted: this interface's sections no longer exist.
		}
	}

	return &last.State{
		Version:  last.CurrentVersion,
		WG:       wg,
		Stunmesh: diff.StunmeshContent,
	}
}

// sectionsFor names the UCI sections BuildInterface creates for name
// and iface: interface "<iface>", route "<iface>_r_<n>", peer
// "<iface>_p_<peer>". It names them through uci.RouteSectionNames and
// uci.PeerSectionNames, the same functions BuildInterface itself uses.
func sectionsFor(name string, iface bundle.Interface) last.Sections {
	return last.Sections{
		Interface: name,
		Routes:    uci.RouteSectionNames(name, iface.Routes),
		Peers:     uci.PeerSectionNames(name, iface.Peers),
	}
}
