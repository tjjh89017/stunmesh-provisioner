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
// same pattern Env already uses for HTTPClient (see newDHTProxyClient
// in fetch_cmd.go).
func runnerFor(env *Env) execx.Runner {
	if env.Runner != nil {
		return env.Runner
	}
	return execx.Exec{}
}

// applyDiff runs the apply procedure (PLAN.md 6) for diff, the result
// of computeDiff, and writes cfg.LastPath on success. state is the
// last.json content applyChanges already read; applyDiff needs it
// only to carry forward the recorded UCI sections of an unchanged
// interface into the new last.json (an InterfaceDiff for
// InterfaceUnchanged does not carry Sections; see fetch_diff.go).
//
// # Steps
//
// applyDiff runs the steps in this exact order (PLAN.md 6):
//
//  1. Delete the recorded sections of every removed or changed
//     interface, then create the sections of every new or changed
//     interface (uciBatch, one interface at a time, in diff.Interfaces
//     order).
//  2. "uci commit network", once.
//  3. "ubus call network reload".
//  4. "ifup <iface>" for every new or changed interface, in
//     diff.Interfaces order. No removed interface gets one; see
//     ifupChangedInterfaces's doc comment for why step 3 alone is not
//     enough here, and why a removed interface needs nothing more.
//  5. Write cfg.StunmeshConfigPath (mode 0600), or delete it when the
//     new stunmesh text is empty.
//  6. "/etc/init.d/stunmesh reload" when the stunmesh text or any
//     interface changed; "/etc/init.d/stunmesh stop" instead, when the
//     new stunmesh text is empty.
//  7. Write cfg.LastPath (mode 0600, last.Write), only when every step
//     above succeeded.
//
// applyDiff stops at the first failing step and returns ExitError. It
// never writes cfg.LastPath after a failure, so the next fetch sees
// the same diff and retries the same steps (PLAN.md 6 "Rules": "the
// apply is idempotent").
//
// # Recovery from a failure during step 1
//
// "uci set", "uci add_list", and "uci delete" only stage changes; they
// take no effect on the running system until "uci commit" runs. If
// step 1 fails partway through, applyDiff runs "uci revert network"
// before returning, discarding every staged change from this run. The
// next fetch then starts from the same, unmodified UCI state as this
// one did, and retries the same delete-then-create commands cleanly.
// Without this revert, a stale staged delete or create from the
// failed run could make a delete command in the next run's retry fail
// (a section it expects to still exist could already be staged
// absent), for a reason the next run cannot tell apart from a real
// failure -- execx's secret policy deliberately does not let a caller
// read a failed command's stderr to distinguish "not found" from
// anything else (see internal/execx's package doc "Secret policy").
// Reverting removes that ambiguity instead of trying to parse around
// it.
//
// # No revert after "uci commit" succeeds
//
// Once "uci commit network" succeeds, UCI already reflects the new
// state; there is nothing staged left to revert, and applyDiff does
// not call revert again after that point. A failure in a later step
// (network reload, ifup, the stunmesh config file, or
// /etc/init.d/stunmesh) leaves UCI committed to the new state but
// last.json still describing the old one. The next fetch recomputes
// the same diff against that stale last.json and retries step 1's
// deletes for the same section names.
//
// # Retrying a delete after a successful commit
//
// A retry's delete step names sections this run's own earlier commit
// may have already removed. A real uci returns non-zero for deleting
// a section that is not there, so a plain, unconditional delete would
// fail again on every following fetch, wedging the node until an
// operator intervenes by hand.
//
// writeUCI avoids this through deleteSections: before it deletes a
// recorded section, it checks with "uci get" whether the section is
// still there, and skips the delete when it is not. The exact names
// it checks and deletes are still only the ones last.json (or, for a
// section about to be recreated, this same diff) records -- this
// tolerance changes nothing about PLAN.md 6's "Rules": "The agent
// deletes sections by the exact names that last.json records. It
// never deletes by pattern."
//
// execx's secret policy (see internal/execx's package doc) does not
// let deleteSections read a failed "uci get" or "uci delete" call's
// exit code or output, so it cannot ask "is this failure specifically
// 'not found'?". It does not need to: "uci get" on one exact,
// already-known section name has, in practice, exactly one common
// failure reason -- the section is not there -- so deleteSections
// reads any failure of that specific, narrow call as "absent, nothing
// to delete", not as "unknown, proceed anyway". A "uci get" failure
// for any other underlying reason (a corrupt config file, a missing
// uci binary) does not stay hidden: the same underlying problem
// surfaces immediately at the delete or create call that follows,
// which deleteSections does not tolerate.
//
// # Retrying a create after a successful commit
//
// A retry's create step reruns the same "uci set" and "uci add_list"
// calls the earlier, partly-applied run already issued once. "uci
// set" only overwrites, so rerunning it is harmless. "uci add_list"
// appends: it does not check whether the value is already there. A
// plain, unconditional rerun of the create commands would silently
// double every entry of every list option -- "addresses" on the
// interface, "allowed_ips" on each peer -- and keep doubling them on
// every following retry, with no failing command and nothing in the
// log to point at.
//
// writeUCI avoids this through clearListOptions: immediately before
// it runs an interface's create batch, it clears every list option
// uci.ListOptions names for that interface, the same tolerant
// "uci get" then "uci delete" pattern deleteIfPresent already uses
// for a whole section, applied to one "<section>.<option>" path at a
// time. A path that is not there yet (a genuine first-time create) is
// left alone -- there is nothing to clear -- and the create batch
// then populates it from empty, exactly as it would have without a
// prior failed attempt.
func applyDiff(env *Env, cfg *Config, diff *Diff, state *last.State) int {
	runner := runnerFor(env)

	if err := writeUCI(runner, diff); err != nil {
		revertUCI(runner)
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: apply: uci: %v\n", err)
		return ExitError
	}

	if _, err := runner.Run("uci", "commit", "network"); err != nil {
		revertUCI(runner)
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: apply: uci commit: %v\n", err)
		return ExitError
	}

	if _, err := runner.Run("ubus", "call", "network", "reload"); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: apply: network reload: %v\n", err)
		return ExitError
	}

	if err := ifupChangedInterfaces(runner, diff); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: apply: ifup: %v\n", err)
		return ExitError
	}

	if err := applyStunmeshConfig(cfg.StunmeshConfigPath, diff); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: apply: stunmesh config: %v\n", err)
		return ExitError
	}

	if diff.Stunmesh != StunmeshUnchanged || anyInterfaceChanged(diff) {
		action := "reload"
		if diff.Stunmesh == StunmeshEmpty {
			action = "stop"
		}
		if _, err := runner.Run("/etc/init.d/stunmesh", action); err != nil {
			fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: apply: stunmesh %s: %v\n", action, err)
			return ExitError
		}
	}

	newState := buildState(diff, state)
	if err := last.Write(cfg.LastPath, newState); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: fetch: apply: last.json: %v\n", err)
		return ExitError
	}

	return ExitOK
}

// revertUCI discards every staged, uncommitted UCI change for the
// "network" config, so the next fetch starts clean (see applyDiff's
// doc comment "Recovery from a failure during step 1"). It is
// best-effort: its own result is not checked, since a failure here
// gives applyDiff nothing safer to do than report the original
// failure and return, which it already does.
func revertUCI(runner execx.Runner) {
	_, _ = runner.Run("uci", "revert", "network")
}

// writeUCI runs step 1 of the apply procedure (PLAN.md 6): for every
// interface in diff.Interfaces, in order, delete its recorded
// sections (InterfaceRemoved, InterfaceChanged) and then create its
// sections from the new content (InterfaceNew, InterfaceChanged). It
// runs no network command; PLAN.md 6 step 3/4 ("write UCI... No
// network command yet") is exactly this function plus the caller's
// later "uci commit network".
//
// The delete half goes through deleteSections, not a plain batch run:
// see applyDiff's doc comment "Retrying a delete after a successful
// commit" for why a delete must tolerate an already-absent section.
//
// The create half clears each interface's list options first, through
// clearListOptions, before running its create batch: see applyDiff's
// doc comment "Retrying a create after a successful commit" for why a
// create must not let "uci add_list" append onto a list an earlier,
// partly-applied create already populated.
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
			// Nothing to do: PLAN.md 6's change table has no row for
			// an unchanged interface.
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
// currently there, through deleteIfPresent -- the same tolerant check
// deleteIfPresent already runs for a whole section, applied here to
// one "<section>.<option>" path at a time. See applyDiff's doc
// comment "Retrying a create after a successful commit" for why a
// create must clear a list option before repopulating it, and why
// this reuses deleteIfPresent rather than a second idiom: the
// underlying command pattern -- "uci get" first, "uci delete" only if
// that succeeds -- is exactly the same regardless of whether the name
// after "network." is a whole section or one of its options.
func clearListOptions(runner execx.Runner, options []string) error {
	for _, option := range options {
		if err := deleteIfPresent(runner, option); err != nil {
			return err
		}
	}
	return nil
}

// deleteSections runs the delete half of step 1 (PLAN.md 6) for one
// interface's recorded sections: peer sections, then route sections,
// then the interface section last, the same order uci.BuildDelete
// builds (see its doc comment). It deletes only the exact names
// sections records, never a pattern (PLAN.md 6 "Rules").
//
// Unlike a plain uci.BuildDelete batch run through runUCIBatch,
// deleteSections checks each section with deleteIfPresent first and
// skips a section that is not there. See applyDiff's doc comment
// "Retrying a delete after a successful commit" for why: a retry
// after "uci commit network" already succeeded once names sections
// that commit may have already removed, and a plain delete would fail
// on them every time, wedging the node.
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

// ifupChangedInterfaces runs step 4 of the apply procedure (see
// applyDiff's doc comment "Steps"): "ifup <iface>" for every
// interface in diff.Interfaces whose Change is InterfaceNew or
// InterfaceChanged, in diff.Interfaces order. It runs after "ubus
// call network reload" already ran (step 3).
//
// PLAN.md 6 flagged this as an open assumption: "network reload also
// restarts a WireGuard interface when only its wireguard_<iface> peer
// sections changed. ... If it is false, add ifup <iface> for each
// changed interface." The e2e harness measured it on a real OpenWrt
// guest and found the assumption false: after a fetch that changed
// only one peer of one interface, "uci commit network" and "ubus call
// network reload" both succeeded, but "wg show" on the running kernel
// interface still listed the old peer, never the new one. A plain
// reload restages UCI; it does not, by itself, push a
// wireguard_<iface> peer change into the kernel. An explicit "ifup
// <iface>" for the affected interface is what makes netifd
// reconfigure it for real.
//
// InterfaceRemoved gets no ifup. The same e2e measurement found the
// opposite result for removal: "network reload" alone already tears a
// removed interface's kernel netdev down, with no extra "ifup" or
// "ifdown" needed. Adding one here would also be wrong on its own
// terms: step 1 already deleted the interface's UCI section, so
// "ifup" on that name has no config left to bring up. Do not add it
// back; the asymmetry between "changed needs ifup" and "removed does
// not" is the measured behavior, not an oversight.
//
// InterfaceUnchanged gets no ifup either: reload never touches an
// unchanged interface, and there is nothing new to push into it.
//
// A failing "ifup" is fatal, the same as a failing reload immediately
// before it: ifupChangedInterfaces returns the error, and applyDiff
// stops and reports ExitError without writing last.json (see
// applyDiff's doc comment "No revert after uci commit succeeds").
// UCI is already committed to the new state by this point, so the
// next fetch recomputes the same diff and retries the same "ifup"
// call. Unlike step 1's "uci add_list", "ifup" on an interface that
// is already up is a normal, idempotent netifd operation, not one
// that needs a tolerant retry path of its own.
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
// one interface whose Change is not InterfaceUnchanged. PLAN.md 6
// step 6 runs "/etc/init.d/stunmesh reload" (or "stop") "if the
// stunmesh text or any interface changed"; this is the "any interface
// changed" half of that condition.
func anyInterfaceChanged(diff *Diff) bool {
	for _, id := range diff.Interfaces {
		if id.Change != InterfaceUnchanged {
			return true
		}
	}
	return false
}

// applyStunmeshConfig runs step 5 of the apply procedure (PLAN.md 6):
// write path (mode 0600) with diff.StunmeshContent when the stunmesh
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
	defer os.Remove(tmpPath)

	if cerr := tmp.Chmod(0o600); cerr != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpPath, cerr)
	}
	if _, werr := tmp.WriteString(content); werr != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpPath, werr)
	}
	if serr := tmp.Sync(); serr != nil {
		tmp.Close()
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
// successful apply (PLAN.md 6 step 7): "record every interface's
// section names". For InterfaceNew and InterfaceChanged, it records
// the sections BuildInterface just created (sectionsFor). For
// InterfaceUnchanged, it carries forward the sections already
// recorded in state (the new diff never touched that interface, so
// its recorded sections still name what is in UCI). InterfaceRemoved
// interfaces are dropped: their sections are gone, and PLAN.md 6
// records only what the agent still owns.
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
// and iface (PLAN.md 6 "Rules": interface "<iface>", route
// "<iface>_r_<n>", peer "<iface>_p_<peer>"). It names them through
// uci.RouteSectionNames and uci.PeerSectionNames, the same functions
// internal/uci's own BuildInterface derives its create commands'
// section names from (both go through routeSectionName and
// peerSectionName). sectionsFor holds no naming rule of its own: it
// cannot drift from what BuildInterface actually creates, because
// there is only one implementation of the naming convention, and this
// is it, called from the record side too.
func sectionsFor(name string, iface bundle.Interface) last.Sections {
	return last.Sections{
		Interface: name,
		Routes:    uci.RouteSectionNames(name, iface.Routes),
		Peers:     uci.PeerSectionNames(name, iface.Peers),
	}
}
