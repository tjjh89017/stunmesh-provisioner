package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

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
//  4. Write cfg.StunmeshConfigPath (mode 0600), or delete it when the
//     new stunmesh text is empty.
//  5. "/etc/init.d/stunmesh reload" when the stunmesh text or any
//     interface changed; "/etc/init.d/stunmesh stop" instead, when the
//     new stunmesh text is empty.
//  6. Write cfg.LastPath (mode 0600, last.Write), only when every step
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
// (network reload, the stunmesh config file, or
// /etc/init.d/stunmesh) leaves UCI committed to the new state but
// last.json still describing the old one. The next fetch recomputes
// the same diff against that stale last.json and retries step 1's
// deletes for sections that this run's commit already removed;
// on a real uci, deleting an already-absent section fails. This is a
// known gap in the procedure PLAN.md 6 defines, not something this
// item introduces or can close within it (see this function's doc
// comment survey in the implementation report). It is also the less
// likely failure window in practice: step 1 is many commands and the
// one most likely to hit a transient error, while commit, reload, the
// config file write, and init.d are each a single, simple operation.
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
func writeUCI(runner execx.Runner, diff *Diff) error {
	for _, id := range diff.Interfaces {
		switch id.Change {
		case InterfaceRemoved:
			if err := runUCIBatch(runner, uci.BuildDelete(id.Sections)); err != nil {
				return fmt.Errorf("delete %s: %w", id.Name, err)
			}
		case InterfaceChanged:
			if err := runUCIBatch(runner, uci.BuildDelete(id.Sections)); err != nil {
				return fmt.Errorf("delete %s: %w", id.Name, err)
			}
			if err := runUCIBatch(runner, uci.BuildInterface(id.Name, *id.Content)); err != nil {
				return fmt.Errorf("create %s: %w", id.Name, err)
			}
		case InterfaceNew:
			if err := runUCIBatch(runner, uci.BuildInterface(id.Name, *id.Content)); err != nil {
				return fmt.Errorf("create %s: %w", id.Name, err)
			}
		case InterfaceUnchanged:
			// Nothing to do: PLAN.md 6's change table has no row for
			// an unchanged interface.
		}
	}
	return nil
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
// "<iface>_r_<n>", peer "<iface>_p_<peer>"). Routes follow iface's own
// slice order, the same order buildRoute in internal/uci assigns
// route indices. Peers are sorted by name, the same order buildPeer
// in internal/uci creates them in (internal/uci's package doc
// "Ordering"), so Sections.Peers reads in the order the agent actually
// created them, as its own doc comment promises.
func sectionsFor(name string, iface bundle.Interface) last.Sections {
	routes := make([]string, len(iface.Routes))
	for n := range iface.Routes {
		routes[n] = fmt.Sprintf("%s_r_%d", name, n)
	}

	peerNames := make([]string, 0, len(iface.Peers))
	for peer := range iface.Peers {
		peerNames = append(peerNames, peer)
	}
	sort.Strings(peerNames)

	peers := make([]string, 0, len(peerNames))
	for _, peer := range peerNames {
		peers = append(peers, name+"_p_"+peer)
	}

	return last.Sections{
		Interface: name,
		Routes:    routes,
		Peers:     peers,
	}
}
