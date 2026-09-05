package main

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/backend"
	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// fallbackPollInterval is the wait the republish loop uses when no
// namespace exists yet (so there is no configured republish_interval
// to read), or when a namespace's own provd.yaml cannot be read this
// round. It only affects how soon the loop notices an operator has
// finished fixing or creating a namespace; it is not a per-node
// republish period. 5m matches the republish_interval `init` writes
// by default, so an idle controller polls the tree at roughly the
// pace an operator would otherwise expect it to publish.
const fallbackPollInterval = 5 * time.Minute

// nodeKey identifies one node's cache entry across rounds of the
// republish loop.
type nodeKey struct {
	namespace string
	nodeID    string
}

// cacheEntry is what the republish loop keeps in memory for one node,
// across rounds, so it can tell whether the next round's build
// produced the same thing to publish.
//
// bundle and identityPub are compared, not sealed: sealed is what
// gets re-put when they still match.
type cacheEntry struct {
	bundle      *bundle.Bundle
	identityPub crypto.Key
	sealed      []byte
}

// runPublishLoop is the entry point runPublish uses for the republish
// loop (no --once). It owns the process-level concern -- reacting to
// SIGINT/SIGTERM -- and delegates the loop itself to runRepublishLoop,
// which takes a plain context so tests can drive shutdown without
// sending the process a real signal.
func runPublishLoop(env *Env, ns string) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runRepublishLoop(ctx, env, ns)
}

// runRepublishLoop runs publish rounds until ctx is canceled. Each
// round:
//
//  1. re-reads the whole tree (resolveNamespaces, then every
//     namespace's provd.yaml and every one of its nodes) -- so an
//     operator's edit, a node added, or a node removed, is picked up
//     without a restart;
//  2. for each namespace that is due (see below), prepares every
//     node's bundle and either re-puts the cached sealed bytes
//     unchanged, when the node's canonical bundle content and
//     identity.pub both match the last round that sealed it, or
//     seals fresh and caches the result;
//  3. sleeps until the soonest namespace becomes due, or until ctx is
//     canceled, whichever comes first.
//
// A namespace's due time comes from its own provd.yaml
// republish_interval: namespaces are allowed different periods, and
// each is checked against its own schedule, not a global
// one. The loop still re-reads every namespace every round (step 1
// above) so it notices a newly added or removed namespace at once;
// only the decision "publish this namespace now or wait" is
// per-namespace. The wait between rounds is therefore the minimum
// over every known namespace's remaining time, so the loop wakes up
// exactly when the next namespace is due, not before.
//
// A namespace whose provd.yaml cannot be read this round is retried
// after fallbackPollInterval; it does not stop the loop or the other
// namespaces, matching runPublish/publishRound's rule that one bad
// namespace or node never aborts the rest.
//
// A round that ends without a single node to publish prints one
// diagnostic line to stderr every round (see nothingToPublishLine),
// so a controller pointed at an empty or half-provisioned volume does
// not run silently in `docker logs`.
//
// runRepublishLoop returns ExitOK on a clean shutdown (ctx canceled).
// It returns ExitError only when the tree itself cannot be resolved at
// all (for example, --namespace names a namespace that does not
// exist): that can never self-heal by waiting, so the loop stops
// instead of retrying forever. A per-node or per-namespace failure
// within an otherwise valid tree is logged and the loop continues.
func runRepublishLoop(ctx context.Context, env *Env, ns string) int {
	cache := map[nodeKey]cacheEntry{}
	due := map[string]time.Time{}

	for {
		namespaces, err := resolveNamespaces(env, ns)
		if err != nil {
			fmt.Fprintf(env.Stderr, "stunmesh-provd: publish: %v\n", err)
			return ExitError
		}

		now := env.Now()
		nextDue := map[string]time.Time{}
		wait := fallbackPollInterval

		// haveNodes and emptyNamespaces feed nothingToPublishLine below;
		// see that function's doc for what each namespace outcome does
		// to them. Both are computed from the tree's current state, not
		// from whether this round happened to publish the namespace, so
		// a namespace waiting out its own republish_interval never
		// looks "empty" just because this round skipped it.
		haveNodes := false
		var emptyNamespaces []string

		for _, namespace := range namespaces {
			deployment, err := store.ReadDeployment(env.Dir, namespace)
			if err != nil {
				fmt.Fprintf(env.Stderr, "stunmesh-provd: publish: %s: %v\n", namespace, err)
				nextDue[namespace] = now.Add(fallbackPollInterval)
				continue
			}

			switch nodeIDs, nodeErr := store.Nodes(env.Dir, namespace); {
			case nodeErr == nil && len(nodeIDs) > 0:
				haveNodes = true
			case nodeErr == nil || errors.Is(nodeErr, store.ErrNotExist):
				// No nodes/ directory, or one that exists but is empty:
				// either way, this namespace has nothing to publish.
				emptyNamespaces = append(emptyNamespaces, namespace)
			default:
				// An unreadable nodes/ directory is a real failure, not
				// an empty namespace: publishNamespaceCached below
				// reports it (as its own error) on the round(s) this
				// namespace is due, exactly as it always has. Counting
				// it as "have nodes" here only keeps it out of the
				// nothing-to-publish diagnostic, which is for a tree
				// that is legitimately empty, not one that is broken.
				haveNodes = true
			}

			runsAt, seen := due[namespace]
			if !seen || !now.Before(runsAt) {
				for _, report := range publishNamespaceCached(ctx, env, deployment, now, cache) {
					printPublishReport(env, report)
				}
				runsAt = now.Add(deployment.RepublishInterval)
			}
			nextDue[namespace] = runsAt

			if remaining := runsAt.Sub(now); remaining < wait {
				wait = remaining
			}
		}
		due = nextDue
		pruneCache(cache, namespaces)

		if line, ok := nothingToPublishLine(env.Dir, namespaces, haveNodes, emptyNamespaces); ok {
			fmt.Fprintln(env.Stderr, line)
		}

		if wait < 0 {
			wait = 0
		}
		if err := env.Sleep(ctx, wait); err != nil {
			return ExitOK
		}
	}
}

// nothingToPublishLine reports the diagnostic runRepublishLoop prints
// when a round finds nothing to publish anywhere in the tree. ok is
// false when at least one namespace has at least one node, so the
// caller prints nothing.
//
// namespaces empty means env.Dir has no namespace directories at all.
// haveNodes false with a non-empty namespaces means every namespace
// that could be read has no nodes/ directory or an empty one;
// emptyNamespaces names them. A namespace whose provd.yaml or nodes/
// directory failed to read for some other reason is not folded in,
// because its own error already appears in this round's output.
func nothingToPublishLine(dir string, namespaces []string, haveNodes bool, emptyNamespaces []string) (line string, ok bool) {
	if len(namespaces) == 0 {
		return fmt.Sprintf("stunmesh-provd: publish: nothing to publish in %s (no namespaces)", dir), true
	}
	if !haveNodes && len(emptyNamespaces) > 0 {
		return fmt.Sprintf("stunmesh-provd: publish: nothing to publish in %s (no nodes in %s)", dir, strings.Join(emptyNamespaces, ", ")), true
	}
	return "", false
}

// pruneCache drops cache entries for namespaces no longer present in
// the tree, so a removed namespace's nodes do not linger in memory
// forever.
func pruneCache(cache map[nodeKey]cacheEntry, namespaces []string) {
	live := make(map[string]bool, len(namespaces))
	for _, ns := range namespaces {
		live[ns] = true
	}
	for k := range cache {
		if !live[k.namespace] {
			delete(cache, k)
		}
	}
}

// publishNamespaceCached is publishNamespace's counterpart for the
// republish loop: it publishes every node in one namespace, re-putting
// a node's cached sealed bytes when nothing about it changed instead
// of sealing again. deployment is already read, unlike
// publishNamespace, because the loop needs it to compute the
// namespace's due time regardless of whether this round publishes it.
func publishNamespaceCached(ctx context.Context, env *Env, deployment *store.Deployment, now time.Time, cache map[nodeKey]cacheEntry) []nodeReport {
	nodeIDs, err := store.Nodes(env.Dir, deployment.Namespace)
	if err != nil {
		if errors.Is(err, store.ErrNotExist) {
			return nil
		}
		return []nodeReport{{Namespace: deployment.Namespace, Err: fmt.Errorf("list nodes: %w", err)}}
	}

	proxy, err := newBackend(env, deployment.Backend)
	if err != nil {
		return []nodeReport{{Namespace: deployment.Namespace, Err: fmt.Errorf("backend: %w", err)}}
	}

	reports := make([]nodeReport, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		reports = append(reports, publishNodeCached(ctx, env, proxy, deployment, nodeID, now, cache))
	}
	return reports
}

// publishNodeCached is publishNode's counterpart for the republish
// loop. It always prepares the node fresh (build and validate the
// bundle from the current files): a node's files can change between
// rounds, and re-reading them is how the loop notices. What it skips,
// when it can, is sealing and choosing a new nonce: when this round's
// Bundle compares equal, by content (bundle.Bundle.Equal, which
// ignores timestamp), to the cached one, and IdentityPublicKey has
// not changed either, the cached ciphertext is still exactly what a
// node holding that identity key and looking at that content would
// expect, so putting it again is correct and avoids filling the DHT
// key with equivalent-but-distinct values.
//
// A node whose prepareNode fails is not cached: its previous cache
// entry, if any, is left in place, so a transient failure (for
// example, a bad wg.yaml mid-edit) does not erase a good node's
// standing cache entry, and the next successful round can still
// compare against it.
func publishNodeCached(ctx context.Context, env *Env, proxy backend.Store, deployment *store.Deployment, nodeID string, now time.Time, cache map[nodeKey]cacheEntry) nodeReport {
	report, node, plain, err := prepareNode(env, deployment, nodeID, now)
	if err != nil {
		return report
	}

	key := nodeKey{namespace: deployment.Namespace, nodeID: nodeID}
	if prior, ok := cache[key]; ok && prior.identityPub == report.IdentityPublicKey {
		if equal, cmpErr := report.Bundle.Equal(prior.bundle); cmpErr == nil && equal {
			report.Sealed = prior.sealed
			if err := putSealed(ctx, proxy, report.Key, prior.sealed); err != nil {
				report.Err = err
				return report
			}
			return report
		}
	}

	report = sealAndPutNode(ctx, proxy, deployment, node, report, plain)
	if report.Err != nil {
		return report
	}

	cache[key] = cacheEntry{
		bundle:      report.Bundle,
		identityPub: report.IdentityPublicKey,
		sealed:      report.Sealed,
	}
	return report
}
