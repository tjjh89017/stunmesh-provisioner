package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/backend"
	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtkey"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtproxy"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

const publishUsage = "usage: stunmesh-provd publish [--namespace <ns>] [--once]\n"

// putTimeout bounds one node's DHT put. It wraps the context passed to
// dhtproxy.Client.Put, which fans the put out to every configured
// proxy concurrently, so putTimeout is the worst-case wall-clock cost
// of one node, no matter how many proxies are configured or how many
// of them hang. Without it, a single unresponsive proxy could stall
// the whole publish round forever (stage 2 item 7 requirement).
//
// 30s is generous next to dhtproxy's own default per-request timeout
// (10s, see internal/dhtproxy.defaultTimeout): it lets that default
// apply first in the common case, and only steps in as a backstop
// when a caller-supplied http.Client (Env.HTTPClient, the test seam)
// has no timeout of its own.
const putTimeout = 30 * time.Second

// nodeReport is the outcome of processing one node during a publish
// round. publishRound returns one nodeReport per node it attempted,
// whether the node published successfully or not: a per-node failure
// never stops the round (stage 2 item 7 requirement -- one bad node
// must not abort the others).
//
// Bundle, IdentityPublicKey, and Sealed are exported for stage 2 item
// 8 (the republish loop), which wraps publishRound. Item 8 keeps the
// last round's Bundle and IdentityPublicKey for each node and, when
// neither has changed (bundle.Bundle.Equal already ignores
// timestamp), re-puts the cached Sealed bytes unchanged instead of
// calling publishRound again -- publishRound always produces a fresh
// Sealed value, because crypto.Seal picks a random nonce on every
// call. Bundle, IdentityPublicKey, and Sealed are the zero value when
// Err is non-nil; a caller must check Err first.
type nodeReport struct {
	// Namespace and NodeID identify the node this report is about.
	// NodeID is empty when Err describes a namespace-level failure
	// (for example, provd.yaml itself does not parse) that never got
	// as far as reading any individual node.
	Namespace string
	NodeID    string

	// Key is the DHT key this node publishes under, hex-encoded. It
	// is safe to log: PLAN.md 2.5 only asks that the namespace and
	// node ID that make up the key stay out of error messages, not
	// the derived key itself, and cli.go's node_cmd.go and init_cmd.go
	// already treat public identifiers as safe to print.
	Key string

	// Bundle is the validated inner bundle built for this node this
	// round. See the type doc for how item 8 uses it.
	Bundle *bundle.Bundle
	// IdentityPublicKey is the node's identity.pub this round. See the
	// type doc for how item 8 uses it.
	IdentityPublicKey crypto.Key
	// Sealed is nonce||nacl/box(ciphertext) of Bundle's JSON, put to
	// every proxy this round. See the type doc for how item 8 uses it.
	Sealed []byte

	// Err is non-nil when this node's build, seal, or put failed. It
	// never contains file content, so it is always safe to print.
	Err error
}

// printPublishReport writes one node's outcome. It is the single
// implementation both --once (runPublish, above) and the republish
// loop (runRepublishLoop, republish_loop.go) use, so an operator sees
// identical messages whichever path produced the report and a future
// change to the wording only has to happen once.
func printPublishReport(env *Env, r nodeReport) {
	label := r.Namespace
	if r.NodeID != "" {
		label = r.Namespace + "/" + r.NodeID
	}
	if r.Err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: publish: %s: %v\n", label, r.Err)
		return
	}
	fmt.Fprintf(env.Stdout, "published %s: key=%s\n", label, r.Key)
}

// runPublish implements `stunmesh-provd publish [--namespace <ns>]
// [--once]` (PLAN.md 7.2).
//
// --once runs exactly one publish round and exits; see the exit code
// rule below. Without --once, runPublish runs the republish loop
// (stage 2 item 8, PLAN.md 7.2 step 6, republish_loop.go) until
// SIGINT or SIGTERM, and always exits ExitOK on that clean shutdown --
// a running service being asked to stop is not a failure, whatever a
// node's last round looked like.
//
// Exit code (--once only): ExitOK when every node in the round published
// successfully (including the trivial case of zero nodes to
// publish). ExitError when at least one node failed -- whether it
// failed outright or only reached some of its proxies (a
// *dhtproxy.PartialError) -- and also when the round itself could not
// start (for example, --namespace names a namespace that does not
// exist). A partial success is still a failure: a value that reached
// one of two proxies is not the same as a value that reached both,
// and the operator must be able to tell the difference from the exit
// code alone.
func runPublish(env *Env, args []string) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() { fmt.Fprint(env.Stderr, publishUsage) }

	namespace := fs.String("namespace", "", "publish only this namespace")
	once := fs.Bool("once", false, "run one publish round and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}

	if fs.NArg() > 0 {
		fmt.Fprint(env.Stderr, publishUsage)
		return ExitUsage
	}

	if !*once {
		return runPublishLoop(env, *namespace)
	}

	// --once has no signal handling of its own (unlike the loop, which
	// reacts to SIGINT/SIGTERM via runPublishLoop's signal.NotifyContext):
	// it runs exactly one round and returns, so there is nothing running
	// afterward for a cancellation to interrupt. context.Background()
	// still threads through publishRound into putSealed so every put's
	// timeout is derived the same way in both paths (see putSealed).
	reports, err := publishRound(context.Background(), env, *namespace)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: publish: %v\n", err)
		return ExitError
	}

	failed := 0
	for _, r := range reports {
		if r.Err != nil {
			failed++
		}
		printPublishReport(env, r)
	}

	if failed > 0 {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: publish: %d of %d node(s) failed\n", failed, len(reports))
		return ExitError
	}

	if len(reports) == 0 {
		fmt.Fprintln(env.Stdout, "nothing to publish")
	}
	return ExitOK
}

// publishRound runs one publish round (PLAN.md 7.2): for every
// namespace named by ns (or, when ns is empty, every namespace under
// env.Dir), for every node in it, build the bundle, seal it, compute
// its DHT key, and put it to every proxy in that namespace's
// provd.yaml. now is stamped once for the whole round and passed to
// every buildBundle call, so every node's bundle timestamp agrees and
// the round never calls env.Now() more than once (Env's doc: every
// subcommand stamps timestamps through Now, not time.Now directly).
//
// A round-level error -- ns names a namespace that does not exist, or
// the namespace list itself cannot be read -- stops the round before
// any node is attempted and is returned as err, with a nil reports.
// This is what makes naming a bad --namespace a clear error instead
// of a silent no-op: without this check, store.Namespaces (called
// only when ns is empty) would just never list a name that is not
// there, and a typoed --namespace would report success having
// published nothing.
//
// Once the round is under way, every other failure is scoped to one
// namespace or one node and recorded in that entry's nodeReport.Err
// instead of stopping the round: a broken provd.yaml in one namespace,
// or a bad wg.yaml in one node, must not keep the rest from
// publishing (stage 2 item 7 requirement).
func publishRound(ctx context.Context, env *Env, ns string) ([]nodeReport, error) {
	namespaces, err := resolveNamespaces(env, ns)
	if err != nil {
		return nil, err
	}

	now := env.Now()

	var reports []nodeReport
	for _, namespace := range namespaces {
		reports = append(reports, publishNamespace(ctx, env, namespace, now)...)
	}
	return reports, nil
}

// resolveNamespaces returns the namespaces a round should cover. A
// non-empty ns is checked against store.ReadDeployment first, so a
// namespace that does not exist is reported here, before the round
// starts, rather than silently producing zero reports.
func resolveNamespaces(env *Env, ns string) ([]string, error) {
	if ns == "" {
		return store.Namespaces(env.Dir)
	}
	if _, err := store.ReadDeployment(env.Dir, ns); err != nil {
		return nil, fmt.Errorf("namespace %q: %w", ns, err)
	}
	return []string{ns}, nil
}

// publishNamespace publishes every node in one namespace. It always
// returns at least the reports it could produce: a namespace-level
// failure (an unreadable provd.yaml, an unreadable node list) yields
// one nodeReport with an empty NodeID describing that failure, rather
// than an error, so a bad namespace never keeps publishRound's caller
// from seeing -- and acting on -- the other namespaces in the round.
func publishNamespace(ctx context.Context, env *Env, namespace string, now time.Time) []nodeReport {
	deployment, err := store.ReadDeployment(env.Dir, namespace)
	if err != nil {
		return []nodeReport{{Namespace: namespace, Err: fmt.Errorf("read deployment: %w", err)}}
	}

	nodeIDs, err := store.Nodes(env.Dir, namespace)
	if err != nil {
		if errors.Is(err, store.ErrNotExist) {
			// No nodes/ directory yet: a namespace fresh from `init`
			// legitimately has no nodes. Nothing to publish is not a
			// failure.
			return nil
		}
		return []nodeReport{{Namespace: namespace, Err: fmt.Errorf("list nodes: %w", err)}}
	}

	proxy, err := newDHTProxyClient(env, deployment.Proxies)
	if err != nil {
		return []nodeReport{{Namespace: namespace, Err: fmt.Errorf("dht proxy: %w", err)}}
	}

	reports := make([]nodeReport, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		reports = append(reports, publishNode(ctx, env, proxy, deployment, nodeID, now))
	}
	return reports
}

// newDHTProxyClient builds the backend.Store a namespace's round
// uses. It prefers env.HTTPClient when a test set one (see Env's
// doc), so a test tree points every proxy call at an httptest.Server
// instead of the real network; a production run leaves it nil and
// gets internal/dhtproxy's own client and default per-request
// timeout. It always constructs a dhtproxy.Client directly: a
// selection factory for other backend.Store implementations comes in
// a later item.
func newDHTProxyClient(env *Env, proxies []string) (backend.Store, error) {
	var opts []dhtproxy.Option
	if env.HTTPClient != nil {
		opts = append(opts, dhtproxy.WithHTTPClient(env.HTTPClient))
	}
	return dhtproxy.New(proxies, opts...)
}

// publishNode builds, seals, and puts the bundle for one node (PLAN.md
// 7.2 steps 1-5). It never returns an error directly: every failure is
// recorded on the returned nodeReport's Err field instead, so one bad
// node's problem never stops publishNamespace's loop over the rest.
//
// publishNode always seals fresh, even when nothing changed since the
// last round: it is the building block --once uses, and --once has no
// prior round to compare against. Stage 2 item 8's republish loop
// calls prepareNode and sealAndPutNode directly instead, so it can
// compare the prepared Bundle and IdentityPublicKey against a cached
// prior round before deciding whether to seal again (see
// republish_loop.go).
func publishNode(ctx context.Context, env *Env, proxy backend.Store, deployment *store.Deployment, nodeID string, now time.Time) nodeReport {
	report, node, plain, err := prepareNode(env, deployment, nodeID, now)
	if err != nil {
		return report
	}
	return sealAndPutNode(ctx, proxy, deployment, node, report, plain)
}

// prepareNode reads one node's files, builds and validates its inner
// bundle, and computes its DHT key (PLAN.md 7.2 steps 1-3). It stops
// short of encryption: the returned plain is the exact bundle JSON
// that still needs sealing, and report already carries Namespace,
// NodeID, IdentityPublicKey, Bundle, and Key.
//
// On failure, report.Err is set and returned alongside a non-nil err;
// the caller must return report as-is without calling sealAndPutNode.
// node and plain are only meaningful when err is nil.
func prepareNode(env *Env, deployment *store.Deployment, nodeID string, now time.Time) (report nodeReport, node *store.Node, plain []byte, err error) {
	report = nodeReport{Namespace: deployment.Namespace, NodeID: nodeID}

	node, err = store.ReadNode(env.Dir, deployment.Namespace, nodeID)
	if err != nil {
		report.Err = fmt.Errorf("read node: %w", err)
		return report, nil, nil, report.Err
	}
	report.IdentityPublicKey = node.IdentityPublicKey

	b, err := buildBundle(deployment.Namespace, node, now)
	if err != nil {
		report.Err = err
		return report, nil, nil, report.Err
	}
	report.Bundle = b

	key, err := dhtkey.Key(deployment.Namespace, nodeID)
	if err != nil {
		report.Err = fmt.Errorf("dht key: %w", err)
		return report, nil, nil, report.Err
	}
	report.Key = key

	// Marshal through Bundle's own MarshalJSON, the exact bytes that
	// buildBundle already proved fit under maxInnerBundleSize (it does
	// the same marshal to measure that bound). This is the plaintext
	// that gets sealed; nothing derived from assembledBundle's raw
	// JSON is used here.
	plain, err = json.Marshal(b)
	if err != nil {
		report.Err = fmt.Errorf("marshal bundle: %w", err)
		return report, nil, nil, report.Err
	}

	return report, node, plain, nil
}

// sealAndPutNode seals plain to node's identity key and puts it to
// every proxy under report.Key (PLAN.md 7.2 steps 4-5). report must
// come from a successful prepareNode call for the same node.
func sealAndPutNode(ctx context.Context, proxy backend.Store, deployment *store.Deployment, node *store.Node, report nodeReport, plain []byte) nodeReport {
	// The controller is the sender: it seals with its own private key
	// (deployment.ControllerPrivateKey) and the node's identity public
	// key (node.IdentityPublicKey) as the recipient (PLAN.md 2.4,
	// docs/format.md 3). Getting this order backwards would produce a
	// value only the controller itself could open.
	sealed, err := crypto.Seal(plain, node.IdentityPublicKey, deployment.ControllerPrivateKey)
	if err != nil {
		report.Err = fmt.Errorf("seal: %w", err)
		return report
	}
	report.Sealed = sealed

	if err := putSealed(ctx, proxy, report.Key, sealed); err != nil {
		report.Err = err
		return report
	}
	return report
}

// putSealed puts sealed to every proxy under key (PLAN.md 7.2 step
// 5). It is shared by sealAndPutNode (a freshly sealed value) and
// stage 2 item 8's republish loop (a cached value re-put unchanged).
//
// putTimeout bounds this one put, derived from ctx rather than
// context.Background(): ctx is the cancellable context that reaches
// here from the republish loop's SIGINT/SIGTERM handling (or
// context.Background() from --once, which has nothing to cancel).
// Deriving from ctx means a shutdown signal aborts an in-flight put
// at once instead of waiting out the rest of putTimeout, and a round
// already under way abandons promptly instead of finishing every
// remaining node's full 30s budget first.
//
// dhtproxy.Client.Put base64-encodes its data argument itself (see
// internal/dhtproxy's package doc and Put's payload construction): it
// wraps sealed in {"data": base64(sealed)} before sending. sealed --
// nonce || nacl/box ciphertext, raw bytes -- is passed here unencoded,
// so the wire value ends up as exactly base64(nonce ||
// nacl/box(inner bundle JSON)), matching docs/format.md 3 with no
// double-encoding.
func putSealed(ctx context.Context, proxy backend.Store, key string, sealed []byte) error {
	ctx, cancel := context.WithTimeout(ctx, putTimeout)
	defer cancel()
	if err := proxy.Put(ctx, key, sealed); err != nil {
		return fmt.Errorf("put: %w", err)
	}
	return nil
}
