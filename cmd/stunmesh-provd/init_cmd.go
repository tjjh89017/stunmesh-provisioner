package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/store"
)

// rootReadme is the content of <root>/README.md (PLAN.md 7.1, 7.3).
// It is operator-facing documentation, so it stays in ASD-STE100
// style: short sentences, active voice, one instruction per sentence.
const rootReadme = `# stunmesh-provd provisioning tree

This directory holds the configuration for one or more stunmesh
deployments. stunmesh-provd reads and writes the files under it.

## Layout

One subdirectory is one namespace. A namespace is one independent
deployment:

    <root>/
    ├── README.md              this file
    └── <namespace>/
        ├── provd.yaml         deployment settings: backend plugin, republish interval
        ├── controller.key     controller private key (SECRET)
        ├── controller.pub     controller public key
        └── nodes/
            └── <node_id>/
                ├── identity.pub    node identity public key
                ├── wg.yaml         WireGuard settings for this node (SECRET)
                └── stunmesh.yaml   stunmesh-go settings for this node

## Secret files

Some files hold private key material or other secrets. Protect them:

- ` + "`controller.key`" + ` holds the controller private key. Every node in the
  namespace trusts data signed with this key. Never copy it off the
  controller. Never log it or paste it anywhere.
- ` + "`wg.yaml`" + ` holds the node's WireGuard tunnel private key. Treat it
  with the same care as ` + "`controller.key`" + `.

Every other file is safe to view, copy, or send over a plain channel.

## Files the operator edits

stunmesh-provd never edits an operator file after it first creates it.
The operator is free to edit these files by hand between publish
rounds:

- ` + "`provd.yaml`" + `: change the backend plugin's proxy list or the republish interval.
- ` + "`wg.yaml`" + `: change the WireGuard settings for one node.
- ` + "`stunmesh.yaml`" + `: change the stunmesh-go settings for one node.

Do not edit ` + "`controller.key`" + `, ` + "`controller.pub`" + `, or ` + "`identity.pub`" + ` by
hand. stunmesh-provd generates the key files; the operator only
copies ` + "`identity.pub`" + ` in from the node at node init.
`

// defaultProvdYAML is the content of <namespace>/provd.yaml that
// `init` writes for a new namespace (PLAN.md 7.1, 7.3). It uses the
// "plugins" map + "use_plugin" selector form (docs/format.md section
// 3), the only form the store package accepts: a top-level "proxies"
// key is rejected as malformed.
const defaultProvdYAML = `plugins:
  dht:
    type: dhtproxy
    proxies:
      - https://dhtproxy2.jami.net
      - https://dhtproxy3.jami.net
use_plugin: dht
republish_interval: 5m
`

// rootDirMode is the mode for the provisioning root. The root itself
// holds no secret directly -- only files inside a namespace
// subdirectory do -- so a normal, world-readable directory mode is
// enough; the namespace subdirectories carry the tighter mode.
const rootDirMode = 0o755

// namespaceDirMode is the mode for a namespace directory. A namespace
// directory holds controller.key, a secret, directly inside it, so it
// gets the tighter mode store.CreateDir's doc recommends for a
// directory that holds a secret file.
const namespaceDirMode = 0o700

// runInit implements `stunmesh-provd init [<namespace>]` (PLAN.md
// 7.3). It is safe to run more than once against the same root: every
// step it takes treats "already there" as success, and it never
// generates a new controller key pair over an existing
// controller.key.
func runInit(env *Env, args []string) int {
	if len(args) > 1 {
		fmt.Fprint(env.Stderr, "usage: stunmesh-provd init [<namespace>]\n")
		return ExitUsage
	}

	namespace := ""
	if len(args) == 1 {
		namespace = args[0]
	}

	if err := store.CreateDir(env.Dir, rootDirMode); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: init: %v\n", err)
		return ExitError
	}

	readmePath := filepath.Join(env.Dir, "README.md")
	if err := store.WriteFile(readmePath, []byte(rootReadme), 0o644); err != nil {
		if !errors.Is(err, store.ErrExists) {
			fmt.Fprintf(env.Stderr, "stunmesh-provd: init: %v\n", err)
			return ExitError
		}
		fmt.Fprintf(env.Stdout, "README.md already exists, left unchanged\n")
	} else {
		fmt.Fprintf(env.Stdout, "wrote %s\n", readmePath)
	}

	if namespace == "" {
		generated, err := randomNamespace(env.Rand)
		if err != nil {
			fmt.Fprintf(env.Stderr, "stunmesh-provd: init: %v\n", err)
			return ExitError
		}
		namespace = generated
	}

	nsDir, err := store.ResolveName(env.Dir, namespace)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: init: %v\n", err)
		return ExitError
	}

	if err := store.CreateDir(nsDir, namespaceDirMode); err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: init: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(env.Stdout, "namespace %s: %s\n", namespace, nsDir)

	provdPath := filepath.Join(nsDir, "provd.yaml")
	if err := store.WriteFile(provdPath, []byte(defaultProvdYAML), 0o644); err != nil {
		if !errors.Is(err, store.ErrExists) {
			fmt.Fprintf(env.Stderr, "stunmesh-provd: init: %v\n", err)
			return ExitError
		}
		fmt.Fprintf(env.Stdout, "provd.yaml already exists, left unchanged\n")
	} else {
		fmt.Fprintf(env.Stdout, "wrote %s\n", provdPath)
	}

	pub, keyStatus, err := ensureControllerKeyPair(nsDir)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-provd: init: %v\n", err)
		return ExitError
	}
	switch keyStatus {
	case keyStatusCreated:
		fmt.Fprintf(env.Stdout, "generated controller key pair, public key: %s\n", pub.String())
	case keyStatusAlreadyExisted:
		fmt.Fprintf(env.Stdout, "controller.key already exists, left unchanged, public key: %s\n", pub.String())
	}

	return ExitOK
}

// keyStatus reports what ensureControllerKeyPair did.
type keyStatus int

const (
	keyStatusCreated keyStatus = iota
	keyStatusAlreadyExisted
)

// ensureControllerKeyPair makes sure nsDir has a matching
// controller.key and controller.pub, generating a new pair only when
// controller.key is absent.
//
// Order of operations matters here: a re-run must never generate a
// fresh key pair on top of an existing controller.key, and it must
// never leave a controller.pub that does not match the
// controller.key on disk.
//
//  1. If controller.key already exists, read and parse it. Do not
//     generate anything. Derive the public key from it with
//     crypto.Public.
//  2. If controller.key does not exist, generate a new pair with
//     crypto.Keygen and write controller.key (mode 0600) first. Only
//     after that write succeeds does the private key in step 3 come
//     from the newly generated pair.
//  3. Write controller.pub (mode 0644) derived from whichever private
//     key is now the one of record (either just-read or
//     just-generated). store.WriteFile never overwrites, so an
//     existing controller.pub is left untouched.
//
// This order makes a partial failure self-healing rather than
// dangerous: if the process dies after step 2 but before step 3, the
// next run takes the "already exists" branch of step 1, reads the
// same private key back, and (re)writes a controller.pub derived from
// that same key -- it can never produce a mismatched pair. The one
// failure mode this cannot fix is controller.key being lost or
// replaced by hand after being written; that is an operator error
// outside init's control, not a partial-failure case.
func ensureControllerKeyPair(nsDir string) (pub crypto.Key, status keyStatus, err error) {
	keyPath := filepath.Join(nsDir, "controller.key")
	pubPath := filepath.Join(nsDir, "controller.pub")

	priv, err := readControllerKey(keyPath)
	switch {
	case err == nil:
		status = keyStatusAlreadyExisted
	case errors.Is(err, os.ErrNotExist):
		priv, _, err = crypto.Keygen()
		if err != nil {
			return crypto.Key{}, 0, fmt.Errorf("generate controller key pair: %w", err)
		}
		if werr := store.WriteFile(keyPath, []byte(priv.String()+"\n"), 0o600); werr != nil {
			// Do not treat ErrExists as calm here: readControllerKey
			// just reported this same path as absent, so a
			// concurrent writer raced us. Report it rather than
			// silently discarding the key we just generated.
			return crypto.Key{}, 0, fmt.Errorf("write %s: %w", keyPath, werr)
		}
		status = keyStatusCreated
	default:
		return crypto.Key{}, 0, err
	}

	pub = crypto.Public(priv)

	if werr := store.WriteFile(pubPath, []byte(pub.String()+"\n"), 0o644); werr != nil {
		if !errors.Is(werr, store.ErrExists) {
			return crypto.Key{}, 0, fmt.Errorf("write %s: %w", pubPath, werr)
		}
		// controller.pub already exists. store.WriteFile never
		// overwrote it, so it is left exactly as it was.
	}

	return pub, status, nil
}

// readControllerKey reads and parses path as a controller private
// key. A missing file is reported as os.ErrNotExist (via errors.Is)
// so the caller can tell "generate a new pair" apart from a real
// failure. The returned error never includes the file content.
func readControllerKey(path string) (crypto.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return crypto.Key{}, fmt.Errorf("%s: %w", path, os.ErrNotExist)
		}
		return crypto.Key{}, fmt.Errorf("read %s: %w", path, err)
	}
	key, err := crypto.ParseKey(string(data))
	if err != nil {
		return crypto.Key{}, fmt.Errorf("%s: not a valid key", path)
	}
	return key, nil
}

// randomNamespace makes a random namespace name from r. The name is
// lowercase hex, so it can never contain "/" or start with ".": both
// store.ResolveName and dhtkey.Key reject those. Standard and URL
// base64 were considered and rejected: standard base64 can produce
// "/" and "+", and even base64url's "-" and "_" buy nothing over hex
// here for a name this short, while hex keeps the result trivially
// safe and easy to read aloud or type by hand during node init.
//
// 8 random bytes (16 hex characters) give 64 bits of entropy, ample
// to make the DHT key hard to guess (PLAN.md 2.5) without producing
// an unwieldy directory name.
func randomNamespace(r io.Reader) (string, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("generate random namespace: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
