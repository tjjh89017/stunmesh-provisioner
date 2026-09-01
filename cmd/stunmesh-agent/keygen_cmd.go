package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
)

// runKeygen implements `stunmesh-agent keygen`'s flag parsing: only
// --config-dir (default defaultConfigDir), from which it derives
// identity.key's path. keygen never reads config.yaml: it writes
// exactly one file and needs nothing else from it (PLAN.md section 5
// runs keygen before a node is provisioned at all, so config.yaml may
// not even exist yet).
func runKeygen(env *Env, args []string) int {
	fs := flag.NewFlagSet("stunmesh-agent keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configDir := fs.String("config-dir", defaultConfigDir, "directory to write identity.key into")

	if err := fs.Parse(args); err != nil {
		return handleFlagError(env, fs, err)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: keygen: unexpected argument %q\n", fs.Arg(0))
		return ExitError
	}

	if *configDir == "" {
		fmt.Fprintln(env.Stderr, "stunmesh-agent: keygen: --config-dir: must not be empty")
		return ExitError
	}

	return doKeygen(env, filepath.Join(*configDir, "identity.key"))
}

// identityKeyMode is the file mode for the identity private key
// (PLAN.md section 3: "identity private key | One node | Decrypts the
// bundle. Own file, mode 0600."). It is enforced both when a new key
// is generated and when an existing file is reused (see doKeygen), so
// a key file that predates this rule, or was copied in by hand at a
// looser mode, is tightened the next time keygen runs against it.
const identityKeyMode = 0o600

// doKeygen implements `stunmesh-agent keygen` (PLAN.md section 5): make
// an identity key pair, write the private key to path (mode 0600),
// and print the public key to env.Stdout.
//
// # An existing key file is reused, never overwritten
//
// keygen never generates a new key pair when path already holds one:
// it reads the existing key back, prints its public key, and returns
// success. The only change it ever makes to an existing, valid key
// file is to tighten its mode to 0600 if it was looser.
//
// This mirrors stunmesh-provd init's ensureControllerKeyPair
// (cmd/stunmesh-provd/init_cmd.go): both commands treat "the key file
// is already there" as calm, idempotent success, not an error and not
// license to replace it. keygen is deliberately not stricter
// (refusing outright) and not looser (overwriting): PLAN.md 2.3 says
// the identity key "does not change", and it is the one credential
// that lets the controller recognize this specific node. A node that
// silently got a new identity key on a second run, a re-imaged disk
// that kept old files, or any other accident would be cut off from
// the controller until the operator deletes the file and re-registers
// the node's new public key by hand -- a failure that would surface
// far from its cause, at the next fetch. Reusing the existing key
// removes that failure mode: running keygen twice, or a thousand
// times, always reports the same identity, exactly like running init
// twice always reports the same controller key.
//
// If the file exists but does not parse as a valid key, doKeygen
// fails instead of discarding it and writing a fresh key in its
// place: the file might be corrupt, or it might be an unrelated file
// left at the wrong path by mistake, and either way overwriting it
// without the operator noticing risks a second silent identity
// change. The error names the path, never the file's content.
//
// # A new key file is written atomically
//
// When path does not exist, doKeygen generates a new key pair with
// crypto.Keygen and writes it with writeIdentityKeyAtomic, which
// guarantees the file is either absent or fully and correctly written
// at mode 0600 -- never truncated, empty, or briefly at a wider mode --
// even if the process is killed mid-write.
//
// # Output
//
// doKeygen prints exactly one line to env.Stdout: the public key, in
// standard base64 with padding -- the same encoding crypto.Key.String
// returns and the same one stunmesh-provd prints for controller.pub
// and reads back for `node add`'s identity key argument. Nothing else
// goes to env.Stdout, so the operator can pipe this output straight
// into `stunmesh-provd node add <namespace> <node_id>`. The private
// key never appears on env.Stdout, env.Stderr, or in any error
// message.
func doKeygen(env *Env, path string) int {
	priv, err := loadOrCreateIdentityKey(path)
	if err != nil {
		fmt.Fprintf(env.Stderr, "stunmesh-agent: keygen: %v\n", err)
		return ExitError
	}

	pub := crypto.Public(priv)
	fmt.Fprintln(env.Stdout, pub.String())
	return ExitOK
}

// loadOrCreateIdentityKey returns the identity private key at path,
// generating and writing a new one with writeIdentityKeyAtomic if
// path does not yet exist. See doKeygen's doc comment for why an
// existing file is reused rather than replaced. Neither branch's
// error ever includes key material.
func loadOrCreateIdentityKey(path string) (crypto.Key, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, perr := crypto.ParseKey(string(data))
		if perr != nil {
			return crypto.Key{}, fmt.Errorf("%s: existing file is not a valid key, refusing to replace it", path)
		}
		if cerr := os.Chmod(path, identityKeyMode); cerr != nil {
			return crypto.Key{}, fmt.Errorf("chmod %s: %w", path, cerr)
		}
		return key, nil

	case os.IsNotExist(err):
		priv, _, kerr := crypto.Keygen()
		if kerr != nil {
			return crypto.Key{}, fmt.Errorf("generate identity key: %w", kerr)
		}
		if werr := writeIdentityKeyAtomic(path, priv); werr != nil {
			return crypto.Key{}, werr
		}
		return priv, nil

	default:
		return crypto.Key{}, fmt.Errorf("read %s: %w", path, err)
	}
}

// writeIdentityKeyAtomic writes priv to path so that a crash at any
// point leaves path either absent or fully and correctly written --
// never truncated or empty -- and never briefly at a mode wider than
// identityKeyMode.
//
// It first makes path's parent directory (mode 0755) if it does not
// already exist, then writes the key to a temporary file in that
// directory. os.CreateTemp itself creates that file at mode 0600 (equal
// to identityKeyMode) from the instant it exists, before any data is
// written to it; writeIdentityKeyAtomic also chmods it explicitly
// right after creation, the same defensive step store.WriteFile takes
// after its own O_CREATE, so the mode does not depend on
// os.CreateTemp's current behavior staying what it is today. Once the
// temporary file is fully written and synced to storage,
// writeIdentityKeyAtomic links it into place with os.Link.
//
// os.Link only succeeds if path does not already exist, so this also
// closes the race a bare existence check followed by a separate write
// would leave open: two concurrent keygen runs against the same,
// still-absent path can only ever have one winner. The loser's error
// is reported like any other "already exists" case; it never touches
// path.
func writeIdentityKeyAtomic(path string, priv crypto.Key) (err error) {
	dir := filepath.Dir(path)

	// The identity key's default directory, /etc/stunmesh/agent/, does
	// not exist on a fresh OpenWrt install: nothing else on the router
	// creates it. keygen is normally the very first command run
	// against a new node (PLAN.md section 5), so it makes the
	// directory itself rather than requiring a separate provisioning
	// step. 0755 matches /etc/stunmesh/config.yaml's directory; the
	// key file itself stays 0600, set explicitly below and by
	// os.CreateTemp regardless of this directory's mode.
	if merr := os.MkdirAll(dir, 0o755); merr != nil {
		return fmt.Errorf("create directory %s: %w", dir, merr)
	}

	tmp, err := os.CreateTemp(dir, ".identity.key.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary key file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Best effort: remove the temporary file on every return path.
	// After a successful os.Link below, tmpPath is a redundant second
	// directory entry for the same content already safely linked at
	// path, so removing it (or failing to) does not affect
	// correctness -- it is just tidiness.
	defer os.Remove(tmpPath)

	if cerr := tmp.Chmod(identityKeyMode); cerr != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpPath, cerr)
	}

	if _, werr := tmp.WriteString(priv.String() + "\n"); werr != nil {
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

	if lerr := os.Link(tmpPath, path); lerr != nil {
		if os.IsExist(lerr) {
			return fmt.Errorf("%s: already exists", path)
		}
		return fmt.Errorf("link %s: %w", path, lerr)
	}

	return nil
}
