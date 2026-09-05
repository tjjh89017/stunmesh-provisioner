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
// exactly one file and needs nothing else from it, so it runs before
// a node is provisioned at all, even when config.yaml does not exist
// yet.
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

// identityKeyMode is the file mode for the identity private key. It
// is enforced both when a new key is generated and when an existing
// file is reused (see doKeygen), so a key file that predates this
// rule, or was copied in by hand at a looser mode, is tightened the
// next time keygen runs against it.
const identityKeyMode = 0o600

// doKeygen implements `stunmesh-agent keygen`: make an identity key
// pair, write the private key to path (mode 0600), and print the
// public key to env.Stdout.
//
// An existing key file is reused and its mode tightened to 0600, so
// running keygen twice never changes the node's identity. A file that
// does not parse as a valid key is an error, never overwritten: the
// error names the path, never the file's content.
//
// When path does not exist, doKeygen generates a new key pair with
// crypto.Keygen and writes it with writeIdentityKeyAtomic, which
// guarantees the file is either absent or fully and correctly written
// at mode 0600 -- never truncated, empty, or briefly at a wider mode --
// even if the process is killed mid-write.
//
// Prints the public key alone, so it can be piped into
// `stunmesh-provd node add`. The private key never appears on
// env.Stdout, env.Stderr, or in any error message.
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
// would leave open.
func writeIdentityKeyAtomic(path string, priv crypto.Key) (err error) {
	dir := filepath.Dir(path)

	// The identity key's default directory, /etc/stunmesh/agent/, does
	// not exist on a fresh OpenWrt install, so keygen makes it itself.
	// 0755 matches /etc/stunmesh/config.yaml's directory; the key file
	// itself stays 0600, set explicitly below and by os.CreateTemp
	// regardless of this directory's mode.
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
	defer func() { _ = os.Remove(tmpPath) }()

	if cerr := tmp.Chmod(identityKeyMode); cerr != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpPath, cerr)
	}

	if _, werr := tmp.WriteString(priv.String() + "\n"); werr != nil {
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

	if lerr := os.Link(tmpPath, path); lerr != nil {
		if os.IsExist(lerr) {
			return fmt.Errorf("%s: already exists", path)
		}
		return fmt.Errorf("link %s: %w", path, lerr)
	}

	return nil
}
