package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
)

// Config holds every setting fetch or keygen needs, after flags and
// --config have been merged (see resolveConfig). Which fields are
// actually required differs by command; ValidateFetch and
// ValidateKeygen each check their own subset.
type Config struct {
	Namespace          string
	NodeID             string
	ControllerPubkey   string
	Proxies            []string
	IdentityKeyPath    string
	LastPath           string
	LockPath           string
	StunmeshConfigPath string
}

// Default paths and proxies (PLAN.md section 3). A flag or --config
// setting overrides its default; see resolveConfig.
const (
	defaultLastPath           = "/etc/stunmesh/provd/last.json"
	defaultLockPath           = "/var/lock/stunmesh-agent.lock"
	defaultStunmeshConfigPath = "/etc/stunmesh/config.yaml"
)

// defaultProxies is DHT_PROXY's default (PLAN.md section 3): the
// public Jami dhtproxy instances. fetch uses this list only when
// neither a --proxy flag nor a config file "proxy" line supplies any
// proxy at all.
var defaultProxies = []string{
	"https://dhtproxy2.jami.net",
	"https://dhtproxy3.jami.net",
}

// defaultProxiesText is defaultProxies rendered for the usage text.
var defaultProxiesText = strings.Join(defaultProxies, ", ")

// flagSeam bundles the pieces registerFlags wires up that resolveConfig
// needs after fs.Parse: cfg is filled in directly by the flag package,
// configPath is where --config's argument lands, and fs itself is
// kept so resolveConfig can call fs.Visit to see which flags the
// caller actually passed (as opposed to a flag sitting at its zero or
// default value because it was never mentioned).
type flagSeam struct {
	fs         *flag.FlagSet
	cfg        *Config
	configPath *string
}

// registerFlags adds every stunmesh-agent flag (PLAN.md section 3,
// stage 3 item 1) to fs and returns the seam resolveConfig needs to
// finish building a Config. fetch and keygen both call this: they
// accept the same flag set and differ only in which settings they
// require (see ValidateFetch, ValidateKeygen).
func registerFlags(fs *flag.FlagSet) *flagSeam {
	cfg := &Config{}

	fs.StringVar(&cfg.Namespace, "namespace", "", "deployment namespace")
	fs.StringVar(&cfg.NodeID, "node-id", "", "this node's ID")
	fs.StringVar(&cfg.ControllerPubkey, "controller-pubkey", "", "controller public key, base64")
	fs.Var(&proxyFlag{&cfg.Proxies}, "proxy", "dhtproxy base URL (repeatable)")
	fs.StringVar(&cfg.IdentityKeyPath, "identity-key", "", "node identity private key file")
	fs.StringVar(&cfg.LastPath, "last", defaultLastPath, "last-applied bundle file")
	fs.StringVar(&cfg.LockPath, "lock", defaultLockPath, "lock file")
	fs.StringVar(&cfg.StunmeshConfigPath, "stunmesh-config", defaultStunmeshConfigPath, "stunmesh-go config file")

	configPath := fs.String("config", "", "flat key=value file supplying any of the settings above")

	return &flagSeam{fs: fs, cfg: cfg, configPath: configPath}
}

// proxyFlag implements flag.Value for a repeatable --proxy flag. Each
// occurrence appends one URL to *values, in the order given on the
// command line.
type proxyFlag struct {
	values *[]string
}

func (p *proxyFlag) String() string {
	if p == nil || p.values == nil {
		return ""
	}
	return strings.Join(*p.values, ",")
}

func (p *proxyFlag) Set(v string) error {
	if v == "" {
		return errors.New("proxy: must not be empty")
	}
	*p.values = append(*p.values, v)
	return nil
}

// resolveConfig finishes building the Config that seam's fs.Parse
// already started: it merges in --config's settings, then the
// package defaults, and returns the result.
//
// # Precedence
//
// An explicit flag always wins over the same setting in --config. A
// setting that neither supplies falls back to its default (--last,
// --lock, --stunmesh-config already carry theirs from registerFlags;
// --proxy falls back to defaultProxies).
//
// This is the least surprising rule for the two deployments PLAN.md
// section 3 and 5 describe. On OpenWrt, the init.d script reads UCI
// and always launches stunmesh-agent with flags built from the
// current UCI state; it never writes a --config file. A flag there is
// the freshest, most specific expression of "what to do right now",
// so it must win. On another system, an operator (or a wrapper
// script) using --config expects an explicit flag on the same
// invocation to be a deliberate one-off override of the file, the
// normal shape of "flag beats config file" in most CLIs -- not the
// reverse, which would make a file silently unoverridable without
// editing it.
//
// resolveConfig tells "a flag was explicitly given" apart from "a
// flag sits at its zero-value default" with fs.Visit, which the flag
// package documents as visiting only flags that were actually set on
// the command line. This is why --last, --lock, and
// --stunmesh-config's defaults are registered directly on the flag
// (registerFlags), rather than applied here: an unset --last flag
// still reads as defaultLastPath after fs.Parse, and fs.Visit
// correctly leaves it out of the visited set either way, so --config
// (and, failing that, the package default already sitting in the
// field) still gets a chance to apply.
func resolveConfig(seam *flagSeam) (*Config, error) {
	cfg := seam.cfg

	set := map[string]bool{}
	seam.fs.Visit(func(f *flag.Flag) {
		set[f.Name] = true
	})

	if *seam.configPath != "" {
		data, err := os.ReadFile(*seam.configPath)
		if err != nil {
			return nil, fmt.Errorf("--config %s: %w", *seam.configPath, err)
		}
		fc, err := parseConfigFile(strings.NewReader(string(data)))
		if err != nil {
			return nil, fmt.Errorf("--config %s: %w", *seam.configPath, err)
		}
		applyFileConfig(cfg, fc, set)
	}

	if !set["proxy"] && len(cfg.Proxies) == 0 {
		cfg.Proxies = append([]string(nil), defaultProxies...)
	}

	return cfg, nil
}

// applyFileConfig copies each setting fc carries into cfg, skipping
// any field whose flag was explicitly given (set[name] is true): that
// is the precedence rule resolveConfig documents. proxy is handled
// separately: fc.Proxies is used whole, in file order, only when the
// --proxy flag was never given at all; a --config "proxy" line never
// merges with --proxy flag values, so the effective list is always
// exactly one source's list, never a mix of two.
func applyFileConfig(cfg *Config, fc *fileConfig, set map[string]bool) {
	if !set["namespace"] && fc.Namespace != nil {
		cfg.Namespace = *fc.Namespace
	}
	if !set["node-id"] && fc.NodeID != nil {
		cfg.NodeID = *fc.NodeID
	}
	if !set["controller-pubkey"] && fc.ControllerPubkey != nil {
		cfg.ControllerPubkey = *fc.ControllerPubkey
	}
	if !set["identity-key"] && fc.IdentityKey != nil {
		cfg.IdentityKeyPath = *fc.IdentityKey
	}
	if !set["last"] && fc.Last != nil {
		cfg.LastPath = *fc.Last
	}
	if !set["lock"] && fc.Lock != nil {
		cfg.LockPath = *fc.Lock
	}
	if !set["stunmesh-config"] && fc.StunmeshConfig != nil {
		cfg.StunmeshConfigPath = *fc.StunmeshConfig
	}
	if !set["proxy"] && len(fc.Proxies) > 0 {
		cfg.Proxies = append([]string(nil), fc.Proxies...)
	}
}

// fileConfig is the result of parsing a --config file (parseConfigFile).
// Every field is a pointer so a key's absence (nil) is distinguishable
// from an explicit empty value (a non-nil pointer to ""); Proxies is
// the exception, since its own zero value, nil, already means
// "absent" (an empty slice cannot appear here: every "proxy" line
// carries a non-empty value, see proxyFlag.Set and the same rule
// enforced in parseConfigFile).
type fileConfig struct {
	Namespace        *string
	NodeID           *string
	ControllerPubkey *string
	IdentityKey      *string
	Last             *string
	Lock             *string
	StunmeshConfig   *string
	Proxies          []string
}

// configFileKeys are the only keys parseConfigFile accepts. Anything
// else is a mistake -- most likely a typo of one of these -- and is
// rejected rather than silently ignored.
var configFileKeys = map[string]bool{
	"namespace":         true,
	"node_id":           true,
	"controller_pubkey": true,
	"proxy":             true,
	"identity_key":      true,
	"last":              true,
	"lock":              true,
	"stunmesh_config":   true,
}

// parseConfigFile reads stunmesh-agent's flat --config file grammar
// from r:
//
//   - One setting per line, "key=value".
//   - A blank line (empty, or whitespace only) is ignored.
//   - A line whose first non-whitespace character is "#" is a
//     comment; it is ignored, in full, whatever else is on it.
//   - Leading and trailing whitespace around both key and value is
//     trimmed. The value is otherwise taken literally: no quoting, no
//     escaping, no continuation lines.
//   - The key must be one of: namespace, node_id, controller_pubkey,
//     proxy, identity_key, last, lock, stunmesh_config. Any other key
//     is rejected -- most likely it is a typo of one of these.
//   - "proxy" may appear more than once; each occurrence adds one URL
//     to the list, in file order. Every other key may appear at most
//     once; a repeat is rejected, since a second value for the same
//     setting almost always means the file was edited by hand and
//     something was left behind by mistake, not that the second value
//     should silently replace the first.
//   - A non-blank, non-comment line with no "=" is rejected as
//     malformed.
//   - An empty value (e.g. "namespace=") is rejected: every one of
//     these keys names a required-when-present setting, so an empty
//     value can only be an editing mistake, never a deliberate
//     "unset".
//
// Every error names the line number and, where it applies, the key --
// never the value, so a mistake in controller_pubkey or identity_key
// is never echoed back.
func parseConfigFile(r io.Reader) (*fileConfig, error) {
	fc := &fileConfig{}
	seen := map[string]bool{}

	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		idx := strings.IndexByte(trimmed, '=')
		if idx < 0 {
			return nil, fmt.Errorf("line %d: malformed line, expected key=value", lineNo)
		}

		key := strings.TrimSpace(trimmed[:idx])
		value := strings.TrimSpace(trimmed[idx+1:])

		if key == "" {
			return nil, fmt.Errorf("line %d: malformed line, expected key=value", lineNo)
		}
		if !configFileKeys[key] {
			return nil, fmt.Errorf("line %d: unknown key %q", lineNo, key)
		}
		if value == "" {
			return nil, fmt.Errorf("line %d: %s: value must not be empty", lineNo, key)
		}

		if key == "proxy" {
			fc.Proxies = append(fc.Proxies, value)
			continue
		}

		if seen[key] {
			return nil, fmt.Errorf("line %d: %s: given more than once", lineNo, key)
		}
		seen[key] = true

		switch key {
		case "namespace":
			fc.Namespace = &value
		case "node_id":
			fc.NodeID = &value
		case "controller_pubkey":
			fc.ControllerPubkey = &value
		case "identity_key":
			fc.IdentityKey = &value
		case "last":
			fc.Last = &value
		case "lock":
			fc.Lock = &value
		case "stunmesh_config":
			fc.StunmeshConfig = &value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	return fc, nil
}

// ValidateFetch reports whether cfg has everything `fetch` needs
// (PLAN.md section 5's fetch row). It does not touch the network or
// the filesystem; it only checks the settings themselves.
func (cfg *Config) ValidateFetch() error {
	var missing []string
	if cfg.Namespace == "" {
		missing = append(missing, "--namespace")
	}
	if cfg.NodeID == "" {
		missing = append(missing, "--node-id")
	}
	if cfg.ControllerPubkey == "" {
		missing = append(missing, "--controller-pubkey")
	}
	if cfg.IdentityKeyPath == "" {
		missing = append(missing, "--identity-key")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required setting(s): %s", strings.Join(missing, ", "))
	}

	// crypto.ParseKey's error never echoes its input (see its doc
	// comment), so wrapping it here still names only the field, never
	// the value.
	if _, err := crypto.ParseKey(cfg.ControllerPubkey); err != nil {
		return fmt.Errorf("--controller-pubkey: not a valid key")
	}

	if len(cfg.Proxies) == 0 {
		return errors.New("no proxy configured")
	}
	for _, p := range cfg.Proxies {
		if p == "" {
			return errors.New("--proxy: must not be empty")
		}
	}

	if cfg.LastPath == "" {
		return errors.New("--last: must not be empty")
	}
	if cfg.LockPath == "" {
		return errors.New("--lock: must not be empty")
	}
	if cfg.StunmeshConfigPath == "" {
		return errors.New("--stunmesh-config: must not be empty")
	}

	return nil
}

// ValidateKeygen reports whether cfg has everything `keygen` needs
// (PLAN.md section 5's keygen row). keygen only ever writes one file,
// the identity key, so it needs nothing else: not --namespace,
// --node-id, --controller-pubkey, --proxy, --last, --lock, or
// --stunmesh-config.
func (cfg *Config) ValidateKeygen() error {
	if cfg.IdentityKeyPath == "" {
		return errors.New("missing required setting: --identity-key")
	}
	return nil
}
