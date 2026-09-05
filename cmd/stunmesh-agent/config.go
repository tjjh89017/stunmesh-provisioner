package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	stunmeshapp "github.com/tjjh89017/stunmesh-go/app"
	"github.com/tjjh89017/stunmesh-provisioner/internal/backend"
	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/yamlx"
)

// defaultConfigDir is --config-dir's default: the directory
// stunmesh-agent searches for config.yaml, then config.yml, when
// --config is not given. It is also keygen's default directory for
// deriving identity.key's path.
const defaultConfigDir = "/etc/stunmesh/agent"

// defaultLockPath is Config.LockPath's default when config.yaml omits
// "lock".
const defaultLockPath = "/var/lock/stunmesh-agent.lock"

// defaultStunmeshConfigPath is the path the agent writes the bundle's
// stunmesh text to, and the embedded stunmesh-go app's config file,
// when config.yaml omits the whole "stunmesh" section or leaves both
// of its keys unset.
const defaultStunmeshConfigPath = "/etc/stunmesh/config.yaml"

// defaultRefreshInterval and defaultFullApplyInterval are
// "refresh_interval" and "full_apply_interval"'s defaults when
// config.yaml omits them.
const (
	defaultRefreshInterval   = 5 * time.Minute
	defaultFullApplyInterval = 24 * time.Hour
)

// defaultProxies is the built-in dhtproxy list used when config.yaml
// has neither "use_plugin" nor "plugins" (docs/format.md section 3):
// the public Jami dhtproxy instances.
var defaultProxies = []string{
	"https://dhtproxy2.jami.net",
	"https://dhtproxy3.jami.net",
}

// ErrConfigMalformed means config.yaml exists but its content is not
// well-formed: bad YAML, an unknown key, a missing required key, or a
// field that fails its own rule (a bad duration, an invalid key). The
// wrapped detail never includes file content -- only a path and, at
// most, a key name (see parseRawConfig and buildConfig).
var ErrConfigMalformed = errors.New("config: malformed content")

// Config holds every setting the daemon/--oneshot mode needs, after
// config.yaml has been loaded and validated (loadConfig). It is
// distinct from stunmeshapp.Options: that one configures the embedded
// stunmesh-go app (its own config.yaml), not this agent.
type Config struct {
	Namespace        string
	NodeID           string
	ControllerPubkey string

	// RefreshInterval is the daemon's fetch/apply tick. Always
	// positive; a zero or negative value is a config error.
	RefreshInterval time.Duration
	// FullApplyInterval is the daemon's periodic full re-apply tick.
	// Zero disables the periodic full apply entirely; a negative value
	// is a config error.
	FullApplyInterval time.Duration

	IdentityKeyPath string
	LastPath        string
	LockPath        string

	Backend string
	Proxies []string

	Stunmesh StunmeshConfig
}

// StunmeshConfig is the settings the daemon needs to write the
// bundle's `stunmesh` text to disk and to build the embedded
// stunmesh-go app pointed at it.
type StunmeshConfig struct {
	// WritePath is where applyStunmeshConfig writes the bundle's
	// stunmesh text (fetch_apply.go), and always names the same file
	// AppOptions.ConfigFile or AppOptions.ConfigDir would resolve to,
	// so the embedded app always reads what the agent just wrote.
	WritePath string
	// AppOptions is passed to stunmeshapp.New to build (or rebuild) the
	// embedded stunmesh-go app.
	AppOptions stunmeshapp.Options
}

// rawConfig is config.yaml's on-disk shape. Every field is a pointer
// (or, for Plugins, a map whose nilness is itself meaningful) so a
// key's absence is distinguishable from an explicit empty or zero
// value; see buildConfig for how each is resolved to its default.
//
// json tags match config.yaml's documented keys exactly (README.md,
// this repository's top-level CLAUDE.md). Decoding goes through
// yamlx.ToJSON and then encoding/json with DisallowUnknownFields, the
// same strict pattern internal/bundle uses for the wire format, so a
// typo in a key name is rejected rather than silently ignored.
type rawConfig struct {
	Namespace         *string                       `json:"namespace"`
	NodeID            *string                       `json:"node_id"`
	ControllerPubkey  *string                       `json:"controller_pubkey"`
	RefreshInterval   *durationString               `json:"refresh_interval"`
	FullApplyInterval *durationString               `json:"full_apply_interval"`
	IdentityKey       *string                       `json:"identity_key"`
	Last              *string                       `json:"last"`
	Lock              *string                       `json:"lock"`
	UsePlugin         *string                       `json:"use_plugin"`
	Plugins           map[string]backend.PluginSpec `json:"plugins"`
	Stunmesh          *rawStunmesh                  `json:"stunmesh"`
}

// rawStunmesh is config.yaml's "stunmesh" section: the args for the
// embedded stunmesh-go app, not this agent's own config.
type rawStunmesh struct {
	Config    *string `json:"config"`
	ConfigDir *string `json:"config_dir"`
}

// findConfigFile resolves which file loadConfig should read:
// configFile (an exact file, "-c/--config") wins when given; not
// finding it there is an error, since an explicit path is a promise
// the file exists. Otherwise it searches configDir for config.yaml,
// then config.yml; finding neither is not an error -- it returns ""
// -- since a freshly flashed node has no config.yaml yet (this
// mirrors stunmesh-go's own config.Load semantics, per this
// repository's top-level CLAUDE.md).
func findConfigFile(configFile, configDir string) (string, error) {
	if configFile != "" {
		if _, err := os.Stat(configFile); err != nil {
			return "", fmt.Errorf("--config %s: %w", configFile, err)
		}
		return configFile, nil
	}

	for _, name := range []string{"config.yaml", "config.yml"} {
		p := filepath.Join(configDir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", nil
}

// loadConfig reads and validates the full config.yaml at path
// (daemon and --oneshot mode: every field is required or defaulted).
// See loadStunmeshOnlyConfig for the --stunmesh-only mode, which
// tolerates every other section being absent.
func loadConfig(path string) (*Config, error) {
	rc, err := parseRawConfig(path)
	if err != nil {
		return nil, err
	}
	return buildConfig(rc, path)
}

// parseRawConfig reads path and decodes it into a rawConfig, strictly
// (unknown top-level keys are rejected). Its errors never include the
// file's content, only the path and, for an unknown key, the key name
// (from encoding/json's own DisallowUnknownFields message, which never
// echoes a value).
func parseRawConfig(path string) (*rawConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}

	jsonBytes, err := yamlx.ToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: not valid yaml", ErrConfigMalformed, path)
	}

	var rc rawConfig
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rc); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrConfigMalformed, path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: %s: trailing data after the yaml document", ErrConfigMalformed, path)
	}

	return &rc, nil
}

// buildConfig resolves rc (already strictly decoded) into a Config,
// applying every default and rule this package's doc / README.md
// document. configPath is used only to derive IdentityKeyPath's and
// LastPath's own defaults (same directory as config.yaml) and to name
// the file in an error.
func buildConfig(rc *rawConfig, configPath string) (*Config, error) {
	dir := filepath.Dir(configPath)
	cfg := &Config{}

	var missing []string
	if rc.Namespace == nil || *rc.Namespace == "" {
		missing = append(missing, "namespace")
	} else {
		cfg.Namespace = *rc.Namespace
	}
	if rc.NodeID == nil || *rc.NodeID == "" {
		missing = append(missing, "node_id")
	} else {
		cfg.NodeID = *rc.NodeID
	}
	if rc.ControllerPubkey == nil || *rc.ControllerPubkey == "" {
		missing = append(missing, "controller_pubkey")
	} else {
		cfg.ControllerPubkey = *rc.ControllerPubkey
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s: missing required key(s): %s", ErrConfigMalformed, configPath, strings.Join(missing, ", "))
	}

	// crypto.ParseKey's error never echoes its input; wrapping it here
	// still names only the field, never the value.
	if _, err := crypto.ParseKey(cfg.ControllerPubkey); err != nil {
		return nil, fmt.Errorf("%w: %s: controller_pubkey: not a valid key", ErrConfigMalformed, configPath)
	}

	refresh, err := parseDuration(rc.RefreshInterval, defaultRefreshInterval, false, "refresh_interval", configPath)
	if err != nil {
		return nil, err
	}
	if refresh <= 0 {
		return nil, fmt.Errorf("%w: %s: refresh_interval must be positive", ErrConfigMalformed, configPath)
	}
	cfg.RefreshInterval = refresh

	fullApply, err := parseDuration(rc.FullApplyInterval, defaultFullApplyInterval, true, "full_apply_interval", configPath)
	if err != nil {
		return nil, err
	}
	if fullApply < 0 {
		return nil, fmt.Errorf("%w: %s: full_apply_interval must not be negative", ErrConfigMalformed, configPath)
	}
	cfg.FullApplyInterval = fullApply

	cfg.IdentityKeyPath = filepath.Join(dir, "identity.key")
	if rc.IdentityKey != nil && *rc.IdentityKey != "" {
		cfg.IdentityKeyPath = *rc.IdentityKey
	}
	cfg.LastPath = filepath.Join(dir, "last.json")
	if rc.Last != nil && *rc.Last != "" {
		cfg.LastPath = *rc.Last
	}
	cfg.LockPath = defaultLockPath
	if rc.Lock != nil && *rc.Lock != "" {
		cfg.LockPath = *rc.Lock
	}

	cfg.Backend = backend.TypeDHTProxy
	cfg.Proxies = append([]string(nil), defaultProxies...)
	usePlugin := ""
	if rc.UsePlugin != nil {
		usePlugin = *rc.UsePlugin
	}
	if usePlugin != "" || rc.Plugins != nil {
		resolved, err := backend.Resolve(backend.Selection{Plugins: rc.Plugins, UsePlugin: usePlugin})
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrConfigMalformed, configPath, err)
		}
		cfg.Backend = resolved.Type
		cfg.Proxies = resolved.Proxies
	}

	cfg.Stunmesh = resolveStunmeshConfig(rc.Stunmesh)

	return cfg, nil
}

// durationString decodes a YAML/JSON duration value written either
// quoted ("5m", "0") or bare (0): unquoted YAML "0" decodes as the
// JSON number 0, not the string "0", so both spellings are accepted.
type durationString string

func (d *durationString) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*d = durationString(s)
		return nil
	}
	*d = durationString(data)
	return nil
}

// parseDuration parses *s with time.ParseDuration, returning def when
// s is nil. allowZero lets a caller accept "0" (or any duration that
// parses to exactly zero) as a valid value with its own meaning
// (full_apply_interval: 0 disables the periodic full apply); the
// negative-value rule is still enforced by the caller, not here, since
// "negative" means something different for each of the two duration
// settings (an error for both, but buildConfig phrases the two error
// messages separately to match this package's per-field style).
func parseDuration(s *durationString, def time.Duration, allowZero bool, field, configPath string) (time.Duration, error) {
	if s == nil {
		return def, nil
	}
	d, err := time.ParseDuration(string(*s))
	if err != nil {
		return 0, fmt.Errorf("%w: %s: %s: %v", ErrConfigMalformed, configPath, field, err)
	}
	if d == 0 && !allowZero {
		return 0, fmt.Errorf("%w: %s: %s must be positive", ErrConfigMalformed, configPath, field)
	}
	return d, nil
}

// resolveStunmeshConfig builds StunmeshConfig from config.yaml's
// "stunmesh" section (rs may be nil: the whole section is optional).
//
// # Precedence
//
//   - rs.Config set: that exact file is both WritePath (where the
//     agent writes the bundle's stunmesh text) and
//     AppOptions.ConfigFile (what the embedded app reads); the app
//     never needs to search, because the agent just wrote the one
//     file it names.
//   - rs.Config unset, rs.ConfigDir set: WritePath is
//     "<config_dir>/config.yaml" (the app.Options.ConfigDir search
//     order tries config.yaml before config.yml, per stunmesh-go's
//     own config.Load; writing that name first guarantees the app
//     finds exactly what the agent wrote, not a stale config.yml left
//     over from a previous install). AppOptions.ConfigDir is passed
//     through unchanged, so the app still runs its own search if the
//     agent has not written anything there yet (--stunmesh-only mode
//     with no agent loop feeding it, for example).
//   - Neither set (or the whole "stunmesh" section absent):
//     defaultStunmeshConfigPath for both.
func resolveStunmeshConfig(rs *rawStunmesh) StunmeshConfig {
	if rs != nil && rs.Config != nil && *rs.Config != "" {
		return StunmeshConfig{
			WritePath:  *rs.Config,
			AppOptions: stunmeshapp.Options{ConfigFile: *rs.Config},
		}
	}
	if rs != nil && rs.ConfigDir != nil && *rs.ConfigDir != "" {
		return StunmeshConfig{
			WritePath:  filepath.Join(*rs.ConfigDir, "config.yaml"),
			AppOptions: stunmeshapp.Options{ConfigDir: *rs.ConfigDir},
		}
	}
	return StunmeshConfig{
		WritePath:  defaultStunmeshConfigPath,
		AppOptions: stunmeshapp.Options{ConfigFile: defaultStunmeshConfigPath},
	}
}

// loadStunmeshOnlyConfig reads path (when non-empty) and returns just
// its "stunmesh" section, tolerating every other section being absent
// or, if present, simply ignored: --stunmesh-only never needs
// namespace/node_id/controller_pubkey/etc, and config.yaml itself is
// optional in this mode (see findConfigFile). An empty path returns
// the all-defaults StunmeshConfig.
func loadStunmeshOnlyConfig(path string) (StunmeshConfig, error) {
	if path == "" {
		return resolveStunmeshConfig(nil), nil
	}
	rc, err := parseRawConfig(path)
	if err != nil {
		return StunmeshConfig{}, err
	}
	return resolveStunmeshConfig(rc.Stunmesh), nil
}
