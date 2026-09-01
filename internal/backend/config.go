package backend

import "errors"

// Selection is the "plugins" map plus "use_plugin" selector shape
// (docs/format.md section 3). It is shared by provd.yaml
// (internal/store) and stunmesh-agent's config.yaml
// (cmd/stunmesh-agent), which both name a backend the same way.
type Selection struct {
	// Plugins maps a plugin name (the operator's own label) to its
	// definition. A nil map means the key is absent from the source
	// document; an empty, non-nil map means it was present but empty.
	Plugins map[string]PluginSpec `json:"plugins,omitempty"`
	// UsePlugin names the entry in Plugins this deployment uses.
	UsePlugin string `json:"use_plugin,omitempty"`
	// Proxies is the retired top-level "proxies" shorthand. Its mere
	// presence (non-nil, even if empty) is itself a Resolve error; see
	// Resolve.
	Proxies []string `json:"proxies,omitempty"`
}

// PluginSpec is one entry in a Selection's Plugins map.
type PluginSpec struct {
	// Type selects the plugin implementation. Only TypeDHTProxy exists.
	Type string `json:"type,omitempty"`
	// Proxies is the list of dhtproxy base URLs. Required when Type is
	// TypeDHTProxy.
	Proxies []string `json:"proxies,omitempty"`
}

// Resolved is the outcome of a successful Resolve: the plugin type
// and its settings.
type Resolved struct {
	Type    string
	Proxies []string
}

// Resolve validates and resolves s into a Resolved, applying the
// rules docs/format.md section 3 lists. It is the one place that
// interprets a "plugins"/"use_plugin" Selection; internal/store's
// ReadDeployment and stunmesh-agent's config loader both call it and
// wrap its error with their own sentinel error and file path, so the
// two never drift on what counts as malformed.
//
// Resolve's own error text names only the failing key -- never a
// plugin name, a type string, or a URL from s -- so a caller can wrap
// it directly without re-checking that rule itself.
func Resolve(s Selection) (Resolved, error) {
	hasProxies := s.Proxies != nil
	hasPlugins := s.Plugins != nil
	hasUsePlugin := s.UsePlugin != ""

	switch {
	case hasProxies:
		// A top-level "proxies" list is a retired shorthand form; it is
		// no longer a valid key at all. Point the operator at the one
		// remaining form instead of silently ignoring the list.
		return Resolved{}, errors.New("top-level proxies is no longer supported: move the list into a plugins entry (see docs/format.md section 3)")
	case !hasPlugins:
		return Resolved{}, errors.New("plugins is required")
	case !hasUsePlugin:
		return Resolved{}, errors.New("use_plugin is required")
	default:
		plugin, ok := s.Plugins[s.UsePlugin]
		if !ok {
			return Resolved{}, errors.New("use_plugin names a missing plugins entry")
		}
		if plugin.Type != TypeDHTProxy {
			return Resolved{}, errors.New("unknown plugin type")
		}
		if len(plugin.Proxies) == 0 {
			return Resolved{}, errors.New("plugins.*.proxies is required for a dhtproxy plugin")
		}
		return Resolved{Type: TypeDHTProxy, Proxies: plugin.Proxies}, nil
	}
}
