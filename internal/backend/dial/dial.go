// Package dial is the one shared construction point for a
// backend.Store, selected by a resolved backend type (docs/format.md
// section 3). cmd/stunmesh-provd and cmd/stunmesh-agent both go
// through New instead of each keeping its own copy of the type
// switch (a stage 6 code-review finding: the two copies had already
// started to drift in how they wired an HTTP client override and a
// per-request timeout).
//
// dial lives in its own package, not in internal/backend, because
// internal/dhtproxy already imports internal/backend (to implement
// backend.Store); a constructor inside internal/backend that also
// imported dhtproxy would import it back, an import cycle. dial sits
// one level up and imports both, which is not a cycle.
package dial

import (
	"errors"
	"net/http"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/backend"
	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtproxy"
)

// Config selects and configures the backend.Store New builds.
type Config struct {
	// Type is the plugin implementation, e.g. backend.TypeDHTProxy.
	// Any other value makes New return an error.
	Type string

	// Proxies is the list of dhtproxy base URLs. Only meaningful when
	// Type is backend.TypeDHTProxy.
	Proxies []string

	// HTTPClient, when set, overrides the HTTP client the built
	// backend.Store uses for every request -- the seam a test uses to
	// point every proxy call at an httptest.Server instead of the real
	// network. Nil means: use dhtproxy's own default client.
	HTTPClient *http.Client

	// Timeout, when positive, becomes the per-request timeout of the
	// client New builds, unless HTTPClient is also set -- dhtproxy's
	// own WithHTTPClient/WithTimeout precedence rule already resolves
	// that case (WithHTTPClient wins; see internal/dhtproxy.WithTimeout's
	// doc comment), so New passes both options through unconditionally
	// rather than re-implementing the same precedence itself. Zero
	// means: leave dhtproxy's own default timeout in place.
	Timeout time.Duration
}

// New builds the backend.Store cfg selects. It never names cfg.Type's
// actual value in the returned error, so a caller cannot leak an
// operator-supplied (or, for stunmesh-agent, flag-supplied) type
// string into a log line: this is the one construction point every
// backend.Store either binary builds goes through, and a future
// backend type landing here before its case is added must fail
// loudly, not crash or silently pick the wrong implementation.
func New(cfg Config) (backend.Store, error) {
	switch cfg.Type {
	case backend.TypeDHTProxy:
		var opts []dhtproxy.Option
		if cfg.Timeout > 0 {
			opts = append(opts, dhtproxy.WithTimeout(cfg.Timeout))
		}
		if cfg.HTTPClient != nil {
			opts = append(opts, dhtproxy.WithHTTPClient(cfg.HTTPClient))
		}
		return dhtproxy.New(cfg.Proxies, opts...)
	default:
		return nil, errors.New("backend: unknown type")
	}
}
