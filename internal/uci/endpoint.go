package uci

import (
	"net"
	"strings"
)

// parseEndpoint splits a bundle peer's Endpoint field into the
// endpoint_host and endpoint_port UCI options.
//
// Endpoint is `host:port`, with the host bracketed when it is an
// IPv6 literal (`[fd00::1]:51820`), the same convention
// net.JoinHostPort and net.SplitHostPort use. parseEndpoint tries
// net.SplitHostPort first: it already implements that convention
// correctly, including a bracketed IPv6 host with a port.
//
// docs/format.md 6 documents Endpoint as `host:port`, but does not
// forbid a bare host with no port (only a present-but-empty Endpoint
// is rejected, by bundle.Validate, before this package ever sees it).
// When SplitHostPort reports no port -- a bare hostname or IPv4
// address ("bravo.example.com", "203.0.113.5"), or a bracketed IPv6
// literal with no trailing ":port" ("[fd00::1]") -- parseEndpoint
// falls back to treating the whole string as the host, stripping a
// surrounding bracket pair if present, and reports hasPort=false. The
// caller then writes only endpoint_host and omits endpoint_port,
// because there is no port value to invent; UCI has no representation
// for "no port" other than leaving the option unset.
//
// A bare IPv6 literal with no brackets and no port ("fd00::1") cannot
// be split from a would-be port by any rule -- the address itself
// contains colons -- so parseEndpoint returns it unchanged as the
// host, exactly like any other bare host. Endpoint values in practice
// always carry a port (stunmesh-go sets the runtime endpoint itself;
// docs/format.md 6 "usually absent"), so this ambiguous case is not
// expected to occur, but treating it as a bare host is the same
// interpretation net.SplitHostPort would give it, and it never loses
// data: the bytes still land in endpoint_host verbatim.
func parseEndpoint(s string) (host, port string, hasPort bool) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p, true
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") && len(s) >= 2 {
		return s[1 : len(s)-1], "", false
	}
	return s, "", false
}
