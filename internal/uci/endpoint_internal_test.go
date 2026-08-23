package uci

import "testing"

// TestParseEndpoint pins parseEndpoint's rule (see its doc comment):
// SplitHostPort's convention first, a bracket-stripped bare host when
// there is no port, and the string unchanged when there is neither a
// port nor brackets.
func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantHost string
		wantPort string
		wantHas  bool
	}{
		{"host and port", "bravo.example.com:51820", "bravo.example.com", "51820", true},
		{"ipv4 and port", "203.0.113.5:51820", "203.0.113.5", "51820", true},
		{"bracketed ipv6 and port", "[fd00::1]:51820", "fd00::1", "51820", true},
		{"bare host no port", "bravo.example.com", "bravo.example.com", "", false},
		{"bare ipv4 no port", "203.0.113.5", "203.0.113.5", "", false},
		{"bracketed ipv6 no port", "[fd00::1]", "fd00::1", "", false},
		{"bare ipv6 no brackets no port", "fd00::1", "fd00::1", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, hasPort := parseEndpoint(tc.in)
			if host != tc.wantHost || port != tc.wantPort || hasPort != tc.wantHas {
				t.Fatalf("parseEndpoint(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.in, host, port, hasPort, tc.wantHost, tc.wantPort, tc.wantHas)
			}
		})
	}
}
