package dhtkey

import (
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/testvectors"
)

func TestKey(t *testing.T) {
	cases := []struct {
		name      string
		namespace string
		nodeID    string
		want      string
		wantErr   bool
	}{
		{
			name:      "golden vector from testvectors",
			namespace: "test-ns",
			nodeID:    "alpha",
			want:      testvectors.DHTKey(),
		},
		{
			// printf '%s' 'ns/id' | sha1sum
			name:      "hand-computed vector",
			namespace: "ns",
			nodeID:    "id",
			want:      "ffffe098a62c263206dfb7581b04f849a18f25b5",
		},
		{
			name:      "empty namespace",
			namespace: "",
			nodeID:    "alpha",
			wantErr:   true,
		},
		{
			name:      "empty node id",
			namespace: "test-ns",
			nodeID:    "",
			wantErr:   true,
		},
		{
			name:      "slash in namespace",
			namespace: "test/ns",
			nodeID:    "alpha",
			wantErr:   true,
		},
		{
			name:      "slash in node id",
			namespace: "test-ns",
			nodeID:    "al/pha",
			wantErr:   true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Key(c.namespace, c.nodeID)

			if c.wantErr {
				if err == nil {
					t.Fatalf("Key(%q, %q) = %q, want error", c.namespace, c.nodeID, got)
				}
				if strings.Contains(err.Error(), c.namespace) && c.namespace != "" {
					t.Errorf("error %q leaks namespace value %q", err.Error(), c.namespace)
				}
				if strings.Contains(err.Error(), c.nodeID) && c.nodeID != "" {
					t.Errorf("error %q leaks node_id value %q", err.Error(), c.nodeID)
				}
				return
			}

			if err != nil {
				t.Fatalf("Key(%q, %q) returned unexpected error: %v", c.namespace, c.nodeID, err)
			}
			if got != c.want {
				t.Errorf("Key(%q, %q) = %q, want %q", c.namespace, c.nodeID, got, c.want)
			}
		})
	}
}

func TestKeyFormat(t *testing.T) {
	got, err := Key("test-ns", "alpha")
	if err != nil {
		t.Fatalf("Key returned unexpected error: %v", err)
	}
	if len(got) != 40 {
		t.Errorf("len(Key(...)) = %d, want 40", len(got))
	}
	if strings.ToLower(got) != got {
		t.Errorf("Key(...) = %q, want all lowercase", got)
	}
	for _, r := range got {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Errorf("Key(...) = %q contains non-hex character %q", got, r)
			break
		}
	}
}
