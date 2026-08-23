package last_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// intPtr and strPtr build the pointer fields bundle.Interface and
// bundle.Peer use to keep "absent" and "explicit empty" distinguishable.
func intPtr(v int) *int       { return &v }
func strPtr(v string) *string { return &v }

func sampleState() *last.State {
	return &last.State{
		Version: last.CurrentVersion,
		WG: map[string]last.Interface{
			"wg0": {
				Sections: last.Sections{
					Interface: "wg0",
					Routes:    []string{"wg0_r_0"},
					Peers:     []string{"wg0_p_bravo"},
				},
				Content: bundle.Interface{
					PrivateKey: "cHJpdmF0ZS1rZXk=",
					ListenPort: intPtr(51820),
					Addresses:  []string{"10.0.0.1/24"},
					// Routes is present-and-empty on purpose: it pins
					// down that Write/Read must not collapse an
					// explicit empty list to absent (see
					// TestReadWrite_PresenceSurvivesRoundTrip).
					Routes:  []bundle.Route{},
					Options: map[string]string{},
					Peers: map[string]bundle.Peer{
						"bravo": {
							PublicKey:  "cHVibGljLWtleQ==",
							AllowedIPs: []string{"10.0.0.2/32"},
							Endpoint:   strPtr("bravo.example.com:51820"),
						},
					},
				},
			},
		},
		Stunmesh: "interfaces:\n  wg0: {}\n",
	}
}

func TestReadWrite_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")

	want := sampleState()
	if err := last.Write(path, want); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := last.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	gotJSON, err := jsonOf(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	wantJSON, err := jsonOf(want)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("round trip mismatch:\n got:  %s\n want: %s", gotJSON, wantJSON)
	}
}

func TestRead_MissingFileIsEmptyState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.json")

	got, err := last.Read(path)
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("Read: got nil state for a missing file")
	}
	if len(got.WG) != 0 {
		t.Fatalf("Read: got %d interfaces for a missing file, want 0", len(got.WG))
	}
	if got.Stunmesh != "" {
		t.Fatalf("Read: got non-empty stunmesh %q for a missing file", got.Stunmesh)
	}
}

func TestRead_CorruptFileFailsHard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}

	_, err := last.Read(path)
	if err == nil {
		t.Fatal("Read: want an error for a corrupt file, got nil")
	}
	if !errors.Is(err, last.ErrCorrupt) {
		t.Fatalf("Read: got error %v, want it to wrap last.ErrCorrupt", err)
	}
}

func TestRead_CorruptFileErrorNamesOnlyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")

	// The content includes a value that would be a secret in a real
	// bundle. The assertion below is the load-bearing part of this
	// test: that value must never appear in the error text.
	secret := "super-secret-private-key-material"
	if err := os.WriteFile(path, []byte(`{"private_key":"`+secret+`", invalid}`), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}

	_, err := last.Read(path)
	if err == nil {
		t.Fatal("Read: want an error for a corrupt file, got nil")
	}
	msg := err.Error()
	if contains(msg, secret) {
		t.Fatalf("Read: error message leaked file content: %q", msg)
	}
}

func TestRead_UnknownVersionFailsHard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")

	if err := os.WriteFile(path, []byte(`{"version":99,"wg":{},"stunmesh":""}`), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	_, err := last.Read(path)
	if err == nil {
		t.Fatal("Read: want an error for an unknown schema version, got nil")
	}
	if !errors.Is(err, last.ErrCorrupt) {
		t.Fatalf("Read: got error %v, want it to wrap last.ErrCorrupt", err)
	}
}

func TestWrite_Mode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")

	if err := last.Write(path, sampleState()); err != nil {
		t.Fatalf("Write: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want %o", got, 0o600)
	}
}

func TestWrite_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")

	first := sampleState()
	if err := last.Write(path, first); err != nil {
		t.Fatalf("Write first: %v", err)
	}

	second := sampleState()
	second.Stunmesh = "changed"
	delete(second.WG, "wg0")
	if err := last.Write(path, second); err != nil {
		t.Fatalf("Write second: %v", err)
	}

	got, err := last.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Stunmesh != "changed" {
		t.Fatalf("Stunmesh = %q, want %q", got.Stunmesh, "changed")
	}
	if len(got.WG) != 0 {
		t.Fatalf("WG = %v, want empty after overwrite", got.WG)
	}

	// The temporary file used to make the write atomic must not be
	// left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "last.json" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("directory contents = %v, want only last.json", names)
	}

	if got, want := info(t, path).Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("mode after overwrite = %o, want %o", got, want)
	}
}

func TestReadWrite_PresenceSurvivesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")

	state := &last.State{
		Version: last.CurrentVersion,
		WG: map[string]last.Interface{
			"wg0": {
				Sections: last.Sections{Interface: "wg0"},
				Content: bundle.Interface{
					PrivateKey: "key",
					Addresses:  []string{"10.0.0.1/24"},
					// Routes, Options, and Peers are all left nil
					// (absent), on purpose, to pin the other half of
					// the presence contract against
					// TestReadWrite_RoundTrip's explicit-empty case.
				},
			},
		},
		Stunmesh: "",
	}

	if err := last.Write(path, state); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := last.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	iface := got.WG["wg0"]
	if iface.Content.Routes != nil {
		t.Fatalf("Routes = %#v, want nil (absent) after round trip", iface.Content.Routes)
	}
	if iface.Content.Options != nil {
		t.Fatalf("Options = %#v, want nil (absent) after round trip", iface.Content.Options)
	}
	if iface.Content.Peers != nil {
		t.Fatalf("Peers = %#v, want nil (absent) after round trip", iface.Content.Peers)
	}

	// And the explicit-empty case from sampleState: an empty slice/map
	// must come back non-nil and empty, not collapsed to absent.
	path2 := filepath.Join(dir, "last2.json")
	if err := last.Write(path2, sampleState()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got2, err := last.Read(path2)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	iface2 := got2.WG["wg0"]
	if iface2.Content.Routes == nil || len(iface2.Content.Routes) != 0 {
		t.Fatalf("Routes = %#v, want a non-nil empty slice after round trip", iface2.Content.Routes)
	}
	if iface2.Content.Options == nil || len(iface2.Content.Options) != 0 {
		t.Fatalf("Options = %#v, want a non-nil empty map after round trip", iface2.Content.Options)
	}
}

func info(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func jsonOf(v any) ([]byte, error) {
	return json.Marshal(v)
}
