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

// TestRead_UnreadableFileFailsHard pins the non-ENOENT read-failure
// branch (last.go:166): a path that exists but cannot be read as a
// file. A directory triggers this on every platform and every user,
// including root, because reading a directory's bytes fails
// regardless of permissions -- unlike a permission-denied regular
// file, which root can still read.
func TestRead_UnreadableFileFailsHard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("seed directory in place of last.json: %v", err)
	}

	_, err := last.Read(path)
	if err == nil {
		t.Fatal("Read: want an error when path is a directory, got nil")
	}
	if !errors.Is(err, last.ErrCorrupt) {
		t.Fatalf("Read: got error %v, want it to wrap last.ErrCorrupt", err)
	}
	if !contains(err.Error(), path) {
		t.Fatalf("Read: error %q does not name the path %q", err.Error(), path)
	}
}

// TestRead_PermissionDeniedFailsHard is the permission-denied variant
// of the same branch as TestRead_UnreadableFileFailsHard, using a
// regular file this time. It is skipped under root: root bypasses
// file-permission bits and can read a 0000 file, so the read would
// succeed and the test would pass for the wrong reason (or not at
// all) rather than genuinely exercising the failure branch.
func TestRead_PermissionDeniedFailsHard(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping: running as root, which bypasses file permission bits")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"wg":{},"stunmesh":""}`), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 0000: %v", err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) })

	_, err := last.Read(path)
	if err == nil {
		t.Fatal("Read: want an error for a permission-denied file, got nil")
	}
	if !errors.Is(err, last.ErrCorrupt) {
		t.Fatalf("Read: got error %v, want it to wrap last.ErrCorrupt", err)
	}
	if !contains(err.Error(), path) {
		t.Fatalf("Read: error %q does not name the path %q", err.Error(), path)
	}
}

// TestRead_TrailingDataFailsHard pins the dec.More() branch
// (last.go:175-177): a syntactically valid JSON object followed by
// more JSON data is rejected with its own error reason, distinct from
// "not valid JSON". The trailing bytes include a secret-shaped value
// to pin that it never reaches the error message either -- the
// decoder must reject on More() before ever looking at it.
func TestRead_TrailingDataFailsHard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")

	secret := "super-secret-trailing-key-material"
	data := []byte(`{"version":1,"wg":{},"stunmesh":""}{"private_key":"` + secret + `"}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	_, err := last.Read(path)
	if err == nil {
		t.Fatal("Read: want an error for trailing data, got nil")
	}
	if !errors.Is(err, last.ErrCorrupt) {
		t.Fatalf("Read: got error %v, want it to wrap last.ErrCorrupt", err)
	}
	msg := err.Error()
	if !contains(msg, path) {
		t.Fatalf("Read: error %q does not name the path %q", msg, path)
	}
	if contains(msg, secret) {
		t.Fatalf("Read: error message leaked file content: %q", msg)
	}
	if !contains(msg, "trailing data") {
		t.Fatalf("Read: error %q does not give the distinct trailing-data reason", msg)
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

// TestRead_MissingWGKeyNormalizesToEmptyMap pins the st.WG == nil
// normalization (last.go:182-184) for the decode path, not just the
// missing-file path TestRead_MissingFileIsEmptyState already covers:
// a syntactically valid file that simply omits "wg" must still come
// back with a non-nil, empty WG, per the State.WG field doc.
func TestRead_MissingWGKeyNormalizesToEmptyMap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")

	if err := os.WriteFile(path, []byte(`{"version":1,"stunmesh":""}`), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	got, err := last.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.WG == nil {
		t.Fatal("Read: WG is nil, want a non-nil empty map")
	}
	if len(got.WG) != 0 {
		t.Fatalf("Read: WG = %v, want empty", got.WG)
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

// TestWrite_MissingParentDirLeavesTargetAbsent pins the
// os.CreateTemp failure branch (last.go:226-229): the documented case
// where the caller has not created path's parent directory. The
// target must be left absent (the first of the three states the
// package doc promises) and no temporary file may exist anywhere,
// since CreateTemp never got far enough to create one.
func TestWrite_MissingParentDirLeavesTargetAbsent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "does-not-exist")
	path := filepath.Join(parent, "last.json")

	secret := sampleState().WG["wg0"].Content.PrivateKey
	err := last.Write(path, sampleState())
	if err == nil {
		t.Fatal("Write: want an error for a missing parent directory, got nil")
	}
	if contains(err.Error(), secret) {
		t.Fatalf("Write: error message leaked file content: %q", err.Error())
	}

	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("Write: target path exists after a failed write (stat err = %v), want absent", statErr)
	}
	if _, statErr := os.Stat(parent); !os.IsNotExist(statErr) {
		t.Fatalf("Write: parent directory exists after a failed write (stat err = %v), want still absent", statErr)
	}
}

// TestWrite_RenameFailureLeavesPreviousContent pins the os.Rename
// failure branch (last.go:253-255). Making path a pre-existing
// directory lets CreateTemp, Chmod, Write, Sync, and Close all
// succeed against the temporary file, and only the final rename onto
// path fails (renaming a file onto an existing directory always
// fails). This is the "still holding its previous content" state the
// package doc promises: path is untouched by the failed write, and
// the deferred os.Remove(tmpPath) must have cleaned up the temporary
// file, so nothing else appears in the directory.
func TestWrite_RenameFailureLeavesPreviousContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("seed directory in place of last.json: %v", err)
	}

	secret := sampleState().WG["wg0"].Content.PrivateKey
	err := last.Write(path, sampleState())
	if err == nil {
		t.Fatal("Write: want an error when the target path is a directory, got nil")
	}
	if contains(err.Error(), secret) {
		t.Fatalf("Write: error message leaked file content: %q", err.Error())
	}

	fi, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatalf("stat path after failed write: %v", statErr)
	}
	if !fi.IsDir() {
		t.Fatalf("Write: target path is no longer a directory after a failed write, want previous content preserved")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "last.json" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("directory contents after failed rename = %v, want only the pre-existing last.json (no leaked temp file)", names)
	}
}

// TestWrite_ChmodWriteSyncCloseFailuresNotReachable documents, rather
// than tests, the branches this package's test suite cannot reach.
//
// Chmod, Write, Sync, and Close (last.go:237-251) all operate on an
// *os.File this package already opened via os.CreateTemp. Making any
// of them fail from a black-box test would require one of:
//
//   - A filesystem fault (ENOSPC, EDQUOT, EIO, a read-only remount
//     mid-write): not reproducible portably or deterministically in a
//     unit test, and not safe to script against the machine running
//     the suite.
//   - RLIMIT_FSIZE small enough to make Write fail: on Linux this
//     delivers SIGXFSZ to the process instead of returning EFBIG
//     unless the signal is caught, which would require product code
//     (or test code) to install a signal handler -- out of proportion
//     for one branch.
//   - A seam that lets a test substitute the *os.File Write uses (an
//     interface, or a factory function field) so a fake can fail on
//     demand.
//
// The last option is a real seam, but this package's own doc frames
// Write's atomicity guarantee in terms of a real file and a real
// rename; adding an injectable-writer seam only to reach four lines
// that are a straight passthrough to the standard library (each one
// already: call the stdlib method, wrap the error with the path, best
// effort remove the temp file via the existing defer) would add
// production-code indirection for four branches whose logic is
// "if err != nil, wrap and return" -- not a design flaw this package
// needs fixing. These branches are accepted as uncovered by design.
func TestWrite_ChmodWriteSyncCloseFailuresNotReachable(t *testing.T) {
	t.Skip("Chmod/Write/Sync/Close failures on the temp file are not reachable from a black-box test without a filesystem fault or a seam; see comment above this test")
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
