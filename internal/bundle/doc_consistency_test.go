package bundle_test

// This test guards docs/format.md against drift from the code in this
// package. It does not check prose quality; it checks that a set of
// load-bearing strings still appear in the document.

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/bundle"
	"github.com/tjjh89017/stunmesh-provisioner/internal/testvectors"
)

// docPath returns the path of docs/format.md relative to this test
// file, so the test works regardless of the caller's working
// directory.
func docPath(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("doc_consistency_test: cannot determine caller")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "docs", "format.md")
}

// jsonTags returns every `json` tag name declared on the fields of
// v's type, skipping "-". It does not recurse into nested struct
// types; call it once per type instead.
func jsonTags(v any) []string {
	t := reflect.TypeOf(v)

	var names []string
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		names = append(names, name)
	}
	return names
}

func TestFormatDocMatchesBundleFields(t *testing.T) {
	path := docPath(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	doc := string(data)

	// Every JSON field name declared by the bundle types must be
	// documented. This fails when a field is added to the code but
	// not to docs/format.md.
	var fieldNames []string
	fieldNames = append(fieldNames, jsonTags(bundle.Bundle{})...)
	fieldNames = append(fieldNames, jsonTags(bundle.Interface{})...)
	fieldNames = append(fieldNames, jsonTags(bundle.RoutingTable{})...)
	fieldNames = append(fieldNames, jsonTags(bundle.Route{})...)
	fieldNames = append(fieldNames, jsonTags(bundle.Peer{})...)

	for _, name := range fieldNames {
		if !strings.Contains(doc, name) {
			t.Errorf("docs/format.md does not mention JSON field %q", name)
		}
	}

	// The golden DHT key vector must appear verbatim.
	dhtKey := testvectors.DHTKey()
	if !strings.Contains(doc, dhtKey) {
		t.Errorf("docs/format.md does not contain the golden DHT key %q", dhtKey)
	}

	// A fixed set of terms that the document must explain.
	for _, want := range []string{"nonce", "base64", "timestamp", "del(.timestamp)", "64"} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/format.md does not contain %q", want)
		}
	}
}
