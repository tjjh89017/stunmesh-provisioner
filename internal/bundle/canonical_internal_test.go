package bundle

// Table-driven unit tests for unescapeLineSeparators, the helper that
// undoes encoding/json's unconditional U+2028/U+2029 escaping so
// Canonical matches the `jq -S -c 'del(.timestamp)'` reference bytes
// (PLAN.md 4.5). White-box (package bundle, not bundle_test) because
// the helper is unexported.
//
// Inputs below are built with plain double-quoted string literals, so
// `\\` is one literal backslash byte and `\\u2028` is the six ASCII
// bytes backslash, u, 2, 0, 2, 8 — the escape sequence as it appears
// in encoded JSON, never the raw U+2028 rune itself.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"testing"
)

var (
	rawU2028 = []byte{0xE2, 0x80, 0xA8}
	rawU2029 = []byte{0xE2, 0x80, 0xA9}
)

func TestUnescapeLineSeparators(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []byte
	}{
		{
			name: "u2028 escape alone becomes raw bytes",
			in:   "\\u2028",
			want: rawU2028,
		},
		{
			name: "u2029 escape alone becomes raw bytes",
			in:   "\\u2029",
			want: rawU2029,
		},
		{
			name: "u2028 escape at string start",
			in:   "\\u2028rest",
			want: append(append([]byte{}, rawU2028...), "rest"...),
		},
		{
			name: "u2028 escape at string end",
			in:   "rest\\u2028",
			want: append([]byte("rest"), rawU2028...),
		},
		{
			name: "both separators in the same string",
			in:   "a\\u2028b\\u2029c",
			want: func() []byte {
				out := []byte("a")
				out = append(out, rawU2028...)
				out = append(out, "b"...)
				out = append(out, rawU2029...)
				out = append(out, "c"...)
				return out
			}(),
		},
		{
			name: "one escaped backslash before u2028 leaves it literal",
			// The JSON source `"a\\u2028b"` decodes to the Go string
			// a<backslash>u2028b (one literal backslash, then the literal text
			// "u2028b"). Re-encoding it escapes only the backslash
			// (as \\), leaving u2028b untouched: the byte sequence
			// under test is two backslashes followed by "u2028b".
			in:   "a\\\\u2028b",
			want: []byte("a\\\\u2028b"),
		},
		{
			name: "one escaped backslash before u2029 leaves it literal",
			in:   "a\\\\u2029b",
			want: []byte("a\\\\u2029b"),
		},
		{
			name: "three backslashes before the escape: even preceding count, converts",
			// Three backslashes then "u2028": the escape's own leading
			// backslash is the third one, preceded by two backslashes
			// (an even count), so the third is a fresh, genuine escape
			// introducer and converts. The function copies bytes it
			// does not match verbatim, so the two preceding
			// backslashes pass through unchanged (this helper does
			// not also collapse \\ pairs); only the matched six-byte
			// escape sequence becomes the raw separator.
			in: "a\\\\\\u2028b",
			want: func() []byte {
				out := []byte("a\\\\")
				out = append(out, rawU2028...)
				out = append(out, "b"...)
				return out
			}(),
		},
		{
			name: "four backslashes before the escape: odd preceding count, stays literal",
			// Four backslashes then "u2028": the escape's own leading
			// backslash is the fourth one, preceded by three
			// backslashes (an odd count). The fourth backslash is
			// therefore the second half of an escaped pair with the
			// third, not a fresh escape introducer, so nothing here
			// converts; all four backslashes and "u2028b" stay
			// literal.
			in:   "a\\\\\\\\u2028b",
			want: []byte("a\\\\\\\\u2028b"),
		},
		{
			name: "no separator present",
			in:   "plain text with no escapes",
			want: []byte("plain text with no escapes"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := unescapeLineSeparators([]byte(tc.in))
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("unescapeLineSeparators(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeEscapesMatchesJQAcrossCodePoints is a table-driven,
// whole-code-point sweep of every place Go's encoding/json and jq
// 1.8.2 are known (or suspected) to diverge in how they escape a
// string byte, plus a sample of code points where they are expected
// to already agree. For each code point it builds a valid bundle with
// that character in `stunmesh`, and a second valid bundle with it as
// a peer-name map key, runs Canonical, and compares byte-for-byte
// with `jq -S -c 'del(.timestamp)'`. This is the empirical discovery
// step: it does not assume which code points diverge, it checks all
// of 0x00-0x1F, 0x7F, U+2028, U+2029, plus `"`, `\`, `/`, and two
// non-ASCII samples.
func TestNormalizeEscapesMatchesJQAcrossCodePoints(t *testing.T) {
	jqPath, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq not found on PATH, skipping byte-equality check against the jq reference")
	}

	var codePoints []rune
	for cp := rune(0x00); cp <= 0x1F; cp++ {
		codePoints = append(codePoints, cp)
	}
	codePoints = append(codePoints, 0x7F, 0x2028, 0x2029, '"', '\\', '/', 'é', '中')

	for _, cp := range codePoints {
		name := fmt.Sprintf("U+%04X", cp)

		t.Run(name+"/stunmesh", func(t *testing.T) {
			m := map[string]any{
				"version":   1,
				"namespace": "n",
				"node_id":   "a",
				"timestamp": 1,
				"wg":        map[string]any{},
				"stunmesh":  string(cp),
			}
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			checkCanonicalMatchesJQ(t, jqPath, data)
		})

		t.Run(name+"/peer-name-key", func(t *testing.T) {
			m := map[string]any{
				"version":   1,
				"namespace": "n",
				"node_id":   "a",
				"timestamp": 1,
				"stunmesh":  "",
				"wg": map[string]any{
					"wg0": map[string]any{
						"private_key": "k",
						"addresses":   []any{"1.1.1.1/32"},
						"peers": map[string]any{
							string(cp): map[string]any{
								"public_key":  "p",
								"allowed_ips": []any{"1.1.1.2/32"},
							},
						},
					},
				},
			}
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			checkCanonicalMatchesJQ(t, jqPath, data)
		})
	}
}

// checkCanonicalMatchesJQ parses data, runs Canonical, and fails the
// test if the result does not match `jq -S -c 'del(.timestamp)'` on
// the same input, byte for byte.
func checkCanonicalMatchesJQ(t *testing.T, jqPath string, data []byte) {
	t.Helper()

	b, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	got, err := b.Canonical()
	if err != nil {
		t.Fatalf("Canonical: unexpected error: %v", err)
	}

	cmd := exec.Command(jqPath, "-S", "-c", "del(.timestamp)")
	cmd.Stdin = bytes.NewReader(data)
	want, err := cmd.Output()
	if err != nil {
		t.Fatalf("jq: %v", err)
	}
	want = bytes.TrimRight(want, "\n")

	if !bytes.Equal(got, want) {
		t.Fatalf("Canonical mismatch with jq reference\n got: %s\nwant: %s", got, want)
	}
}
