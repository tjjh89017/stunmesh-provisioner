package yamlx

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestToJSON_StringKeysBecomeObject(t *testing.T) {
	got, err := ToJSON([]byte("a: 1\nb: two\n"))
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if string(got) != `{"a":1,"b":"two"}` {
		t.Fatalf("ToJSON = %s", got)
	}
}

func TestToJSON_NonStringKeyRejected(t *testing.T) {
	_, err := ToJSON([]byte("1: a\n"))
	if err == nil {
		t.Fatal("ToJSON: got nil error, want an error for an integer map key")
	}
	if got, want := err.Error(), "!!int"; !strings.Contains(got, want) {
		t.Fatalf("ToJSON error = %q, want it to name the key type %q", got, want)
	}
	if strings.Contains(err.Error(), ": a") {
		t.Fatalf("ToJSON error = %q, must not echo the value", err.Error())
	}
}

func TestToJSON_NestedMapsAndSequences(t *testing.T) {
	in := "a:\n  b:\n    - 1\n    - 2\n  c: {}\n  d: []\n"
	got, err := ToJSON([]byte(in))
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	a := v["a"].(map[string]any)
	if b, ok := a["b"].([]any); !ok || len(b) != 2 {
		t.Fatalf("a.b = %#v, want a two-element sequence", a["b"])
	}
	if c, ok := a["c"].(map[string]any); !ok || len(c) != 0 {
		t.Fatalf("a.c = %#v, want an empty object", a["c"])
	}
	if d, ok := a["d"].([]any); !ok || len(d) != 0 {
		t.Fatalf("a.d = %#v, want an empty array", a["d"])
	}
}

func TestToJSON_IntegerPrecision(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"n: 4294967295\n", `{"n":4294967295}`},
		{"n: 9223372036854775807\n", `{"n":9223372036854775807}`},
		{"n: 18446744073709551615\n", `{"n":18446744073709551615}`},
	}
	for _, tc := range cases {
		got, err := ToJSON([]byte(tc.in))
		if err != nil {
			t.Fatalf("ToJSON(%q): %v", tc.in, err)
		}
		if string(got) != tc.want {
			t.Fatalf("ToJSON(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestToJSON_TimestampScalarStaysString(t *testing.T) {
	got, err := ToJSON([]byte("d: 2026-09-05\n"))
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if string(got) != `{"d":"2026-09-05"}` {
		t.Fatalf("ToJSON = %s, want the timestamp kept as a string", got)
	}
}

func TestToJSON_EmptyAndNull(t *testing.T) {
	for _, in := range []string{"", "null\n", "~\n"} {
		got, err := ToJSON([]byte(in))
		if err != nil {
			t.Fatalf("ToJSON(%q): %v", in, err)
		}
		if string(got) != "null" {
			t.Fatalf("ToJSON(%q) = %s, want null", in, got)
		}
	}
}

func TestToJSON_MultipleDocumentsRejected(t *testing.T) {
	_, err := ToJSON([]byte("a: 1\n---\nb: 2\n"))
	if err == nil {
		t.Fatal("ToJSON: got nil error, want an error for a second document")
	}
}

func TestToJSON_DuplicateKeyRejected(t *testing.T) {
	_, err := ToJSON([]byte("a: 1\na: 2\n"))
	if err == nil {
		t.Fatal("ToJSON: got nil error, want an error for a duplicate key")
	}
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("ToJSON error = %v, want ErrDuplicateKey", err)
	}
}

func TestToJSON_AnchorAndAliasResolve(t *testing.T) {
	got, err := ToJSON([]byte("a: &x 1\nb: *x\n"))
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if string(got) != `{"a":1,"b":1}` {
		t.Fatalf("ToJSON = %s, want the alias resolved to the anchored value", got)
	}
}

func TestToJSON_MergeKeyRejected(t *testing.T) {
	_, err := ToJSON([]byte("<<: {a: 1}\nb: 2\n"))
	if err == nil {
		t.Fatal("ToJSON: got nil error, want an error for a merge key")
	}
}

func TestToJSON_BinaryScalarDecodesToString(t *testing.T) {
	got, err := ToJSON([]byte("a: !!binary aGVsbG8=\n"))
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if string(got) != `{"a":"hello"}` {
		t.Fatalf("ToJSON = %s, want the decoded bytes as a JSON string", got)
	}
}

func TestToJSON_BoolLikeWordsStayStrings(t *testing.T) {
	got, err := ToJSON([]byte("a: yes\nb: no\nc: on\nd: off\n"))
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	want := `{"a":"yes","b":"no","c":"on","d":"off"}`
	if string(got) != want {
		t.Fatalf("ToJSON = %s, want %s (yaml.in/yaml/v3 only resolves true/false as booleans)", got, want)
	}
}

func TestToJSON_FloatStaysFloat(t *testing.T) {
	got, err := ToJSON([]byte("a: 3.14\n"))
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if string(got) != `{"a":3.14}` {
		t.Fatalf("ToJSON = %s, want a JSON float", got)
	}
}

func TestToJSON_ScalarDecodeErrorDoesNotLeakValue(t *testing.T) {
	const secret = "wireguard-private-key-should-not-leak"
	_, err := ToJSON([]byte("private_key: !!int " + secret + "\n"))
	if err == nil {
		t.Fatal("ToJSON: got nil error, want an error for a mistagged scalar")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("ToJSON error = %q, must not echo the scalar value", err.Error())
	}
}

func TestToJSON_SyntaxErrorNextToSecretDoesNotLeakValue(t *testing.T) {
	const secret = "wireguard-private-key-should-not-leak"
	_, err := ToJSON([]byte("private_key: " + secret + "\nbad: [\n"))
	if err == nil {
		t.Fatal("ToJSON: got nil error, want an error for the syntax error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("ToJSON error = %q, must not echo the scalar value", err.Error())
	}
}
