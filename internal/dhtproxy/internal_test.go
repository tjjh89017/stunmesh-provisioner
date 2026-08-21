package dhtproxy

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

// TestReadLine_ContentAtMaxLenAccepted proves that a line whose
// content (excluding its terminator) is exactly maxLen bytes is
// accepted, not flagged oversized. The terminator must not count
// against the limit.
func TestReadLine_ContentAtMaxLenAccepted(t *testing.T) {
	content := strings.Repeat("a", 10)
	r := bufio.NewReader(strings.NewReader(content + "\n"))

	line, oversized, err := readLine(r, 10)

	if oversized {
		t.Fatalf("readLine: oversized = true, want false for content == maxLen")
	}
	if err != nil && err != io.EOF {
		t.Fatalf("readLine: unexpected error: %v", err)
	}
	if string(line) != content {
		t.Fatalf("readLine: line = %q, want %q", line, content)
	}
}

// TestReadLine_ContentOverMaxLenOversized proves that content one
// byte over maxLen is rejected as oversized.
func TestReadLine_ContentOverMaxLenOversized(t *testing.T) {
	content := strings.Repeat("a", 11)
	r := bufio.NewReader(strings.NewReader(content + "\n"))

	line, oversized, _ := readLine(r, 10)

	if !oversized {
		t.Fatalf("readLine: oversized = false, want true for content == maxLen+1")
	}
	if line != nil {
		t.Fatalf("readLine: line = %q, want nil", line)
	}
}

// TestReadLine_ContentAtMaxLenNoTrailingNewlineAccepted covers the
// same accept boundary at EOF with no trailing newline.
func TestReadLine_ContentAtMaxLenNoTrailingNewlineAccepted(t *testing.T) {
	content := strings.Repeat("a", 10)
	r := bufio.NewReader(strings.NewReader(content))

	line, oversized, err := readLine(r, 10)

	if oversized {
		t.Fatalf("readLine: oversized = true, want false for content == maxLen at EOF")
	}
	if err != io.EOF {
		t.Fatalf("readLine: err = %v, want io.EOF", err)
	}
	if string(line) != content {
		t.Fatalf("readLine: line = %q, want %q", line, content)
	}
}

// TestReadLine_ContentOverMaxLenNoTrailingNewlineOversized covers the
// reject boundary at EOF with no trailing newline.
func TestReadLine_ContentOverMaxLenNoTrailingNewlineOversized(t *testing.T) {
	content := strings.Repeat("a", 11)
	r := bufio.NewReader(strings.NewReader(content))

	line, oversized, _ := readLine(r, 10)

	if !oversized {
		t.Fatalf("readLine: oversized = false, want true for content == maxLen+1 at EOF")
	}
	if line != nil {
		t.Fatalf("readLine: line = %q, want nil", line)
	}
}

// TestReadLine_CRLFTerminatorNotCounted proves a \r\n terminator is
// also excluded from the length comparison.
func TestReadLine_CRLFTerminatorNotCounted(t *testing.T) {
	content := strings.Repeat("a", 10)
	r := bufio.NewReader(strings.NewReader(content + "\r\n"))

	_, oversized, _ := readLine(r, 10)

	if oversized {
		t.Fatalf("readLine: oversized = true, want false for content == maxLen with CRLF terminator")
	}
}

// TestDecodeLine_AfterCapCountsDroppedOnlyForValidValues proves that
// once the value cap is reached, a further malformed line counts as
// Skipped, not Dropped, and a further valid line counts as Dropped.
// Result.Dropped is documented as "valid values received after the
// cap".
func TestDecodeLine_AfterCapCountsDroppedOnlyForValidValues(t *testing.T) {
	c := &Client{maxValues: 1}
	result := &Result{}

	// Fill the cap with one valid value.
	c.decodeLine([]byte(`{"data":"aGVsbG8="}`), result) // "hello"
	if len(result.Values) != 1 {
		t.Fatalf("Values = %d, want 1 after filling the cap", len(result.Values))
	}

	// A further valid value after the cap: Dropped, not Skipped.
	c.decodeLine([]byte(`{"data":"d29ybGQ="}`), result) // "world"
	if result.Dropped != 1 {
		t.Fatalf("Dropped = %d, want 1 after a valid value past the cap", result.Dropped)
	}
	if result.Skipped != 0 {
		t.Fatalf("Skipped = %d, want 0 after a valid value past the cap", result.Skipped)
	}

	// A further malformed value after the cap: Skipped, not Dropped.
	c.decodeLine([]byte(`not json`), result)
	if result.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1 after a malformed value past the cap", result.Skipped)
	}
	if result.Dropped != 1 {
		t.Fatalf("Dropped = %d, want 1 (unchanged) after a malformed value past the cap", result.Dropped)
	}
	if len(result.Values) != 1 {
		t.Fatalf("Values = %d, want 1 (unchanged) past the cap", len(result.Values))
	}
}

// TestIsHexKey checks the key format accepted by Get and Put.
func TestIsHexKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want bool
	}{
		{"valid 40-char lowercase hex", "0123456789abcdef0123456789abcdef01234567", true},
		{"39 chars", "0123456789abcdef0123456789abcdef0123456", false},
		{"41 chars", "0123456789abcdef0123456789abcdef012345678", false},
		{"uppercase hex", "0123456789ABCDEF0123456789abcdef01234567", false},
		{"path traversal", "../x", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isHexKey(c.key); got != c.want {
				t.Errorf("isHexKey(%q) = %v, want %v", c.key, got, c.want)
			}
		})
	}
}
