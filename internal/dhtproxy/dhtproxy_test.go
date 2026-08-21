package dhtproxy_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tjjh89017/stunmesh-provisioner/internal/dhtproxy"
)

const testKey = "0123456789abcdef0123456789abcdef01234567"

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestGet_SingleValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":"` + b64("hello") + `"}` + "\n"))
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(res.Values) != 1 || string(res.Values[0]) != "hello" {
		t.Fatalf("Values = %v", res.Values)
	}
	if res.Skipped != 0 || res.Dropped != 0 {
		t.Fatalf("Skipped=%d Dropped=%d, want 0,0", res.Skipped, res.Dropped)
	}
}

func TestGet_MultipleValuesWithExtraFields(t *testing.T) {
	body := strings.Join([]string{
		`{"id":"1","type":0,"seq":1,"data":"` + b64("v1") + `"}`,
		`{"id":"2","type":0,"seq":2,"data":"` + b64("v2") + `"}`,
		`{"id":"3","type":0,"seq":3,"data":"` + b64("v3") + `"}`,
	}, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body + "\n"))
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(res.Values) != 3 {
		t.Fatalf("len(Values) = %d, want 3", len(res.Values))
	}
	want := []string{"v1", "v2", "v3"}
	for i, w := range want {
		if string(res.Values[i]) != w {
			t.Errorf("Values[%d] = %q, want %q", i, res.Values[i], w)
		}
	}
}

func TestGet_BlankLinesIgnored(t *testing.T) {
	body := "\n" + `{"data":"` + b64("v1") + `"}` + "\n\n" + `{"data":"` + b64("v2") + `"}` + "\n\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(res.Values) != 2 {
		t.Fatalf("len(Values) = %d, want 2", len(res.Values))
	}
}

func TestGet_BadLinesSkipped(t *testing.T) {
	body := strings.Join([]string{
		`{"data":"` + b64("good") + `"}`,
		`not json`,
		`{"data":"not-valid-base64!!"}`,
	}, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body + "\n"))
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(res.Values) != 1 || string(res.Values[0]) != "good" {
		t.Fatalf("Values = %v", res.Values)
	}
	if res.Skipped != 2 {
		t.Fatalf("Skipped = %d, want 2", res.Skipped)
	}
}

func TestGet_MaxValuesCap(t *testing.T) {
	lines := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		lines = append(lines, `{"data":"`+b64("v")+`"}`)
	}
	body := strings.Join(lines, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body + "\n"))
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL}, dhtproxy.WithMaxValues(2))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(res.Values) != 2 {
		t.Fatalf("len(Values) = %d, want 2", len(res.Values))
	}
	if res.Dropped != 3 {
		t.Fatalf("Dropped = %d, want 3", res.Dropped)
	}
}

// TestGet_OversizedLineAfterGoodLineSkipped covers an oversized line
// (well over the 1 MiB line cap) that comes after a good line, with a
// trailing newline of its own and nothing after it in the body.
func TestGet_OversizedLineAfterGoodLineSkipped(t *testing.T) {
	oversized := strings.Repeat("a", 2<<20) // 2 MiB, well over the 1 MiB line cap
	body := strings.Join([]string{
		`{"data":"` + b64("good") + `"}`,
		`{"data":"` + oversized + `"}`,
	}, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body + "\n"))
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if len(res.Values) != 1 || string(res.Values[0]) != "good" {
		t.Fatalf("Values = %v, want [\"good\"]", res.Values)
	}
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", res.Skipped)
	}
}

// TestGet_OversizedLineBetweenGoodLinesSkippedRestKept proves that an
// oversized line in the middle of the body does not swallow the good
// lines that follow it. Before the fix, bufio.Scanner's ErrTooLong
// stopped the scan for good, so "good2" was lost.
func TestGet_OversizedLineBetweenGoodLinesSkippedRestKept(t *testing.T) {
	oversized := strings.Repeat("a", 2<<20) // 2 MiB, well over the 1 MiB line cap
	body := strings.Join([]string{
		`{"data":"` + b64("good1") + `"}`,
		`{"data":"` + oversized + `"}`,
		`{"data":"` + b64("good2") + `"}`,
	}, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body + "\n"))
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if len(res.Values) != 2 {
		t.Fatalf("len(Values) = %d, want 2: %v", len(res.Values), res.Values)
	}
	if string(res.Values[0]) != "good1" || string(res.Values[1]) != "good2" {
		t.Fatalf("Values = %v, want [\"good1\", \"good2\"]", res.Values)
	}
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", res.Skipped)
	}
}

// TestGet_OversizedFirstLineSkippedGoodLineKept covers an oversized
// line as the very first line of the body, followed by a good line.
func TestGet_OversizedFirstLineSkippedGoodLineKept(t *testing.T) {
	oversized := strings.Repeat("a", 2<<20) // 2 MiB, well over the 1 MiB line cap
	body := strings.Join([]string{
		`{"data":"` + oversized + `"}`,
		`{"data":"` + b64("good") + `"}`,
	}, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body + "\n"))
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if len(res.Values) != 1 || string(res.Values[0]) != "good" {
		t.Fatalf("Values = %v, want [\"good\"]", res.Values)
	}
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", res.Skipped)
	}
}

// TestGet_OversizedLineAtEOFWithoutTrailingNewlineSkipped covers an
// oversized line that is also the last bytes of the body, with no
// trailing newline at all.
func TestGet_OversizedLineAtEOFWithoutTrailingNewlineSkipped(t *testing.T) {
	oversized := strings.Repeat("a", 2<<20) // 2 MiB, well over the 1 MiB line cap
	body := `{"data":"` + oversized + `"}`  // no trailing newline

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if len(res.Values) != 0 {
		t.Fatalf("Values = %v, want empty", res.Values)
	}
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", res.Skipped)
	}
}

func TestGet_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(res.Values) != 0 {
		t.Fatalf("Values = %v, want empty", res.Values)
	}
}

func TestGet_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(res.Values) != 0 {
		t.Fatalf("Values = %v, want empty", res.Values)
	}
}

func TestGet_Path(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Write([]byte(`{"data":"` + b64("v") + `"}` + "\n"))
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.Get(context.Background(), testKey); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotPath != "/"+testKey {
		t.Errorf("path = %q, want %q", gotPath, "/"+testKey)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
}

func TestGet_FallbackOnNotFound(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":"` + b64("v2") + `"}` + "\n"))
	}))
	defer srv2.Close()

	c, err := dhtproxy.New([]string{srv1.URL, srv2.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if res.URL != srv2.URL {
		t.Errorf("URL = %q, want %q", res.URL, srv2.URL)
	}
	if len(res.Values) != 1 || string(res.Values[0]) != "v2" {
		t.Fatalf("Values = %v", res.Values)
	}
}

func TestGet_BothNotFound(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv2.Close()

	c, err := dhtproxy.New([]string{srv1.URL, srv2.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(res.Values) != 0 {
		t.Fatalf("Values = %v, want empty", res.Values)
	}
	if res.URL != srv2.URL {
		t.Errorf("URL = %q, want %q (last URL tried)", res.URL, srv2.URL)
	}
}

// TestGet_ConnectionRefusedThenNotFoundReturnsPartialError proves that
// when one proxy is unreachable and the only proxy that answers says
// "no value", Get reports the outage instead of silently returning an
// empty result indistinguishable from "nothing published".
func TestGet_ConnectionRefusedThenNotFoundReturnsPartialError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	deadURL := "http://" + ln.Addr().String()
	ln.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{deadURL, srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if len(res.Values) != 0 {
		t.Fatalf("Values = %v, want empty", res.Values)
	}
	if err == nil {
		t.Fatal("Get: want a non-nil error for a connection-refused proxy plus an empty answer, got nil")
	}
	var partial *dhtproxy.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("Get: error is not *PartialError: %v", err)
	}
	if len(partial.Errs) != 1 {
		t.Fatalf("PartialError.Errs = %v, want 1 entry", partial.Errs)
	}
	if strings.Contains(err.Error(), testKey) {
		t.Errorf("error %q contains the key", err.Error())
	}
}

// TestGet_BothNotFoundReturnsNilError proves that when every proxy
// answers (even with 404), and none has a value, Get still reports
// "nothing published" as a nil error: this is not an outage.
func TestGet_BothNotFoundReturnsNilError(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv2.Close()

	c, err := dhtproxy.New([]string{srv1.URL, srv2.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if len(res.Values) != 0 {
		t.Fatalf("Values = %v, want empty", res.Values)
	}
}

// TestGet_ServerErrorThenValueSucceedsUnchanged proves the existing
// "one proxy 5xx, another has the value" behavior is unaffected by
// the partial-outage handling above.
func TestGet_ServerErrorThenValueSucceedsUnchanged(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":"` + b64("v2") + `"}` + "\n"))
	}))
	defer srv2.Close()

	c, err := dhtproxy.New([]string{srv1.URL, srv2.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if len(res.Values) != 1 || string(res.Values[0]) != "v2" {
		t.Fatalf("Values = %v", res.Values)
	}
}

func TestGet_FallbackOnServerError(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":"` + b64("v2") + `"}` + "\n"))
	}))
	defer srv2.Close()

	c, err := dhtproxy.New([]string{srv1.URL, srv2.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if res.URL != srv2.URL {
		t.Errorf("URL = %q, want %q", res.URL, srv2.URL)
	}
	if len(res.Values) != 1 || string(res.Values[0]) != "v2" {
		t.Fatalf("Values = %v", res.Values)
	}
}

func TestGet_FallbackOnConnectionRefused(t *testing.T) {
	// A listener that is opened and immediately closed yields an
	// address nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	deadURL := "http://" + ln.Addr().String()
	ln.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":"` + b64("v2") + `"}` + "\n"))
	}))
	defer srv2.Close()

	c, err := dhtproxy.New([]string{deadURL, srv2.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Get(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if res.URL != srv2.URL {
		t.Errorf("URL = %q, want %q", res.URL, srv2.URL)
	}
}

func TestGet_AllFail(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv2.Close()

	c, err := dhtproxy.New([]string{srv1.URL, srv2.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = c.Get(context.Background(), testKey)
	if err == nil {
		t.Fatal("Get: want error, got nil")
	}
	host1 := strings.TrimPrefix(srv1.URL, "http://")
	host2 := strings.TrimPrefix(srv2.URL, "http://")
	msg := err.Error()
	if !strings.Contains(msg, host1) || !strings.Contains(msg, host2) {
		t.Errorf("error %q does not mention both hosts %q %q", msg, host1, host2)
	}
	if strings.Contains(msg, testKey) {
		t.Errorf("error %q contains the key", msg)
	}
}

func TestGet_ContextCancelled(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = c.Get(ctx, testKey)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Get: want error, got nil")
	}
	if elapsed > time.Second {
		t.Fatalf("Get took %v, want it to return promptly", elapsed)
	}
}

func TestNew_EmptyList(t *testing.T) {
	if _, err := dhtproxy.New(nil); err == nil {
		t.Fatal("New(nil): want error, got nil")
	}
	if _, err := dhtproxy.New([]string{}); err == nil {
		t.Fatal("New([]string{}): want error, got nil")
	}
}

func TestNew_InvalidMaxValues(t *testing.T) {
	if _, err := dhtproxy.New([]string{"http://example.com"}, dhtproxy.WithMaxValues(0)); err == nil {
		t.Fatal("New: want error for WithMaxValues(0), got nil")
	}
	if _, err := dhtproxy.New([]string{"http://example.com"}, dhtproxy.WithMaxValues(-1)); err == nil {
		t.Fatal("New: want error for WithMaxValues(-1), got nil")
	}
}

func TestNew_InvalidURL(t *testing.T) {
	if _, err := dhtproxy.New([]string{"not a url"}); err == nil {
		t.Fatal("New: want error, got nil")
	}
	if _, err := dhtproxy.New([]string{"/just/a/path"}); err == nil {
		t.Fatal("New: want error for URL without scheme/host, got nil")
	}
}

func TestNew_TrimsTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.Get(context.Background(), testKey); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotPath != "/"+testKey {
		t.Errorf("path = %q, want %q (no double slash)", gotPath, "/"+testKey)
	}
}

func TestPut_BothSucceed(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var contentTypes []string

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		mu.Lock()
		bodies = append(bodies, string(body))
		contentTypes = append(contentTypes, r.Header.Get("Content-Type"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}

	srv1 := httptest.NewServer(http.HandlerFunc(handler))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(handler))
	defer srv2.Close()

	c, err := dhtproxy.New([]string{srv1.URL, srv2.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := []byte("secret-data")
	if err := c.Put(context.Background(), testKey, data); err != nil {
		t.Fatalf("Put: %v", err)
	}

	want := `{"data":"` + base64.StdEncoding.EncodeToString(data) + `"}`
	if len(bodies) != 2 {
		t.Fatalf("got %d requests, want 2", len(bodies))
	}
	for i, b := range bodies {
		if b != want {
			t.Errorf("body[%d] = %q, want %q", i, b, want)
		}
	}
	for i, ct := range contentTypes {
		if !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type[%d] = %q, want application/json", i, ct)
		}
	}
}

// TestPut_RunsConcurrently proves Put fans requests out instead of
// sending them one at a time. srv1's handler blocks until srv2's
// handler has been hit; if Put posted sequentially in base URL order,
// srv1 would never unblock and the test would time out.
func TestPut_RunsConcurrently(t *testing.T) {
	hitSrv2 := make(chan struct{})

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(hitSrv2)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()

	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hitSrv2
		w.WriteHeader(http.StatusOK)
	}))
	defer srv1.Close()

	c, err := dhtproxy.New([]string{srv1.URL, srv2.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- c.Put(context.Background(), testKey, []byte("data"))
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Put did not complete: srv1 waited for srv2, which only happens if requests run sequentially")
	}
}

func TestPut_PartialFailure(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv2.Close()

	c, err := dhtproxy.New([]string{srv1.URL, srv2.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.Put(context.Background(), testKey, []byte("data"))
	if err == nil {
		t.Fatal("Put: want error, got nil")
	}

	var partial *dhtproxy.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("Put: error is not *PartialError: %v", err)
	}
	if len(partial.Errs) != 1 {
		t.Fatalf("PartialError.Errs = %v, want 1 entry", partial.Errs)
	}
}

func TestPut_AllFail(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv2.Close()

	c, err := dhtproxy.New([]string{srv1.URL, srv2.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	secretData := []byte("very-secret-payload")
	err = c.Put(context.Background(), testKey, secretData)
	if err == nil {
		t.Fatal("Put: want error, got nil")
	}

	var partial *dhtproxy.PartialError
	if errors.As(err, &partial) {
		t.Fatalf("Put: want plain error when all fail, got *PartialError: %v", err)
	}

	msg := err.Error()
	if strings.Contains(msg, testKey) {
		t.Errorf("error %q contains the key", msg)
	}
	if strings.Contains(msg, base64.StdEncoding.EncodeToString(secretData)) {
		t.Errorf("error %q contains the base64 data", msg)
	}
}

func TestPut_ErrorMessageIsSanitized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c, err := dhtproxy.New([]string{srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.Put(context.Background(), testKey, []byte("payload"))
	if err == nil {
		t.Fatal("Put: want error, got nil")
	}
	if strings.Contains(err.Error(), testKey) {
		t.Errorf("error %q contains the key", err.Error())
	}
}

func TestWithHTTPClientOverridesTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	custom := &http.Client{Timeout: 3 * time.Second}
	c, err := dhtproxy.New([]string{srv.URL}, dhtproxy.WithTimeout(1*time.Nanosecond), dhtproxy.WithHTTPClient(custom))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.Get(context.Background(), testKey); err != nil {
		t.Fatalf("Get: %v (WithHTTPClient should have overridden the 1ns timeout)", err)
	}
}
