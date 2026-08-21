// Package dhtproxy is an HTTP client for the OpenDHT dhtproxy REST API.
//
// The dhtproxy exposes two endpoints for one key:
//
//	GET  {base}/{key}   returns the values stored under key as
//	                     newline-delimited JSON, one object per line.
//	                     Each line carries at least a "data" field with
//	                     the value encoded as base64. Other fields
//	                     (id, type, seq, ...) exist and are ignored. An
//	                     empty body or a 404 status means no values.
//	POST {base}/{key}   stores one value. The body is a JSON object
//	                     {"data": "<base64>"}. Any 2xx status is success.
//
// Get tries each configured base URL in order. A 404, or a 2xx
// response with no values, is not treated as the final answer: Put can
// partially fail, so a later proxy may still hold the value. Get keeps
// trying the remaining base URLs and returns the first one that yields
// at least one value. If every base URL answers (2xx or 404) and none
// has a value, Get returns an empty Result with a nil error, and URL
// set to the last base URL tried: every proxy was reachable, so an
// empty result means nothing was published. A connection error, a 5xx
// status, or a timeout moves on to the next base URL instead. If that
// leaves at least one base URL that did answer, but empty, Get
// returns that empty Result together with a *PartialError wrapping
// the per-host failures, so a majority outage is distinguishable from
// "nothing published". If every base URL fails that way, Get returns
// an empty Result and a plain error joining every per-host failure.
// Put writes to every base URL, because the controller must reach
// every proxy instance (PLAN 2.5).
//
// A key names a DHT record and is part of a rendezvous secret. This
// package never puts a key, or the data associated with it, into an
// error message; errors name only the proxy host. Get and Put reject
// a key that is not exactly 40 lowercase hex characters (the
// internal/dhtkey format) with ErrBadKey, before it ever reaches a
// URL.
//
// The dhtproxy protocol allows more than one value under one key.
// OpenDHT caps that count (PLAN 4.6); Get enforces the same cap by
// default and reports how many values it dropped or skipped.
package dhtproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// defaultTimeout is the request timeout used by the client built
	// by New when no http.Client is supplied via WithHTTPClient.
	defaultTimeout = 10 * time.Second

	// defaultMaxValues is the default cap on the number of values Get
	// returns for one key (PLAN 4.6).
	defaultMaxValues = 64

	// maxLineSize is the largest newline-delimited JSON line Get
	// accepts.
	maxLineSize = 1 << 20 // 1 MiB
)

// Client is an HTTP client for the dhtproxy REST API. It holds an
// ordered list of proxy base URLs. Create one with New.
type Client struct {
	baseURLs    []string
	httpClient  *http.Client
	maxValues   int
	maxLineSize int
}

// config collects Option values before New builds the Client.
type config struct {
	httpClient  *http.Client
	timeout     time.Duration
	maxValues   int
	maxLineSize int
}

// Option configures a Client built by New.
type Option func(*config)

// WithHTTPClient sets the http.Client used for every request. It
// overrides WithTimeout, since the caller now owns request timing.
// Tests use this to point the client at an httptest.Server.
func WithHTTPClient(hc *http.Client) Option {
	return func(cfg *config) { cfg.httpClient = hc }
}

// WithTimeout sets the per-request timeout of the client New builds.
// It has no effect when WithHTTPClient is also given. Default: 10s.
func WithTimeout(d time.Duration) Option {
	return func(cfg *config) { cfg.timeout = d }
}

// WithMaxValues sets the cap on the number of values Get returns for
// one key (PLAN 4.6). Default: 64.
func WithMaxValues(n int) Option {
	return func(cfg *config) { cfg.maxValues = n }
}

// New builds a Client for the given ordered list of dhtproxy base
// URLs. It returns an error if baseURLs is empty, or if any entry
// fails to parse as a URL with a scheme and a host. A trailing "/" on
// each base URL is trimmed.
func New(baseURLs []string, opts ...Option) (*Client, error) {
	if len(baseURLs) == 0 {
		return nil, errors.New("dhtproxy: base URL list must not be empty")
	}

	trimmed := make([]string, 0, len(baseURLs))
	for _, b := range baseURLs {
		u, err := url.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("dhtproxy: invalid base URL %q: %w", b, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("dhtproxy: base URL %q must have a scheme and a host", b)
		}
		trimmed = append(trimmed, strings.TrimRight(b, "/"))
	}

	cfg := config{
		timeout:     defaultTimeout,
		maxValues:   defaultMaxValues,
		maxLineSize: maxLineSize,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.maxValues < 1 {
		return nil, fmt.Errorf("dhtproxy: max values must be at least 1, got %d", cfg.maxValues)
	}

	hc := cfg.httpClient
	if hc == nil {
		hc = &http.Client{Timeout: cfg.timeout}
	}

	return &Client{
		baseURLs:    trimmed,
		httpClient:  hc,
		maxValues:   cfg.maxValues,
		maxLineSize: cfg.maxLineSize,
	}, nil
}

// ErrBadKey is returned by Get and Put when key is not a well-formed
// dhtkey: exactly 40 lowercase hex characters (internal/dhtkey's
// output format). The bad key itself is never included in the error,
// since it is part of a rendezvous secret.
var ErrBadKey = errors.New("dhtproxy: key must be 40 lowercase hex characters")

// isHexKey reports whether key is exactly 40 lowercase hex characters,
// the format internal/dhtkey produces.
func isHexKey(key string) bool {
	if len(key) != 40 {
		return false
	}
	for _, r := range key {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// Result is the outcome of a successful Get.
type Result struct {
	// Values holds the decoded value bytes, in the order they were
	// returned, up to the client's maxValues cap.
	Values [][]byte
	// Skipped counts lines that could not be parsed: invalid JSON,
	// missing "data", or invalid base64.
	Skipped int
	// Dropped counts valid values received after the cap was reached.
	Dropped int
	// URL is the base URL that answered the request.
	URL string
}

// Get fetches the values stored under key. It tries each base URL in
// order and returns the result of the first one that yields at least
// one value. A 404, or a 2xx response with no values, does not stop
// the search: Put can partially fail, so a later proxy may still hold
// the value (PLAN 2.5). If every base URL answers and none has a
// value, Get returns an empty Result with a nil error, and URL set to
// the last base URL tried. If some base URLs fail (connection error or
// unexpected status) while at least one that did answer had no value,
// Get returns that empty Result with a *PartialError, so the caller
// can tell a majority outage apart from "nothing published". If every
// base URL fails, Get returns an empty Result and a plain error.
func (c *Client) Get(ctx context.Context, key string) (Result, error) {
	if !isHexKey(key) {
		return Result{}, ErrBadKey
	}

	var errs []error
	var empty *Result

	for _, base := range c.baseURLs {
		reqURL := base + "/" + key

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			errs = append(errs, wrapHostError(base, err))
			continue
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			errs = append(errs, wrapHostError(base, err))
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			drainAndClose(resp.Body)
			r := Result{URL: base}
			empty = &r
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			drainAndClose(resp.Body)
			errs = append(errs, hostStatusError(base, resp.StatusCode))
			continue
		}

		result, err := c.parseValues(resp.Body, base)
		drainAndClose(resp.Body)
		if err != nil {
			errs = append(errs, wrapHostError(base, err))
			continue
		}

		if len(result.Values) == 0 {
			empty = &result
			continue
		}

		return result, nil
	}

	if empty != nil {
		if len(errs) > 0 {
			// Some proxies were unreachable or errored, and the rest
			// answered empty. That is a partial outage, not proof
			// nothing was published: report it instead of returning a
			// nil error indistinguishable from "nothing published".
			return *empty, &PartialError{Op: "get", Errs: errs}
		}
		return *empty, nil
	}

	return Result{}, fmt.Errorf("dhtproxy: get failed on all proxies: %w", errors.Join(errs...))
}

// parseValues reads a newline-delimited JSON body and decodes each
// line's "data" field. A line over maxLineSize counts as one Skipped
// value. Unlike bufio.Scanner (whose default line reader stops for
// good on a too-long line), parseValues discards the rest of an
// oversized line up to its terminating newline (or EOF) and keeps
// reading, so every valid line before and after an oversized one is
// still returned.
func (c *Client) parseValues(body io.Reader, base string) (Result, error) {
	result := Result{URL: base}

	r := bufio.NewReaderSize(body, 64*1024)
	for {
		line, oversized, err := readLine(r, c.maxLineSize)
		if err != nil && err != io.EOF {
			return Result{}, err
		}

		switch {
		case oversized:
			result.Skipped++
		case len(line) > 0:
			c.decodeLine(line, &result)
		}

		if err == io.EOF {
			break
		}
	}

	return result, nil
}

// readLine reads one newline-delimited line from r, without
// bufio.Scanner's all-or-nothing internal buffer limit. The line's
// terminator ("\n" or "\r\n") does not count against maxLen: only the
// content is measured. If that content is longer than maxLen bytes,
// oversized is true, line is nil, and the excess bytes up to the next
// '\n' (or EOF) are discarded so the next call reads the following
// line. err is io.EOF only once r has no more data to offer; a final
// line with content but no trailing newline is still returned with
// err set to io.EOF alongside it.
func readLine(r *bufio.Reader, maxLen int) (line []byte, oversized bool, err error) {
	var buf []byte
	for {
		chunk, e := r.ReadSlice('\n')
		if len(buf) <= maxLen+1 {
			buf = append(buf, chunk...)
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		err = e
		break
	}

	content := buf
	if n := len(content); n > 0 && content[n-1] == '\n' {
		content = content[:n-1]
		if n := len(content); n > 0 && content[n-1] == '\r' {
			content = content[:n-1]
		}
	}

	if len(content) > maxLen {
		return nil, true, err
	}

	content = bytes.TrimSpace(content)
	if len(content) == 0 && err == io.EOF {
		return nil, false, io.EOF
	}
	return content, false, err
}

// decodeLine decodes one already-trimmed, non-empty line into result,
// counting a Skipped or Dropped value as appropriate. Once the cap
// (c.maxValues) is reached, decodeLine still decodes the line to tell
// a valid value from a malformed one: only a line that decodes
// successfully counts as Dropped ("valid values received after the
// cap", per Result.Dropped's doc); a malformed line still counts as
// Skipped, cap or no cap.
func (c *Client) decodeLine(line []byte, result *Result) {
	var obj struct {
		Data *string `json:"data"`
	}
	if err := json.Unmarshal(line, &obj); err != nil || obj.Data == nil {
		result.Skipped++
		return
	}

	data, err := base64.StdEncoding.DecodeString(*obj.Data)
	if err != nil {
		result.Skipped++
		return
	}

	if len(result.Values) >= c.maxValues {
		result.Dropped++
		return
	}

	result.Values = append(result.Values, data)
}

// PartialError reports a partial failure across the configured base
// URLs: from Put, that it succeeded on some base URLs and failed on
// others; from Get, that some base URLs were unreachable or errored
// while every base URL that did answer had no value, which makes an
// empty Result ambiguous between "an outage" and "nothing published".
// Op is "put" or "get". Errs holds one error for each URL that
// failed.
type PartialError struct {
	Op   string
	Errs []error
}

// Error implements the error interface.
func (e *PartialError) Error() string {
	return fmt.Sprintf("dhtproxy: %s failed on %d of the proxies: %s", e.Op, len(e.Errs), errors.Join(e.Errs...))
}

// Unwrap lets errors.Is and errors.As see the per-URL errors.
func (e *PartialError) Unwrap() []error {
	return e.Errs
}

// Put stores data under key on every configured base URL, one POST per
// URL, run concurrently so the wall-clock cost is one request's
// latency rather than the sum of all of them. It returns nil when
// every URL succeeds, a *PartialError when some succeed and some
// fail, and a plain error when all fail.
func (c *Client) Put(ctx context.Context, key string, data []byte) error {
	if !isHexKey(key) {
		return ErrBadKey
	}

	payload, err := json.Marshal(struct {
		Data string `json:"data"`
	}{Data: base64.StdEncoding.EncodeToString(data)})
	if err != nil {
		return fmt.Errorf("dhtproxy: encode put body: %w", err)
	}

	putErrs := make([]error, len(c.baseURLs))
	var wg sync.WaitGroup
	for i, base := range c.baseURLs {
		wg.Add(1)
		go func(i int, base string) {
			defer wg.Done()
			putErrs[i] = c.put(ctx, base, key, payload)
		}(i, base)
	}
	wg.Wait()

	var errs []error
	successes := 0
	for _, err := range putErrs {
		if err != nil {
			errs = append(errs, err)
			continue
		}
		successes++
	}

	switch {
	case len(errs) == 0:
		return nil
	case successes > 0:
		return &PartialError{Op: "put", Errs: errs}
	default:
		return fmt.Errorf("dhtproxy: put failed on all proxies: %w", errors.Join(errs...))
	}
}

// put sends one POST request to base and reports success as a nil
// error.
func (c *Client) put(ctx context.Context, base, key string, payload []byte) error {
	reqURL := base + "/" + key

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payload))
	if err != nil {
		return wrapHostError(base, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return wrapHostError(base, err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return hostStatusError(base, resp.StatusCode)
	}

	return nil
}

// drainAndClose discards and closes a response body so the
// connection can be reused.
func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}

// wrapHostError names the proxy host in err without repeating the
// request URL, which would include the key.
func wrapHostError(base string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return fmt.Errorf("%s: %w", hostOf(base), err)
}

// hostStatusError reports an unexpected HTTP status from a proxy.
func hostStatusError(base string, status int) error {
	return fmt.Errorf("%s: unexpected status %d", hostOf(base), status)
}

// hostOf returns the host part of a base URL, falling back to the
// full base string if it does not parse.
func hostOf(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return base
	}
	return u.Host
}
