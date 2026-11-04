package epsskev

import (
	"io"
	"net/http"
	"time"
)

// Default endpoints for the public data sources.
const (
	// DefaultEPSSBaseURL is the FIRST.org EPSS API.
	DefaultEPSSBaseURL = "https://api.first.org/data/v1/epss"
	// DefaultKEVURL is the CISA Known Exploited Vulnerabilities JSON feed.
	DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// epssBatchSize caps how many CVEs are requested per EPSS API call to keep
	// the query string within sane limits.
	epssBatchSize = 100
	// DefaultMaxResponseBytes bounds how much of a response body is read.
	// Both sources are external and neither is under our control: the KEV
	// catalog is a few megabytes today, but a misbehaving endpoint or a proxy
	// can stream without end, and an unbounded decode would exhaust memory on
	// the operator's machine.
	DefaultMaxResponseBytes int64 = 64 << 20 // 64 MiB
)

// Client fetches EPSS scores and the CISA KEV catalog over HTTP. The zero value
// is not usable; construct one with NewClient.
type Client struct {
	HTTP        *http.Client
	EPSSBaseURL string
	KEVURL      string
	UserAgent   string
	// MaxResponseBytes bounds each response body. Zero selects
	// DefaultMaxResponseBytes; a negative value disables the limit.
	MaxResponseBytes int64
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets a custom *http.Client (e.g. with a proxy or timeout).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.HTTP = h } }

// WithEPSSBaseURL overrides the EPSS API base URL (useful for tests).
func WithEPSSBaseURL(u string) Option { return func(c *Client) { c.EPSSBaseURL = u } }

// WithKEVURL overrides the KEV feed URL (useful for tests).
func WithKEVURL(u string) Option { return func(c *Client) { c.KEVURL = u } }

// WithUserAgent sets the User-Agent header sent with requests.
func WithUserAgent(ua string) Option { return func(c *Client) { c.UserAgent = ua } }

// WithMaxResponseBytes overrides how much of a response body is read. A
// negative value disables the limit.
func WithMaxResponseBytes(n int64) Option { return func(c *Client) { c.MaxResponseBytes = n } }

// NewClient returns a Client with sensible defaults, customised by opts.
func NewClient(opts ...Option) *Client {
	c := &Client{
		HTTP:             &http.Client{Timeout: 30 * time.Second},
		EPSSBaseURL:      DefaultEPSSBaseURL,
		KEVURL:           DefaultKEVURL,
		UserAgent:        "epss-kev-prioritizer/1.0 (+https://github.com/safetylab/ShadowSecurityScanner)",
		MaxResponseBytes: DefaultMaxResponseBytes,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// responseLimit returns the effective body limit, or a negative value when the
// limit is disabled.
func (c *Client) responseLimit() int64 {
	if c.MaxResponseBytes == 0 {
		return DefaultMaxResponseBytes
	}
	return c.MaxResponseBytes
}

// limitedBody wraps a response body so a decode cannot read without end, and
// reports how much was read. One byte past the limit is allowed through so the
// caller can tell "exactly at the limit" from "truncated".
func (c *Client) limitedBody(r io.Reader) (io.Reader, *countingReader) {
	counter := &countingReader{r: r}
	limit := c.responseLimit()
	if limit < 0 {
		return counter, counter
	}
	return io.LimitReader(counter, limit+1), counter
}

// truncated reports whether the body hit the cap, which means the data is
// incomplete and must not be treated as the whole catalog.
func (c *Client) truncated(read int64) bool {
	limit := c.responseLimit()
	return limit >= 0 && read > limit
}

// countingReader records how many bytes were read through it, so the caller
// can tell a complete body from one cut off at the limit.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
