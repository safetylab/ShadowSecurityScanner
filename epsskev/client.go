package epsskev

import (
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
)

// Client fetches EPSS scores and the CISA KEV catalog over HTTP. The zero value
// is not usable; construct one with NewClient.
type Client struct {
	HTTP        *http.Client
	EPSSBaseURL string
	KEVURL      string
	UserAgent   string
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

// NewClient returns a Client with sensible defaults, customised by opts.
func NewClient(opts ...Option) *Client {
	c := &Client{
		HTTP:        &http.Client{Timeout: 30 * time.Second},
		EPSSBaseURL: DefaultEPSSBaseURL,
		KEVURL:      DefaultKEVURL,
		UserAgent:   "epss-kev-prioritizer/1.0 (+https://github.com/safetylab/ShadowSecurityScanner)",
	}
	for _, o := range opts {
		o(c)
	}
	return c
}
