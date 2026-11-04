package epsskev

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveJSON returns a client pointed at a server that answers both endpoints
// with the given bodies.
func serveJSON(t *testing.T, epssBody, kevBody string, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/epss":
			_, _ = w.Write([]byte(epssBody))
		case "/kev":
			_, _ = w.Write([]byte(kevBody))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	all := append([]Option{
		WithEPSSBaseURL(srv.URL + "/epss"),
		WithKEVURL(srv.URL + "/kev"),
	}, opts...)
	return NewClient(all...)
}

func TestFetchKEVRejectsOversizedBody(t *testing.T) {
	// A body larger than the limit must fail rather than being decoded as if
	// it were the whole catalog.
	padding := strings.Repeat(" ", 4096)
	body := fmt.Sprintf(`{"title":"x","count":0,"vulnerabilities":[]%s}`, padding)

	c := serveJSON(t, "{}", body, WithMaxResponseBytes(512))

	if _, err := c.FetchKEV(context.Background()); err == nil {
		t.Fatal("FetchKEV accepted a body over the limit")
	}
}

func TestFetchEPSSRejectsOversizedBody(t *testing.T) {
	padding := strings.Repeat(" ", 4096)
	body := fmt.Sprintf(`{"status":"OK","data":[]%s}`, padding)

	c := serveJSON(t, body, "{}", WithMaxResponseBytes(512))

	_, err := c.FetchEPSS(context.Background(), []string{"CVE-2021-44228"})
	if err == nil {
		t.Fatal("FetchEPSS accepted a body over the limit")
	}
}

func TestBodyWithinTheLimitIsAccepted(t *testing.T) {
	kev := `{"title":"x","count":1,"vulnerabilities":[
		{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j",
		 "vulnerabilityName":"Log4Shell","dateAdded":"2021-12-10"}]}`

	c := serveJSON(t, "{}", kev, WithMaxResponseBytes(1<<20))

	got, err := c.FetchKEV(context.Background())
	if err != nil {
		t.Fatalf("FetchKEV: %v", err)
	}
	if _, ok := got["CVE-2021-44228"]; !ok {
		t.Errorf("entry missing: %v", got)
	}
}

func TestUnparseableScoreIsDroppedNotZeroed(t *testing.T) {
	// Zero is not "unknown": it sorts a finding to the bottom of a fix-first
	// ranking, so a parsing failure must not look like a safe score.
	epss := `{"status":"OK","data":[
		{"cve":"CVE-2021-44228","epss":"not-a-number","percentile":"0.9","date":"2026-01-01"},
		{"cve":"CVE-2024-6387","epss":"0.92","percentile":"0.99","date":"2026-01-01"}]}`

	c := serveJSON(t, epss, "{}")

	got, err := c.FetchEPSS(context.Background(), []string{"CVE-2021-44228", "CVE-2024-6387"})
	if err != nil {
		t.Fatalf("FetchEPSS: %v", err)
	}
	if _, ok := got["CVE-2021-44228"]; ok {
		t.Error("a score that failed to parse was recorded anyway")
	}
	if got["CVE-2024-6387"].EPSS != 0.92 {
		t.Errorf("valid score lost: %+v", got["CVE-2024-6387"])
	}
}

func TestMalformedIdentifiersAreNotRequested(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Query().Get("cve")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"OK","data":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(WithEPSSBaseURL(srv.URL), WithKEVURL(srv.URL))
	findings := []Finding{
		{CVE: "CVE-2021-44228"},
		{CVE: "not a cve"},
		{CVE: "CVE-A"},
		{CVE: ""},
	}

	if _, err := Enrich(context.Background(), c, findings); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if asked != "CVE-2021-44228" {
		t.Errorf("requested %q, want only the well-formed identifier", asked)
	}
}

func TestMalformedIdentifiersStillAppearInOutput(t *testing.T) {
	// They are simply unenriched: dropping the finding would hide it.
	c := serveJSON(t, `{"status":"OK","data":[]}`, `{"vulnerabilities":[]}`)
	findings := []Finding{{CVE: "CVE-2021-44228"}, {CVE: "junk"}}

	got, err := Enrich(context.Background(), c, findings)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[1].Known || got[1].InKEV {
		t.Errorf("malformed finding was enriched: %+v", got[1])
	}
}

func TestIsCVE(t *testing.T) {
	valid := []string{
		"CVE-2021-44228",
		"CVE-1999-0001",
		"CVE-2026-1234567",
	}
	invalid := []string{
		"", "CVE-A", "CVE-21-44228", "CVE-2021-123", "cve-2021-44228",
		"CVE-2021-44228 OR 1=1", "../../etc/passwd", "CVE-2021-44228\n",
	}

	for _, id := range valid {
		if !isCVE(id) {
			t.Errorf("isCVE(%q) = false, want true", id)
		}
	}
	for _, id := range invalid {
		if isCVE(id) {
			t.Errorf("isCVE(%q) = true, want false", id)
		}
	}
}

func TestResponseLimitDefaultsAndOverrides(t *testing.T) {
	if got := NewClient().responseLimit(); got != DefaultMaxResponseBytes {
		t.Errorf("default limit = %d, want %d", got, DefaultMaxResponseBytes)
	}
	if got := NewClient(WithMaxResponseBytes(99)).responseLimit(); got != 99 {
		t.Errorf("override = %d, want 99", got)
	}
	if got := NewClient(WithMaxResponseBytes(-1)).responseLimit(); got >= 0 {
		t.Errorf("negative limit = %d, want it to stay negative (disabled)", got)
	}
	// The zero value of the field, not of the client, selects the default.
	c := &Client{}
	if got := c.responseLimit(); got != DefaultMaxResponseBytes {
		t.Errorf("zero field = %d, want %d", got, DefaultMaxResponseBytes)
	}
}
