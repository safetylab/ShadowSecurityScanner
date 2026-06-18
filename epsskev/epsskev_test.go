package epsskev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const epssJSON = `{
  "status": "OK",
  "data": [
    {"cve": "CVE-2017-0144", "epss": "0.97000", "percentile": "0.99900", "date": "2026-06-17"},
    {"cve": "CVE-2024-6387", "epss": "0.92000", "percentile": "0.99000", "date": "2026-06-17"},
    {"cve": "CVE-2099-0001", "epss": "0.04000", "percentile": "0.20000", "date": "2026-06-17"}
  ]
}`

const kevJSON = `{
  "title": "CISA Catalog",
  "catalogVersion": "2026.06.17",
  "count": 2,
  "vulnerabilities": [
    {"cveID": "CVE-2017-0144", "vendorProject": "Microsoft", "product": "SMBv1", "vulnerabilityName": "EternalBlue", "dateAdded": "2022-03-25"},
    {"cveID": "CVE-2024-6387", "vendorProject": "OpenBSD", "product": "OpenSSH", "vulnerabilityName": "regreSSHion", "dateAdded": "2024-07-01"}
  ]
}`

// newTestClient spins up an httptest server serving canned EPSS and KEV responses.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/epss":
			_, _ = w.Write([]byte(epssJSON))
		case "/kev":
			_, _ = w.Write([]byte(kevJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return NewClient(
		WithEPSSBaseURL(srv.URL+"/epss"),
		WithKEVURL(srv.URL+"/kev"),
	)
}

func TestEnrich(t *testing.T) {
	c := newTestClient(t)
	findings := []Finding{
		{CVE: "cve-2099-0001", CVSS: 9.8}, // high CVSS, low EPSS, not in KEV
		{CVE: "CVE-2017-0144", CVSS: 9.3}, // KEV + very high EPSS
		{CVE: "CVE-2024-6387", CVSS: 8.1}, // KEV + high EPSS
		{CVE: "CVE-2000-9999", CVSS: 5.0}, // unknown to both feeds
	}

	got, err := Enrich(context.Background(), c, findings)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(got) != len(findings) {
		t.Fatalf("len = %d, want %d", len(got), len(findings))
	}

	byCVE := map[string]EnrichedFinding{}
	for _, f := range got {
		byCVE[normaliseCVE(f.CVE)] = f
	}

	if e := byCVE["CVE-2017-0144"]; !e.InKEV || e.EPSS != 0.97 || !e.Known {
		t.Errorf("CVE-2017-0144 = %+v, want InKEV, EPSS 0.97, Known", e)
	}
	if e := byCVE["CVE-2099-0001"]; e.InKEV || e.EPSS != 0.04 {
		t.Errorf("CVE-2099-0001 = %+v, want not InKEV, EPSS 0.04", e)
	}
	if e := byCVE["CVE-2000-9999"]; e.Known || e.InKEV || e.EPSS != 0 {
		t.Errorf("CVE-2000-9999 = %+v, want unknown/zero", e)
	}
}

func TestPrioritise(t *testing.T) {
	c := newTestClient(t)
	findings := []Finding{
		{CVE: "CVE-2099-0001", CVSS: 9.8},
		{CVE: "CVE-2024-6387", CVSS: 8.1},
		{CVE: "CVE-2017-0144", CVSS: 9.3},
	}
	got, err := EnrichAndPrioritise(context.Background(), c, findings)
	if err != nil {
		t.Fatalf("EnrichAndPrioritise: %v", err)
	}

	want := []string{"CVE-2017-0144", "CVE-2024-6387", "CVE-2099-0001"}
	for i, w := range want {
		if normaliseCVE(got[i].CVE) != w {
			t.Errorf("rank %d = %s, want %s (order: %v)", i, got[i].CVE, w, order(got))
		}
	}
}

func TestPrioritiseTieBreakCVSS(t *testing.T) {
	// Two non-KEV, equal-EPSS findings should fall back to CVSS, descending.
	fs := []EnrichedFinding{
		{Finding: Finding{CVE: "CVE-A", CVSS: 5.0}, Enrichment: Enrichment{EPSS: 0.1}},
		{Finding: Finding{CVE: "CVE-B", CVSS: 7.5}, Enrichment: Enrichment{EPSS: 0.1}},
	}
	Prioritise(fs)
	if normaliseCVE(fs[0].CVE) != "CVE-B" {
		t.Errorf("CVSS tie-break failed: got %v", order(fs))
	}
}

func order(fs []EnrichedFinding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.CVE
	}
	return out
}

func TestChunk(t *testing.T) {
	got := chunk([]string{"a", "b", "c", "d", "e"}, 2)
	if len(got) != 3 || len(got[0]) != 2 || len(got[2]) != 1 {
		t.Errorf("chunk = %v", got)
	}
}
