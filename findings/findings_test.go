package findings

import (
	"context"
	"testing"

	"github.com/safetylab/ShadowSecurityScanner/epsskev"
)

// mockEnricher implements epsskev.Enricher with canned data — no network.
type mockEnricher struct {
	epss map[string]epsskev.EPSSScore
	kev  map[string]epsskev.KEVEntry
}

func (m mockEnricher) FetchEPSS(_ context.Context, _ []string) (map[string]epsskev.EPSSScore, error) {
	return m.epss, nil
}
func (m mockEnricher) FetchKEV(_ context.Context) (map[string]epsskev.KEVEntry, error) {
	return m.kev, nil
}

func TestTriageEnrichesAndSorts(t *testing.T) {
	mock := mockEnricher{
		epss: map[string]epsskev.EPSSScore{
			"CVE-2017-0144": {EPSS: 0.97},
			"CVE-2099-0001": {EPSS: 0.04},
		},
		kev: map[string]epsskev.KEVEntry{
			"CVE-2017-0144": {CVE: "CVE-2017-0144", DateAdded: "2022-03-25"},
		},
	}

	in := []Finding{
		{CVE: "CVE-2099-0001", Title: "Obscure bug", Severity: "CRITICAL", CVSS: 9.8, Target: "10.0.0.2"},
		{CVE: "CVE-2017-0144", Title: "EternalBlue", Severity: "HIGH", CVSS: 8.1, Target: "10.0.0.3"},
	}

	out, err := Triage(context.Background(), mock, in)
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}

	// KEV finding must rank first despite lower CVSS.
	if out[0].CVE != "CVE-2017-0144" {
		t.Errorf("rank 0 = %s, want CVE-2017-0144", out[0].CVE)
	}
	if !out[0].InKEV {
		t.Error("expected InKEV on CVE-2017-0144")
	}
	// EPSS carried over and original metadata preserved.
	if out[0].EPSS != 0.97 || out[0].Title != "EternalBlue" || out[0].Target != "10.0.0.3" {
		t.Errorf("enrichment/metadata mismatch: %+v", out[0])
	}
}
