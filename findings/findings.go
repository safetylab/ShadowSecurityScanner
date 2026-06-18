// Package findings defines the canonical vulnerability-finding type used across
// ShadowSecurityScanner's open-source components, plus a Triage helper that ties
// the epsskev and sarif packages together: enrich findings with EPSS/CISA KEV,
// sort them fix-first, and produce SARIF-ready output.
package findings

import (
	"context"

	"github.com/safetylab/ShadowSecurityScanner/epsskev"
	"github.com/safetylab/ShadowSecurityScanner/sarif"
)

// Finding is the canonical input shape. It is intentionally minimal and JSON-friendly;
// see findings.schema.json for the formal schema.
type Finding struct {
	CVE         string  `json:"cve"`
	Title       string  `json:"title,omitempty"`
	Severity    string  `json:"severity,omitempty"` // CRITICAL/HIGH/MEDIUM/LOW/INFO
	CVSS        float64 `json:"cvss,omitempty"`     // 0..10
	Target      string  `json:"target,omitempty"`   // host/URL where observed
	Description string  `json:"description,omitempty"`
}

// Triage enriches each finding with EPSS and CISA KEV signals, then returns
// SARIF-ready findings sorted fix-first (KEV → CVSS → CVE). The Enricher is
// injected so callers can supply a real *epsskev.Client or a test double.
//
// Input order is preserved through enrichment; the final ordering is applied by
// sarif.SortFindings.
func Triage(ctx context.Context, e epsskev.Enricher, in []Finding) ([]sarif.Finding, error) {
	ek := make([]epsskev.Finding, len(in))
	for i, f := range in {
		ek[i] = epsskev.Finding{CVE: f.CVE, CVSS: f.CVSS, Severity: f.Severity}
	}

	enriched, err := epsskev.Enrich(ctx, e, ek)
	if err != nil {
		return nil, err
	}

	out := make([]sarif.Finding, len(in))
	for i, f := range in {
		out[i] = sarif.Finding{
			CVE:         f.CVE,
			Title:       f.Title,
			Severity:    sarif.Severity(f.Severity),
			CVSS:        f.CVSS,
			Target:      f.Target,
			Description: f.Description,
			EPSS:        enriched[i].EPSS,
			InKEV:       enriched[i].InKEV,
		}
	}
	sarif.SortFindings(out)
	return out, nil
}
