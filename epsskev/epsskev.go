// Package epsskev enriches and prioritises CVE-based vulnerability findings by
// real-world exploitability using two public data sources:
//
//   - EPSS (Exploit Prediction Scoring System) from FIRST.org — the probability a
//     CVE will be exploited in the wild within the next 30 days.
//   - The CISA KEV (Known Exploited Vulnerabilities) catalog — CVEs confirmed to be
//     actively exploited.
//
// It turns a flat list of findings into a "fix-first" order: KEV → EPSS → CVSS.
// This is the prioritisation model used by ShadowSecurityScanner
// (https://andriigordiienko.github.io/ShadowSecurityScanner-site/), extracted as a
// standalone, dependency-free library.
package epsskev

import (
	"context"
	"sort"
	"strings"
)

// Finding is a vulnerability finding keyed by its CVE ID. CVSS and Severity are
// optional and only used as tie-breakers during prioritisation.
type Finding struct {
	CVE      string  // e.g. "CVE-2021-44228" (case-insensitive)
	CVSS     float64 // base score 0..10, optional
	Severity string  // optional free-form label (e.g. "CRITICAL")
}

// Enrichment holds the exploit-aware signals attached to a CVE.
type Enrichment struct {
	EPSS         float64 // exploit probability in [0,1]; 0 if unknown
	Percentile   float64 // EPSS percentile in [0,1]; 0 if unknown
	InKEV        bool    // true if listed in the CISA KEV catalog
	KEVDateAdded string  // date the CVE was added to KEV (YYYY-MM-DD), if known
	Known        bool    // true if EPSS data was found for this CVE
}

// EnrichedFinding is a Finding decorated with its exploit-aware signals.
type EnrichedFinding struct {
	Finding
	Enrichment
}

// Enricher fetches the exploit signals for a set of CVEs. *Client implements it.
type Enricher interface {
	FetchEPSS(ctx context.Context, cves []string) (map[string]EPSSScore, error)
	FetchKEV(ctx context.Context) (map[string]KEVEntry, error)
}

// normaliseCVE upper-cases and trims a CVE ID for consistent map keys.
func normaliseCVE(cve string) string {
	return strings.ToUpper(strings.TrimSpace(cve))
}

// Enrich attaches EPSS and KEV signals to each finding. It performs one batched
// EPSS lookup and one KEV catalog fetch, then merges the results. The returned
// slice preserves the input order; call Prioritise to sort it.
func Enrich(ctx context.Context, e Enricher, findings []Finding) ([]EnrichedFinding, error) {
	cves := make([]string, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		c := normaliseCVE(f.CVE)
		if c == "" {
			continue
		}
		if _, dup := seen[c]; !dup {
			seen[c] = struct{}{}
			cves = append(cves, c)
		}
	}

	epss, err := e.FetchEPSS(ctx, cves)
	if err != nil {
		return nil, err
	}
	kev, err := e.FetchKEV(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]EnrichedFinding, 0, len(findings))
	for _, f := range findings {
		c := normaliseCVE(f.CVE)
		ef := EnrichedFinding{Finding: f}
		if s, ok := epss[c]; ok {
			ef.EPSS = s.EPSS
			ef.Percentile = s.Percentile
			ef.Known = true
		}
		if k, ok := kev[c]; ok {
			ef.InKEV = true
			ef.KEVDateAdded = k.DateAdded
		}
		out = append(out, ef)
	}
	return out, nil
}

// Prioritise sorts findings in place into fix-first order:
//
//  1. KEV-listed findings first (confirmed active exploitation),
//  2. then by EPSS probability, descending,
//  3. then by CVSS, descending,
//  4. then by CVE ID for stable, deterministic output.
func Prioritise(findings []EnrichedFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.InKEV != b.InKEV {
			return a.InKEV // KEV entries rank first
		}
		if a.EPSS != b.EPSS {
			return a.EPSS > b.EPSS
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		return normaliseCVE(a.CVE) < normaliseCVE(b.CVE)
	})
}

// EnrichAndPrioritise is a convenience wrapper: enrich then sort.
func EnrichAndPrioritise(ctx context.Context, e Enricher, findings []Finding) ([]EnrichedFinding, error) {
	ef, err := Enrich(ctx, e, findings)
	if err != nil {
		return nil, err
	}
	Prioritise(ef)
	return ef, nil
}
