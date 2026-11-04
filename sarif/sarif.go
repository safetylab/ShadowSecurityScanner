// Package vulnsarif converts vulnerability findings into a SARIF 2.1.0 log that
// tools like GitHub code scanning can ingest.
//
// It is a small, dependency-free helper extracted from ShadowSecurityScanner
// (https://shadowsecurityscanner.com/): give it a list
// of findings (CVE, severity, target, optional EPSS/KEV signals) and it produces a
// valid SARIF document with per-CVE rules and GitHub-compatible security-severity.
package sarif

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Severity is a normalised severity label.
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

// Finding is a single vulnerability finding to encode.
type Finding struct {
	CVE         string   // e.g. "CVE-2021-44228" (used as the SARIF ruleId)
	Title       string   // short human title; defaults to the CVE if empty
	Severity    Severity // CRITICAL/HIGH/MEDIUM/LOW/INFO
	CVSS        float64  // base score 0..10 (exported as security-severity)
	Target      string   // host/URL where the finding was observed
	Description string   // longer description / evidence
	EPSS        float64  // optional EPSS probability [0,1]
	InKEV       bool     // optional: listed in CISA KEV
}

// ToolInfo describes the analysis tool recorded in the SARIF run.
type ToolInfo struct {
	Name           string
	Version        string
	InformationURI string
}

// DefaultTool identifies ShadowSecurityScanner.
var DefaultTool = ToolInfo{
	Name:           "ShadowSecurityScanner",
	Version:        "1.1.1",
	InformationURI: "https://shadowsecurityscanner.com/",
}

// unsafeSchemes are schemes an artifact location must never carry into a
// report another tool will render or follow.
var unsafeSchemes = []string{
	"file:", "javascript:", "data:", "vbscript:", "jar:",
}

// safeURI returns target if it is usable as a SARIF artifact location, and ""
// if it is not.
//
// Consumers such as GitHub code scanning annotate files by this URI, so a
// crafted findings file carrying "../../.github/workflows/ci.yml" would place
// an annotation on an arbitrary path in whichever repository the report is
// uploaded to. Absolute paths, parent-directory segments and non-web schemes
// are therefore dropped; http(s) URLs, hostnames and plain relative paths —
// what a scanner actually reports — are kept.
func safeURI(target string) string {
	uri := strings.TrimSpace(target)
	if uri == "" {
		return ""
	}

	lower := strings.ToLower(uri)
	for _, scheme := range unsafeSchemes {
		if strings.HasPrefix(lower, scheme) {
			return ""
		}
	}

	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return uri
	}

	// Anything else must be a relative location: no other scheme, no absolute
	// path, no escaping upwards.
	if strings.Contains(uri, "://") || strings.HasPrefix(uri, "/") ||
		strings.HasPrefix(uri, `\`) {
		return ""
	}

	segments := strings.FieldsFunc(uri, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	if slices.Contains(segments, "..") {
		return ""
	}

	return uri
}

// sarifLevel maps a severity to a SARIF result level.
func sarifLevel(s Severity) string {
	switch Severity(strings.ToUpper(string(s))) {
	case Critical, High:
		return "error"
	case Medium:
		return "warning"
	case Low, Info:
		return "note"
	default:
		return "warning"
	}
}

// Convert builds a SARIF 2.1.0 Log from the given findings. Each distinct CVE
// becomes a reusable rule; every finding becomes a result referencing its rule.
func Convert(findings []Finding, tool ToolInfo) *Log {
	if tool.Name == "" {
		tool = DefaultTool
	}

	ruleIndex := map[string]int{}
	var rules []ReportingDescriptor
	var results []Result

	for _, f := range findings {
		id := strings.ToUpper(strings.TrimSpace(f.CVE))
		if id == "" {
			id = "UNKNOWN"
		}
		idx, ok := ruleIndex[id]
		if !ok {
			idx = len(rules)
			ruleIndex[id] = idx
			rules = append(rules, ruleFor(id, f))
		}

		text := f.Title
		if text == "" {
			text = id
		}
		if f.Description != "" {
			text = text + " — " + f.Description
		}

		res := Result{
			RuleID:    id,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   Message{Text: text},
		}
		if uri := safeURI(f.Target); uri != "" {
			res.Locations = []Location{{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{URI: uri},
				},
			}}
		}
		props := map[string]any{}
		if f.EPSS > 0 {
			props["epss"] = f.EPSS
		}
		if f.InKEV {
			props["cisa-kev"] = true
		}
		if len(props) > 0 {
			res.Properties = props
		}
		results = append(results, res)
	}

	return &Log{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{{
			Tool: Tool{Driver: Driver{
				Name:           tool.Name,
				Version:        tool.Version,
				InformationURI: tool.InformationURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

func ruleFor(id string, f Finding) ReportingDescriptor {
	name := f.Title
	if name == "" {
		name = id
	}
	rd := ReportingDescriptor{
		ID:               id,
		Name:             name,
		ShortDescription: Message{Text: name},
	}
	if strings.HasPrefix(id, "CVE-") {
		rd.HelpURI = "https://nvd.nist.gov/vuln/detail/" + id
	}
	// GitHub code scanning reads properties.security-severity (CVSS as a string)
	// and tags. Always tag as security; add the severity label too.
	props := map[string]any{"tags": []string{"security", strings.ToLower(string(f.Severity))}}
	if f.CVSS > 0 {
		props["security-severity"] = fmt.Sprintf("%.1f", f.CVSS)
	}
	rd.Properties = props
	return rd
}

// Marshal returns the indented SARIF JSON for the findings.
func Marshal(findings []Finding, tool ToolInfo) ([]byte, error) {
	return json.MarshalIndent(Convert(findings, tool), "", "  ")
}

// SortFindings orders findings KEV → CVSS → CVE for stable, readable output.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.InKEV != b.InKEV {
			return a.InKEV
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		return strings.ToUpper(a.CVE) < strings.ToUpper(b.CVE)
	})
}
