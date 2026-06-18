package sarif

import (
	"encoding/json"
	"testing"
)

func sampleFindings() []Finding {
	return []Finding{
		{CVE: "CVE-2021-44228", Title: "Log4Shell", Severity: Critical, CVSS: 10.0, Target: "10.0.0.5:8080", InKEV: true, EPSS: 0.97},
		{CVE: "CVE-2019-20372", Title: "nginx error_page", Severity: Medium, CVSS: 5.3, Target: "10.0.0.6"},
		{CVE: "CVE-2021-44228", Title: "Log4Shell", Severity: Critical, CVSS: 10.0, Target: "10.0.0.9:80", InKEV: true}, // same CVE, 2nd host
	}
}

func TestConvertShape(t *testing.T) {
	log := Convert(sampleFindings(), DefaultTool)

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if log.Schema == "" {
		t.Error("missing $schema")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "ShadowSecurityScanner" {
		t.Errorf("tool name = %q", run.Tool.Driver.Name)
	}
	// 2 distinct CVEs => 2 rules, 3 findings => 3 results.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("rules = %d, want 2", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Errorf("results = %d, want 3", len(run.Results))
	}
}

func TestLevelMapping(t *testing.T) {
	cases := map[Severity]string{
		Critical: "error", High: "error", Medium: "warning", Low: "note", Info: "note",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%s) = %s, want %s", sev, got, want)
		}
	}
}

func TestSecuritySeverityAndHelpURI(t *testing.T) {
	log := Convert(sampleFindings(), DefaultTool)
	rules := log.Runs[0].Tool.Driver.Rules

	var log4shell *ReportingDescriptor
	for i := range rules {
		if rules[i].ID == "CVE-2021-44228" {
			log4shell = &rules[i]
		}
	}
	if log4shell == nil {
		t.Fatal("CVE-2021-44228 rule not found")
	}
	if log4shell.HelpURI != "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" {
		t.Errorf("helpUri = %q", log4shell.HelpURI)
	}
	if ss, _ := log4shell.Properties["security-severity"].(string); ss != "10.0" {
		t.Errorf("security-severity = %v, want 10.0", log4shell.Properties["security-severity"])
	}
}

func TestKEVProperty(t *testing.T) {
	log := Convert(sampleFindings(), DefaultTool)
	first := log.Runs[0].Results[0]
	if first.RuleID != "CVE-2021-44228" {
		t.Fatalf("first result ruleId = %s", first.RuleID)
	}
	if kev, _ := first.Properties["cisa-kev"].(bool); !kev {
		t.Errorf("expected cisa-kev=true on KEV finding, got %v", first.Properties)
	}
}

func TestMarshalValidJSON(t *testing.T) {
	b, err := Marshal(sampleFindings(), ToolInfo{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if generic["version"] != "2.1.0" {
		t.Errorf("round-trip version = %v", generic["version"])
	}
}

func TestSortFindings(t *testing.T) {
	fs := []Finding{
		{CVE: "CVE-B", CVSS: 5.0},
		{CVE: "CVE-A", CVSS: 9.0, InKEV: true},
		{CVE: "CVE-C", CVSS: 9.5},
	}
	SortFindings(fs)
	if fs[0].CVE != "CVE-A" { // KEV first even with lower CVSS
		t.Errorf("KEV not first: %s", fs[0].CVE)
	}
	if fs[1].CVE != "CVE-C" || fs[2].CVE != "CVE-B" { // then CVSS desc
		t.Errorf("CVSS order wrong: %s,%s", fs[1].CVE, fs[2].CVE)
	}
}
