package sarif

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSafeURIKeepsWhatAScannerReports(t *testing.T) {
	kept := []string{
		"https://example.test/login",
		"http://10.0.0.5:8080/admin",
		"example.test",
		"192.168.1.10:443",
		"src/main.go",
		"docs/guide.md",
	}

	for _, uri := range kept {
		if got := safeURI(uri); got != uri {
			t.Errorf("safeURI(%q) = %q, want it kept", uri, got)
		}
	}
}

func TestSafeURIDropsLocationsThatCouldMisplaceAnAnnotation(t *testing.T) {
	// Consumers such as GitHub code scanning annotate files by this URI, so a
	// crafted findings file must not be able to point one at an arbitrary
	// path or a non-web scheme.
	dropped := []string{
		"../../.github/workflows/ci.yml",
		"../secrets.env",
		"a/../../b",
		"/etc/passwd",
		`\windows\system32`,
		"file:///etc/passwd",
		"javascript:alert(1)",
		"data:text/html,<script>",
		"vbscript:msgbox",
		"jar:file:///x!/y",
		"ftp://example.test/x",
		"   ",
		"",
	}

	for _, uri := range dropped {
		if got := safeURI(uri); got != "" {
			t.Errorf("safeURI(%q) = %q, want it dropped", uri, got)
		}
	}
}

func TestSafeURIIgnoresSchemeCase(t *testing.T) {
	for _, uri := range []string{"FILE:///etc/passwd", "JavaScript:alert(1)"} {
		if got := safeURI(uri); got != "" {
			t.Errorf("safeURI(%q) = %q, want it dropped", uri, got)
		}
	}
	if got := safeURI("HTTPS://example.test/x"); got != "HTTPS://example.test/x" {
		t.Errorf("safeURI kept-case = %q", got)
	}
}

func TestConvertOmitsAnUnsafeLocation(t *testing.T) {
	findings := []Finding{{
		CVE:      "CVE-2021-44228",
		Severity: Critical,
		Target:   "../../.github/workflows/ci.yml",
	}}

	out, err := Marshal(findings, ToolInfo{Name: "test"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(out), "..") {
		t.Errorf("unsafe target reached the report:\n%s", out)
	}

	var log map[string]any
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestConvertKeepsASafeLocation(t *testing.T) {
	findings := []Finding{{
		CVE:      "CVE-2021-44228",
		Severity: Critical,
		Target:   "https://example.test/login",
	}}

	out, err := Marshal(findings, ToolInfo{Name: "test"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(out), "https://example.test/login") {
		t.Errorf("safe target missing from the report:\n%s", out)
	}
}
