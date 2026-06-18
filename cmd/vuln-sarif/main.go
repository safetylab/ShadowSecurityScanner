// Command vuln-sarif converts a JSON array of vulnerability findings into a
// SARIF 2.1.0 document (e.g. for GitHub code scanning).
//
// Usage:
//
//	vuln-sarif < findings.json > results.sarif
//	vuln-sarif -in findings.json -tool "MyScanner" > results.sarif
//
// Input is a JSON array of objects:
//
//	[{"cve":"CVE-2021-44228","title":"Log4Shell","severity":"CRITICAL","cvss":10.0,
//	  "target":"10.0.0.5:8080","inKev":true,"epss":0.97}]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	vulnsarif "github.com/safetylab/shadowsecurityscanner/sarif"
)

// jsonFinding is the lowercase-friendly input shape.
type jsonFinding struct {
	CVE         string  `json:"cve"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	Target      string  `json:"target"`
	Description string  `json:"description"`
	EPSS        float64 `json:"epss"`
	InKEV       bool    `json:"inKev"`
}

func main() {
	in := flag.String("in", "", "input JSON file (default: stdin)")
	toolName := flag.String("tool", "", "tool name to record in the SARIF run")
	flag.Parse()

	data, err := readInput(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading input:", err)
		os.Exit(1)
	}

	var raw []jsonFinding
	if err := json.Unmarshal(data, &raw); err != nil {
		fmt.Fprintln(os.Stderr, "error: input must be a JSON array of findings:", err)
		os.Exit(1)
	}

	findings := make([]vulnsarif.Finding, 0, len(raw))
	for _, r := range raw {
		findings = append(findings, vulnsarif.Finding{
			CVE:         r.CVE,
			Title:       r.Title,
			Severity:    vulnsarif.Severity(r.Severity),
			CVSS:        r.CVSS,
			Target:      r.Target,
			Description: r.Description,
			EPSS:        r.EPSS,
			InKEV:       r.InKEV,
		})
	}
	vulnsarif.SortFindings(findings)

	tool := vulnsarif.ToolInfo{Name: *toolName}
	out, err := vulnsarif.Marshal(findings, tool)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error marshalling SARIF:", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}

func readInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}
