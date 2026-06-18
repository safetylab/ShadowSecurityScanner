// Command triage reads vulnerability findings as JSON, enriches them with EPSS and
// CISA KEV, sorts them fix-first, and prints either a table or a SARIF 2.1.0 report.
//
// Usage:
//
//	triage < findings.json                 # table, ranked
//	triage -format sarif < findings.json   # SARIF for GitHub code scanning
//	triage -in findings.json -format sarif > results.sarif
//
// Input matches findings.schema.json — a JSON array of {cve,title,severity,cvss,target,description}.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/safetylab/shadowsecurityscanner/epsskev"
	"github.com/safetylab/shadowsecurityscanner/findings"
	"github.com/safetylab/shadowsecurityscanner/sarif"
)

func main() {
	format := flag.String("format", "table", "output format: table | sarif")
	in := flag.String("in", "", "input JSON file (default: stdin)")
	tool := flag.String("tool", "", "tool name to record in SARIF output")
	timeout := flag.Duration("timeout", 60*time.Second, "overall timeout")
	flag.Parse()

	data, err := readInput(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading input:", err)
		os.Exit(1)
	}

	var fs []findings.Finding
	if err := json.Unmarshal(data, &fs); err != nil {
		fmt.Fprintln(os.Stderr, "error: input must be a JSON array of findings:", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	ranked, err := findings.Triage(ctx, epsskev.NewClient(), fs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	switch *format {
	case "sarif":
		out, err := sarif.Marshal(ranked, sarif.ToolInfo{Name: *tool})
		if err != nil {
			fmt.Fprintln(os.Stderr, "error marshalling SARIF:", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
	case "table":
		printTable(ranked)
	default:
		fmt.Fprintf(os.Stderr, "unknown -format %q (use table or sarif)\n", *format)
		os.Exit(2)
	}
}

func printTable(ranked []sarif.Finding) {
	fmt.Printf("%-4s  %-18s  %-9s  %-6s  %-6s  %s\n", "RANK", "CVE", "SEVERITY", "CVSS", "KEV", "EPSS")
	for i, f := range ranked {
		kev := "-"
		if f.InKEV {
			kev = "KEV"
		}
		fmt.Printf("%-4d  %-18s  %-9s  %-6.1f  %-6s  %.2f\n",
			i+1, strings.ToUpper(f.CVE), f.Severity, f.CVSS, kev, f.EPSS)
	}
}

func readInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}
