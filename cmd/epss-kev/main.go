// Command epss-kev prioritises a list of CVEs by real-world exploitability using
// FIRST.org EPSS and the CISA KEV catalog.
//
// Usage:
//
//	epss-kev CVE-2021-44228 CVE-2017-0144 ...
//	echo "CVE-2021-44228\nCVE-2017-0144" | epss-kev
//	epss-kev -json CVE-2021-44228
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/safetylab/ShadowSecurityScanner/epsskev"
)

func main() {
	jsonOut := flag.Bool("json", false, "output JSON instead of a table")
	timeout := flag.Duration("timeout", 60*time.Second, "overall timeout")
	flag.Parse()

	cves := flag.Args()
	if len(cves) == 0 {
		cves = readStdin()
	}
	if len(cves) == 0 {
		fmt.Fprintln(os.Stderr, "usage: epss-kev [-json] CVE-XXXX-YYYY ...   (or pipe CVEs on stdin)")
		os.Exit(2)
	}

	findings := make([]epsskev.Finding, 0, len(cves))
	for _, c := range cves {
		findings = append(findings, epsskev.Finding{CVE: c})
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := epsskev.NewClient()
	ranked, err := epsskev.EnrichAndPrioritise(ctx, client, findings)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(ranked)
		return
	}
	printTable(ranked)
}

func readStdin() []string {
	info, err := os.Stdin.Stat()
	if err != nil || (info.Mode()&os.ModeCharDevice) != 0 {
		return nil // no pipe
	}
	var cves []string
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		for _, tok := range strings.FieldsFunc(sc.Text(), func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		}) {
			if tok != "" {
				cves = append(cves, tok)
			}
		}
	}
	return cves
}

func printTable(ranked []epsskev.EnrichedFinding) {
	fmt.Printf("%-4s  %-18s  %-6s  %-6s  %s\n", "RANK", "CVE", "EPSS", "KEV", "PERCENTILE")
	for i, f := range ranked {
		kev := "-"
		if f.InKEV {
			kev = "KEV"
		}
		epss := "n/a"
		pct := "n/a"
		if f.Known {
			epss = fmt.Sprintf("%.2f", f.EPSS)
			pct = fmt.Sprintf("%.0f%%", f.Percentile*100)
		}
		fmt.Printf("%-4d  %-18s  %-6s  %-6s  %s\n", i+1, strings.ToUpper(f.CVE), epss, kev, pct)
	}
}
