// Package report formats scan results for terminal and JSON output.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/nullailab/subdomain-takeover-scanner/internal/fingerprint"
	"github.com/nullailab/subdomain-takeover-scanner/internal/scanner"
)

// Summary holds aggregated scan statistics.
type Summary struct {
	Domain      string           `json:"domain"`
	ScannedAt   time.Time        `json:"scanned_at"`
	Total       int              `json:"total"`
	Vulnerable  int              `json:"vulnerable"`
	ByRisk      map[string]int   `json:"by_risk"`
	Results     []scanner.Result `json:"results"`
}

// Build creates a Summary from a slice of results.
func Build(domain string, results []scanner.Result) Summary {
	s := Summary{
		Domain:    domain,
		ScannedAt: time.Now().UTC(),
		Total:     len(results),
		ByRisk:    map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
		Results:   results,
	}
	for _, r := range results {
		if r.Vulnerable {
			s.Vulnerable++
			s.ByRisk[string(r.Risk)]++
		}
	}
	return s
}

// WriteJSON writes the summary as indented JSON.
func WriteJSON(out io.Writer, s Summary) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// WriteConsole writes a human-readable report to out.
func WriteConsole(out io.Writer, s Summary, color bool) {
	reset := "\033[0m"
	bold := "\033[1m"
	red := "\033[91m"
	yellow := "\033[93m"
	cyan := "\033[96m"
	green := "\033[92m"
	dim := "\033[2m"
	if !color {
		reset, bold, red, yellow, cyan, green, dim = "", "", "", "", "", "", ""
	}

	fmt.Fprintf(out, "%s%s%s\n", bold, "═══════════════════════════════════════════════════════", reset)
	fmt.Fprintf(out, "%s  Subdomain Takeover Scanner — Results%s\n", bold, reset)
	fmt.Fprintf(out, "%s%s%s\n", bold, "═══════════════════════════════════════════════════════", reset)
	fmt.Fprintf(out, "  Domain    : %s\n", s.Domain)
	fmt.Fprintf(out, "  Scanned   : %s\n", s.ScannedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(out, "  Checked   : %d subdomains\n", s.Total)
	fmt.Fprintf(out, "  Vulnerable: %s%d%s\n\n", bold, s.Vulnerable, reset)

	if s.Vulnerable == 0 {
		fmt.Fprintf(out, "%s  No takeover vulnerabilities found.%s\n\n", green, reset)
	} else {
		fmt.Fprintf(out, "  %sCRITICAL%s: %d  %sHIGH%s: %d  %sMEDIUM%s: %d  %sLOW%s: %d\n\n",
			red, reset, s.ByRisk["CRITICAL"],
			yellow, reset, s.ByRisk["HIGH"],
			cyan, reset, s.ByRisk["MEDIUM"],
			green, reset, s.ByRisk["LOW"],
		)
	}

	riskColor := map[fingerprint.Risk]string{
		fingerprint.RiskCritical: red,
		fingerprint.RiskHigh:     yellow,
		fingerprint.RiskMedium:   cyan,
		fingerprint.RiskLow:      green,
	}

	for _, r := range s.Results {
		if !r.Vulnerable {
			continue
		}
		rc := riskColor[r.Risk]
		fmt.Fprintf(out, "%s[%s%s%s] %s%s%s\n", bold, rc, r.Risk, reset+bold, bold, r.Subdomain, reset)
		fmt.Fprintf(out, "  Service    : %s\n", r.Service)
		if len(r.CNAMEChain) > 0 {
			fmt.Fprintf(out, "  CNAME      : %v\n", r.CNAMEChain)
		}
		if r.HTTPStatus > 0 {
			fmt.Fprintf(out, "  HTTP Status: %d\n", r.HTTPStatus)
		}
		takeable := "No"
		if r.Takeable {
			takeable = "Yes"
		}
		fmt.Fprintf(out, "  Takeable   : %s\n", takeable)
		fmt.Fprintf(out, "  %sHow to fix : remove the dangling CNAME record from your DNS.%s\n", green, reset)
		if r.Notes != "" {
			fmt.Fprintf(out, "  %sAttacker   : %s%s\n", dim, r.Notes, reset)
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "%s%s%s\n", bold, "═══════════════════════════════════════════════════════", reset)
}
