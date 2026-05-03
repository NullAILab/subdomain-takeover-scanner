package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nullailab/subdomain-takeover-scanner/internal/fingerprint"
	"github.com/nullailab/subdomain-takeover-scanner/internal/report"
	"github.com/nullailab/subdomain-takeover-scanner/internal/scanner"
)

func makeResults(n int, vuln bool) []scanner.Result {
	results := make([]scanner.Result, n)
	for i := range results {
		results[i] = scanner.Result{
			Subdomain:  "sub.example.com",
			Vulnerable: vuln,
		}
		if vuln {
			results[i].Service = "GitHub Pages"
			results[i].Risk = fingerprint.RiskHigh
			results[i].Takeable = true
			results[i].CNAMEChain = []string{"myorg.github.io"}
		}
	}
	return results
}

func TestBuildSummary(t *testing.T) {
	results := append(
		makeResults(2, true),
		makeResults(3, false)...,
	)
	s := report.Build("example.com", results)

	if s.Total != 5 {
		t.Errorf("Total = %d, want 5", s.Total)
	}
	if s.Vulnerable != 2 {
		t.Errorf("Vulnerable = %d, want 2", s.Vulnerable)
	}
	if s.ByRisk["HIGH"] != 2 {
		t.Errorf("ByRisk[HIGH] = %d, want 2", s.ByRisk["HIGH"])
	}
	if s.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", s.Domain)
	}
}

func TestBuildSummaryEmpty(t *testing.T) {
	s := report.Build("test.com", nil)
	if s.Total != 0 || s.Vulnerable != 0 {
		t.Errorf("expected zero counts, got total=%d vuln=%d", s.Total, s.Vulnerable)
	}
}

func TestWriteJSON(t *testing.T) {
	s := report.Build("example.com", makeResults(1, true))
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, s); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if decoded["domain"] != "example.com" {
		t.Errorf("domain = %v, want example.com", decoded["domain"])
	}
	if decoded["vulnerable"].(float64) != 1 {
		t.Errorf("vulnerable = %v, want 1", decoded["vulnerable"])
	}
}

func TestWriteConsoleNoColor(t *testing.T) {
	results := makeResults(1, true)
	s := report.Build("example.com", results)

	var buf bytes.Buffer
	report.WriteConsole(&buf, s, false)
	out := buf.String()

	// No ANSI codes
	if strings.Contains(out, "\033[") {
		t.Error("expected no ANSI codes when color=false")
	}
	if !strings.Contains(out, "example.com") {
		t.Error("expected domain in output")
	}
	if !strings.Contains(out, "GitHub Pages") {
		t.Error("expected service name in output")
	}
	if !strings.Contains(out, "CNAME") {
		t.Error("expected CNAME in output")
	}
}

func TestWriteConsoleNoVulnerabilities(t *testing.T) {
	s := report.Build("clean.com", makeResults(5, false))
	var buf bytes.Buffer
	report.WriteConsole(&buf, s, false)
	out := buf.String()

	if !strings.Contains(out, "No takeover vulnerabilities found") {
		t.Error("expected clean message when no vulnerabilities")
	}
}

func TestWriteConsoleWithColor(t *testing.T) {
	s := report.Build("example.com", makeResults(1, true))
	var buf bytes.Buffer
	report.WriteConsole(&buf, s, true)
	out := buf.String()

	if !strings.Contains(out, "\033[") {
		t.Error("expected ANSI codes when color=true")
	}
}

func TestSummaryRiskCounts(t *testing.T) {
	results := []scanner.Result{
		{Vulnerable: true, Risk: fingerprint.RiskCritical},
		{Vulnerable: true, Risk: fingerprint.RiskCritical},
		{Vulnerable: true, Risk: fingerprint.RiskHigh},
		{Vulnerable: true, Risk: fingerprint.RiskMedium},
		{Vulnerable: false},
	}
	s := report.Build("x.com", results)

	if s.ByRisk["CRITICAL"] != 2 {
		t.Errorf("CRITICAL count = %d, want 2", s.ByRisk["CRITICAL"])
	}
	if s.ByRisk["HIGH"] != 1 {
		t.Errorf("HIGH count = %d, want 1", s.ByRisk["HIGH"])
	}
	if s.ByRisk["MEDIUM"] != 1 {
		t.Errorf("MEDIUM count = %d, want 1", s.ByRisk["MEDIUM"])
	}
	if s.ByRisk["LOW"] != 0 {
		t.Errorf("LOW count = %d, want 0", s.ByRisk["LOW"])
	}
}
