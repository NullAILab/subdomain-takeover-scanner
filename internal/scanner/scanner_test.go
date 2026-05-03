package scanner_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nullailab/subdomain-takeover-scanner/internal/fingerprint"
	"github.com/nullailab/subdomain-takeover-scanner/internal/scanner"
)

func TestDefaultConfig(t *testing.T) {
	cfg := scanner.DefaultConfig()
	if cfg.Concurrency <= 0 {
		t.Error("concurrency should be positive")
	}
	if cfg.DNSTimeout <= 0 {
		t.Error("DNSTimeout should be positive")
	}
	if cfg.HTTPTimeout <= 0 {
		t.Error("HTTPTimeout should be positive")
	}
}

func TestSortResults(t *testing.T) {
	results := []scanner.Result{
		{Subdomain: "b.example.com", Vulnerable: true, Risk: fingerprint.RiskLow},
		{Subdomain: "a.example.com", Vulnerable: true, Risk: fingerprint.RiskHigh},
		{Subdomain: "c.example.com", Vulnerable: true, Risk: fingerprint.RiskCritical},
		{Subdomain: "d.example.com", Vulnerable: true, Risk: fingerprint.RiskMedium},
	}

	scanner.SortResults(results)

	if results[0].Risk != fingerprint.RiskCritical {
		t.Errorf("first result should be CRITICAL, got %s", results[0].Risk)
	}
	if results[1].Risk != fingerprint.RiskHigh {
		t.Errorf("second result should be HIGH, got %s", results[1].Risk)
	}
	if results[2].Risk != fingerprint.RiskMedium {
		t.Errorf("third result should be MEDIUM, got %s", results[2].Risk)
	}
	if results[3].Risk != fingerprint.RiskLow {
		t.Errorf("fourth result should be LOW, got %s", results[3].Risk)
	}
}

func TestSortResultsSameRiskAlphabetical(t *testing.T) {
	results := []scanner.Result{
		{Subdomain: "z.example.com", Vulnerable: true, Risk: fingerprint.RiskHigh},
		{Subdomain: "a.example.com", Vulnerable: true, Risk: fingerprint.RiskHigh},
		{Subdomain: "m.example.com", Vulnerable: true, Risk: fingerprint.RiskHigh},
	}
	scanner.SortResults(results)

	names := []string{results[0].Subdomain, results[1].Subdomain, results[2].Subdomain}
	if !sort.StringsAreSorted(names) {
		t.Errorf("expected alphabetical order within same risk, got %v", names)
	}
}

func TestLoadWordlist(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "words.txt")
	content := "www\nmail\n# comment\nblog\n\napi\n"
	if err := os.WriteFile(wl, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	hosts, err := scanner.LoadWordlist(wl, "example.com")
	if err != nil {
		t.Fatalf("LoadWordlist error: %v", err)
	}

	if len(hosts) != 4 {
		t.Errorf("expected 4 hosts, got %d: %v", len(hosts), hosts)
	}

	for _, h := range hosts {
		if !strings.HasSuffix(h, ".example.com") {
			t.Errorf("host %q should end with .example.com", h)
		}
		if strings.HasPrefix(h, "#") {
			t.Errorf("comment line included: %q", h)
		}
	}
}

func TestLoadWordlistDeduplicates(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "words.txt")
	content := "www\nwww\nwww\nmail\n"
	if err := os.WriteFile(wl, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	hosts, err := scanner.LoadWordlist(wl, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Errorf("expected 2 unique hosts, got %d", len(hosts))
	}
}

func TestLoadWordlistMissingFile(t *testing.T) {
	_, err := scanner.LoadWordlist("/nonexistent/path/file.txt", "example.com")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestScannerCheckNoCNAME(t *testing.T) {
	// localhost resolves but has no CNAME — should return no findings
	cfg := scanner.DefaultConfig()
	s := scanner.New(cfg)
	res := s.Check(context.Background(), "localhost")
	if res.Vulnerable {
		t.Error("localhost should not be marked vulnerable")
	}
}

func TestScannerHTTPBodyMatching(t *testing.T) {
	// Serve a fake "GitHub Pages not found" response
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, "There isn't a GitHub Pages site here.")
	}))
	defer srv.Close()

	// We can't easily inject a CNAME in tests, so test the body matching logic
	// directly through the fingerprint package which the scanner uses.
	fps := fingerprint.ForCNAME("myorg.github.io")
	if len(fps) == 0 {
		t.Fatal("no fingerprint for github.io")
	}
	matched := fingerprint.MatchBody("There isn't a GitHub Pages site here.", fps)
	if matched == nil {
		t.Fatal("expected body to match GitHub Pages fingerprint")
	}
	if matched.Service != "GitHub Pages" {
		t.Errorf("expected GitHub Pages, got %s", matched.Service)
	}
}

func TestScanListContextCancellation(t *testing.T) {
	cfg := scanner.DefaultConfig()
	s := scanner.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	hosts := []string{"a.example.com", "b.example.com", "c.example.com"}
	ch := s.ScanList(ctx, hosts)

	var count int
	for range ch {
		count++
	}
	// With cancelled context, 0 or few results expected
	_ = count // just ensure channel is properly closed
}

func TestScanListEmpty(t *testing.T) {
	cfg := scanner.DefaultConfig()
	s := scanner.New(cfg)

	ch := s.ScanList(context.Background(), []string{})
	var results []scanner.Result
	for r := range ch {
		results = append(results, r)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty input, got %d", len(results))
	}
}

