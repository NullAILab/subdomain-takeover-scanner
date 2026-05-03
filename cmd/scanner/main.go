package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nullailab/subdomain-takeover-scanner/internal/crtsh"
	"github.com/nullailab/subdomain-takeover-scanner/internal/report"
	"github.com/nullailab/subdomain-takeover-scanner/internal/scanner"
)

func main() {
	domain := flag.String("domain", "", "Target apex domain (e.g. example.com)")
	wordlist := flag.String("wordlist", "", "Path to subdomain wordlist file")
	useCrtsh := flag.Bool("crtsh", false, "Discover subdomains via certificate transparency logs")
	subdomains := flag.String("subdomains", "", "Comma-separated list of subdomains to check")
	output := flag.String("output", "console", "Output format: console | json")
	concurrency := flag.Int("concurrency", 20, "Number of concurrent checks")
	dnsServer := flag.String("dns", "", "Custom DNS server (e.g. 8.8.8.8:53)")
	noColor := flag.Bool("no-color", false, "Disable ANSI colors")
	flag.Parse()

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "error: --domain is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg := scanner.Config{
		Concurrency: *concurrency,
		DNSTimeout:  5 * time.Second,
		HTTPTimeout: 8 * time.Second,
		DNSServer:   *dnsServer,
	}

	s := scanner.New(cfg)
	ctx := context.Background()

	// Collect subdomains from all sources
	var hosts []string
	seen := make(map[string]struct{})

	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			if _, ok := seen[h]; !ok {
				seen[h] = struct{}{}
				hosts = append(hosts, h)
			}
		}
	}

	// From --subdomains flag
	if *subdomains != "" {
		for _, sub := range strings.Split(*subdomains, ",") {
			add(sub)
		}
	}

	// From wordlist
	if *wordlist != "" {
		wlHosts, err := scanner.LoadWordlist(*wordlist, *domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading wordlist: %v\n", err)
			os.Exit(1)
		}
		for _, h := range wlHosts {
			add(h)
		}
	}

	// From crt.sh
	if *useCrtsh {
		fmt.Fprintf(os.Stderr, "Fetching subdomains from crt.sh for %s...\n", *domain)
		client := crtsh.New(30 * time.Second)
		ctHosts, err := client.Subdomains(ctx, *domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: crt.sh error: %v\n", err)
		} else {
			for _, h := range ctHosts {
				add(h)
			}
			fmt.Fprintf(os.Stderr, "Found %d subdomains via crt.sh\n", len(ctHosts))
		}
	}

	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "error: no subdomains to scan — use --wordlist, --crtsh, or --subdomains")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Scanning %d subdomains with concurrency %d...\n", len(hosts), *concurrency)

	// Run scans
	var results []scanner.Result
	ch := s.ScanList(ctx, hosts)
	for r := range ch {
		results = append(results, r)
		if r.Vulnerable {
			fmt.Fprintf(os.Stderr, "  [VULN] %s → %s (%s)\n", r.Subdomain, r.Service, r.Risk)
		}
	}

	scanner.SortResults(results)
	summary := report.Build(*domain, results)

	switch *output {
	case "json":
		if err := report.WriteJSON(os.Stdout, summary); err != nil {
			fmt.Fprintf(os.Stderr, "error writing JSON: %v\n", err)
			os.Exit(1)
		}
	default:
		report.WriteConsole(os.Stdout, summary, !*noColor)
	}

	if summary.Vulnerable > 0 {
		os.Exit(1)
	}
}
