// Package scanner orchestrates subdomain enumeration and takeover checking.
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nullailab/subdomain-takeover-scanner/internal/dns"
	"github.com/nullailab/subdomain-takeover-scanner/internal/fingerprint"
)

// Result holds the outcome of scanning a single subdomain.
type Result struct {
	Subdomain   string
	CNAMEChain  []string
	Vulnerable  bool
	Service     string
	Risk        fingerprint.Risk
	Takeable    bool
	Notes       string
	HTTPStatus  int
	BodySnippet string
	Error       string
}

// Config controls scanner behaviour.
type Config struct {
	Concurrency int
	DNSTimeout  time.Duration
	HTTPTimeout time.Duration
	DNSServer   string // optional, e.g. "8.8.8.8:53"
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Concurrency: 20,
		DNSTimeout:  5 * time.Second,
		HTTPTimeout: 8 * time.Second,
	}
}

// Scanner checks subdomains for takeover vulnerabilities.
type Scanner struct {
	cfg      Config
	resolver *dns.Resolver
	http     *http.Client
}

// New creates a Scanner with the given config.
func New(cfg Config) *Scanner {
	var resolver *dns.Resolver
	if cfg.DNSServer != "" {
		resolver = dns.NewWithServer(cfg.DNSServer, cfg.DNSTimeout)
	} else {
		resolver = dns.New(cfg.DNSTimeout)
	}

	return &Scanner{
		cfg:      cfg,
		resolver: resolver,
		http: &http.Client{
			Timeout: cfg.HTTPTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				return nil
			},
		},
	}
}

// ScanList checks each subdomain in the slice concurrently and streams
// results to the returned channel.  The channel is closed when done.
func (s *Scanner) ScanList(ctx context.Context, subdomains []string) <-chan Result {
	out := make(chan Result, len(subdomains))

	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup

	for _, sub := range subdomains {
		sub := sub
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			select {
			case <-ctx.Done():
			case out <- s.check(ctx, sub):
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// Check scans a single subdomain and returns its result.
func (s *Scanner) Check(ctx context.Context, subdomain string) Result {
	return s.check(ctx, subdomain)
}

func (s *Scanner) check(ctx context.Context, subdomain string) Result {
	res := Result{Subdomain: subdomain}

	// Follow CNAME chain
	chain := s.resolver.CNAMEChain(subdomain, 10)
	res.CNAMEChain = chain

	if len(chain) == 0 {
		// No CNAME — check if it resolves at all; if not, dangling A record
		if !s.resolver.Exists(subdomain) {
			res.Error = "NXDOMAIN — dangling record (no CNAME, no A)"
		}
		return res
	}

	// Find matching fingerprints against the last hop in the chain
	finalTarget := chain[len(chain)-1]
	fps := fingerprint.ForCNAME(finalTarget)
	if len(fps) == 0 {
		// CNAME exists but no known service fingerprint
		return res
	}

	// Fetch HTTP response to check body patterns
	body, status, err := s.fetchBody(ctx, "http://"+subdomain)
	if err != nil {
		// Try HTTPS
		body, status, err = s.fetchBody(ctx, "https://"+subdomain)
	}
	res.HTTPStatus = status
	if len(body) > 500 {
		res.BodySnippet = body[:500]
	} else {
		res.BodySnippet = body
	}

	// Match body against fingerprints
	matched := fingerprint.MatchBody(body, fps)
	if matched != nil {
		res.Vulnerable = true
		res.Service = matched.Service
		res.Risk = matched.Risk
		res.Takeable = matched.Takeable
		res.Notes = matched.Notes
	}

	return res
}

func (s *Scanner) fetchBody(ctx context.Context, url string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; subdomain-takeover-scanner/1.0)")

	resp, err := s.http.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return string(body), resp.StatusCode, err
}

// LoadWordlist reads a newline-separated subdomain wordlist file and returns
// full hostnames by prepending domain to each stem.
func LoadWordlist(path, domain string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var hosts []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host := line + "." + domain
		if _, exists := seen[host]; !exists {
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}
	return hosts, sc.Err()
}

// SortResults sorts by risk (critical first) then by subdomain name.
func SortResults(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		ri := fingerprint.RiskOrder(results[i].Risk)
		rj := fingerprint.RiskOrder(results[j].Risk)
		if ri != rj {
			return ri < rj
		}
		return results[i].Subdomain < results[j].Subdomain
	})
}
