// Package crtsh queries the crt.sh certificate transparency log API
// to discover subdomains for a given domain.
package crtsh

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const apiURL = "https://crt.sh/?q=%%25.%s&output=json"

type certEntry struct {
	NameValue string `json:"name_value"`
}

// Client fetches subdomain data from crt.sh.
type Client struct {
	http    *http.Client
	timeout time.Duration
}

// New returns a crt.sh client with the given HTTP timeout.
func New(timeout time.Duration) *Client {
	return &Client{
		http:    &http.Client{Timeout: timeout},
		timeout: timeout,
	}
}

// Subdomains returns a deduplicated list of subdomains discovered via
// certificate transparency logs for the given apex domain.
func (c *Client) Subdomains(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf(apiURL, domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "subdomain-takeover-scanner/1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []certEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crt.sh decode error: %w", err)
	}

	seen := make(map[string]struct{})
	var subs []string

	for _, e := range entries {
		// name_value may contain newline-separated names
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			// Skip wildcards and the apex domain itself
			if name == "" || strings.HasPrefix(name, "*") || name == domain {
				continue
			}
			if !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if _, exists := seen[name]; !exists {
				seen[name] = struct{}{}
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}
