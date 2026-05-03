// Package dns provides DNS resolution helpers for subdomain scanning.
package dns

import (
	"context"
	"net"
	"strings"
	"time"
)

// Resolver wraps the standard net.Resolver with a configurable timeout.
type Resolver struct {
	r       *net.Resolver
	timeout time.Duration
}

// New returns a Resolver using the system DNS with the given timeout.
func New(timeout time.Duration) *Resolver {
	return &Resolver{
		r:       net.DefaultResolver,
		timeout: timeout,
	}
}

// NewWithServer returns a Resolver that queries a specific DNS server (e.g. "8.8.8.8:53").
func NewWithServer(addr string, timeout time.Duration) *Resolver {
	return &Resolver{
		r: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", addr)
			},
		},
		timeout: timeout,
	}
}

// LookupCNAME returns the canonical CNAME target for a hostname.
// Returns ("", nil) if no CNAME exists.
func (r *Resolver) LookupCNAME(host string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	cname, err := r.r.LookupCNAME(ctx, host)
	if err != nil {
		return "", err
	}
	// net.LookupCNAME always returns the original name if no CNAME chain exists.
	// A real CNAME exists only when the result differs from the input.
	normalized := strings.TrimSuffix(cname, ".")
	input := strings.TrimSuffix(host, ".")
	if strings.EqualFold(normalized, input) {
		return "", nil
	}
	return normalized, nil
}

// LookupA returns all A (IPv4) records for a hostname.
func (r *Resolver) LookupA(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	addrs, err := r.r.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// Exists returns true if the hostname resolves to at least one address.
func (r *Resolver) Exists(host string) bool {
	addrs, err := r.LookupA(host)
	return err == nil && len(addrs) > 0
}

// CNAMEChain follows the full CNAME chain and returns each hop.
// Stops after maxHops to prevent infinite loops.
func (r *Resolver) CNAMEChain(host string, maxHops int) []string {
	var chain []string
	current := host
	for i := 0; i < maxHops; i++ {
		next, err := r.LookupCNAME(current)
		if err != nil || next == "" {
			break
		}
		chain = append(chain, next)
		current = next
	}
	return chain
}
