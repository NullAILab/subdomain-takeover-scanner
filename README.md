# 44 — Subdomain Takeover Scanner

> **Difficulty:** Intermediate | **Time:** 2–4 days | **Language:** Go

A scanner that discovers dangling DNS records pointing to unclaimed cloud resources, enabling subdomain takeover vulnerabilities — and helps you fix them before attackers find them.

---

## What You'll Build

A Go tool that:
- Discovers all subdomains via DNS enumeration (wordlist + certificate transparency)
- Checks each subdomain's CNAME chain for unclaimed endpoints
- Tests 50+ cloud services for takeover signatures (GitHub Pages, S3, Heroku, Netlify, etc.)
- Verifies potential takeovers by checking if the resource can be claimed
- Generates a risk-prioritized report
- Monitors continuously for new vulnerable records

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.21+ |
| DNS | `miekg/dns` |
| HTTP | `net/http` |
| Fingerprints | YAML config (50+ services) |
| CT logs | `crtsh` API |

---

## How Subdomain Takeover Works

```
company.com has DNS:
  blog.company.com CNAME → company.github.io

Problem: company.github.io Pages site was deleted.
Attack:  Create GitHub Pages at company.github.io
Result:  Attacker controls blog.company.com!
```

The DNS still points there, but the resource was never reclaimed. Attackers can register the same username/bucket/hostname and serve malicious content under your domain.

---

## Service Fingerprints

| Service | Takeover Indicator | Risk |
|---------|--------------------|------|
| GitHub Pages | "There isn't a GitHub Pages site here" | HIGH |
| Heroku | "No such app" | HIGH |
| AWS S3 | "NoSuchBucket" | HIGH |
| Netlify | "Not Found — Request ID" | MEDIUM |
| Shopify | "Sorry, this shop is currently unavailable" | HIGH |
| Fastly | "Fastly error: unknown domain" | HIGH |

---

## Usage

```bash
# Enumerate subdomains + check for takeover
./takeover-scanner scan --domain company.com \
  --wordlist subdomains-10k.txt

# Check specific subdomain
./takeover-scanner check blog.company.com

# Use certificate transparency logs
./takeover-scanner scan --domain company.com --crt-sh

# Continuous monitoring
./takeover-scanner monitor --domain company.com \
  --interval 6h --webhook https://hooks.slack.com/...

# Generate report
./takeover-scanner scan --domain company.com --output report.html
```

---

## Learning Objectives

- [ ] How CNAME chains work in DNS
- [ ] Why unclaimed cloud resources create security vulnerabilities
- [ ] Certificate Transparency logs for subdomain discovery
- [ ] Bug bounty methodology for subdomain takeover
- [ ] How to remediate dangling DNS records
- [ ] Continuous monitoring for DNS changes

---

## References

- [Can I take over XYZ? — Takeover fingerprints](https://github.com/EdOverflow/can-i-take-over-xyz)
- [Subdomain Takeover Guide](https://0xpatrik.com/subdomain-takeover-basics/)
- [crt.sh — Certificate Transparency](https://crt.sh/)

---

*NullAI Lab — Project 44 | Subdomain Takeover Scanner*
