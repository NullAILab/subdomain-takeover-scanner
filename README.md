# Subdomain Takeover Scanner

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)
![Fingerprints](https://img.shields.io/badge/Fingerprints-25%20services-blue)

Detect dangling DNS CNAME records pointing to unclaimed cloud resources before attackers do. Enumerates subdomains via wordlists and certificate transparency logs, follows full CNAME chains, and matches responses against 25 cloud service fingerprints.

---

## How Subdomain Takeover Works

```
DNS record:  blog.company.com  ──CNAME──▶  company.github.io
                                               │
                                               ▼
                                      GitHub Pages site deleted
                                      but DNS record never removed

Attacker registers company.github.io → controls blog.company.com
```

---

## Example Output

```
═══════════════════════════════════════════════════════
  Subdomain Takeover Scanner — Results
═══════════════════════════════════════════════════════
  Domain    : example.com
  Scanned   : 2025-05-03 14:22:01 UTC
  Checked   : 847 subdomains
  Vulnerable: 3

  CRITICAL: 0  HIGH: 2  MEDIUM: 1  LOW: 0

[HIGH] blog.example.com
  Service    : GitHub Pages
  CNAME      : [example.github.io]
  HTTP Status: 404
  Takeable   : Yes
  How to fix : remove the dangling CNAME record from your DNS.
  Attacker   : Create a GitHub Pages repo matching the username/org + repo name in the CNAME.

[HIGH] cdn.example.com
  Service    : Fastly
  CNAME      : [example.global.ssl.fastly.net]
  Takeable   : Yes
  How to fix : remove the dangling CNAME record from your DNS.
```

---

## Service Fingerprints

| Service | CNAME Pattern | Takeover Signal |
|---------|---------------|-----------------|
| GitHub Pages | `github.io` | "There isn't a GitHub Pages site here" |
| AWS S3 | `.s3.amazonaws.com` | "NoSuchBucket" |
| Heroku | `.herokudns.com` | "No such app" |
| Netlify | `.netlify.app` | "Not Found - Request ID" |
| Shopify | `.myshopify.com` | "Sorry, this shop is currently unavailable" |
| Fastly | `.fastly.net` | "Fastly error: unknown domain" |
| Azure | `.azurewebsites.net` | "404 Web Site not found" |
| Vercel | `.vercel.app` | "The deployment could not be found" |
| Surge.sh | `.surge.sh` | "project not found" |
| Bitbucket | `.bitbucket.io` | "Repository not found" |
| + 15 more | Zendesk, WordPress, Ghost, HubSpot, Render, Fly.io, Pantheon… | |

---

## Usage

```bash
go build -trimpath -o scanner ./cmd/scanner

# Discover subdomains via certificate transparency logs
./scanner --domain example.com --crtsh

# Scan using a wordlist
./scanner --domain example.com --wordlist wordlists/subdomains.txt

# Combine both sources
./scanner --domain example.com --wordlist subdomains.txt --crtsh

# Check a specific list of subdomains
./scanner --domain example.com --subdomains "blog,mail,api,staging,dev"

# JSON output (for pipeline integration)
./scanner --domain example.com --crtsh --output json

# Custom DNS resolver and concurrency
./scanner --domain example.com --crtsh --dns 8.8.8.8:53 --concurrency 50

# No ANSI colors
./scanner --domain example.com --crtsh --no-color
```

Exit code `1` if vulnerable subdomains are found — integrates directly into CI/CD pipelines.

---

## Project Structure

```
cmd/scanner/          ← CLI entry point (flags, orchestration)
internal/
├── dns/              ← CNAME chain resolution (up to 10 hops)
├── crtsh/            ← crt.sh certificate transparency API client
├── fingerprint/      ← 25 service fingerprints (CNAME + body patterns)
├── scanner/          ← Concurrent scan engine (configurable workers)
└── report/           ← Console (ANSI) + JSON output
```

---

## Tests

```bash
go test ./...
```

---

## References

- [Can I Take Over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)
- [crt.sh — Certificate Transparency Logs](https://crt.sh/)
- [0xpatrik — Subdomain Takeover Basics](https://0xpatrik.com/subdomain-takeover-basics/)
- [HackTricks — Subdomain Takeover](https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover)

---

## License

MIT
