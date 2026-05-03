# Subdomain Takeover Scanner

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Fingerprints](https://img.shields.io/badge/Fingerprints-25%20services-blue)

Detect dangling DNS CNAME records pointing to unclaimed cloud resources. Supports wordlist enumeration, certificate transparency log discovery, and concurrent scanning against 25 known service fingerprints.

---

## How Subdomain Takeover Works

```
blog.company.com  CNAME →  company.github.io
```

The GitHub Pages site was deleted but the DNS record remains. An attacker creates a GitHub Pages repo at `company.github.io` and now controls `blog.company.com`.

---

## Service Fingerprints

| Service | Detection |
|---------|-----------|
| GitHub Pages | "There isn't a GitHub Pages site here" |
| AWS S3 | "NoSuchBucket" |
| Heroku | "No such app" |
| Netlify | "Not Found - Request ID" |
| Shopify | "Sorry, this shop is currently unavailable" |
| Fastly | "Fastly error: unknown domain" |
| Azure | "404 Web Site not found" |
| Vercel | "The deployment could not be found" |
| Surge.sh | "project not found" |
| Bitbucket | "Repository not found" |
| + 15 more | Zendesk, WordPress, Ghost, Render, Fly.io… |

---

## Usage

```bash
go build -trimpath -o scanner ./cmd/scanner

# Scan via wordlist
./scanner --domain example.com --wordlist wordlists/subdomains.txt

# Discover via certificate transparency logs
./scanner --domain example.com --crtsh

# Both sources combined
./scanner --domain example.com --wordlist subdomains.txt --crtsh

# Check specific subdomains
./scanner --domain example.com --subdomains "blog,mail,api,staging"

# JSON output
./scanner --domain example.com --crtsh --output json

# Custom DNS server + concurrency
./scanner --domain example.com --crtsh --dns 8.8.8.8:53 --concurrency 50
```

---

## Project Structure

```
cmd/scanner/         ← CLI entry point
internal/
├── dns/             ← CNAME chain resolution
├── crtsh/           ← Certificate transparency log client
├── fingerprint/     ← 25 service fingerprints
├── scanner/         ← Concurrent scan orchestrator
└── report/          ← Console + JSON output
```

---

## Tests

```bash
go test ./...
```

---

## References

- [Can I Take Over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)
- [crt.sh — Certificate Transparency](https://crt.sh/)
- [0xpatrik — Subdomain Takeover Basics](https://0xpatrik.com/subdomain-takeover-basics/)

---

## License

MIT
