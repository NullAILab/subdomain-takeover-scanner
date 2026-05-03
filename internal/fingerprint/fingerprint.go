// Package fingerprint defines service fingerprints for subdomain takeover detection.
// Each fingerprint describes a cloud service, the CNAME pattern that indicates
// use of that service, and the HTTP response body pattern that signals the
// resource is unclaimed and potentially takeable.
package fingerprint

import (
	"regexp"
	"strings"
)

// Risk indicates the severity of a potential takeover.
type Risk string

const (
	RiskCritical Risk = "CRITICAL"
	RiskHigh     Risk = "HIGH"
	RiskMedium   Risk = "MEDIUM"
	RiskLow      Risk = "LOW"
)

// Fingerprint describes how to detect a vulnerable/unclaimed resource.
type Fingerprint struct {
	// Service is the human-readable cloud service name.
	Service string

	// CNAMEPatterns are substrings that the CNAME target must contain
	// for this fingerprint to apply.
	CNAMEPatterns []string

	// BodyPatterns are substrings that must appear in the HTTP response
	// body to confirm the resource is unclaimed.
	BodyPatterns []string

	// Risk is the exploitability/impact rating.
	Risk Risk

	// Takeable indicates whether the service allows self-registration
	// (i.e., the resource can actually be claimed by an attacker).
	Takeable bool

	// Notes is a human-readable description of the takeover method.
	Notes string
}

// Matches returns true if the given CNAME target matches any of the
// fingerprint's CNAME patterns (case-insensitive substring match).
func (f *Fingerprint) Matches(cnameTarget string) bool {
	lower := strings.ToLower(cnameTarget)
	for _, p := range f.CNAMEPatterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// BodyVulnerable returns true if the response body contains any of the
// expected "unclaimed resource" patterns.
func (f *Fingerprint) BodyVulnerable(body string) bool {
	for _, p := range f.BodyPatterns {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}

// All is the registry of all known service fingerprints.
var All = []Fingerprint{
	{
		Service:       "GitHub Pages",
		CNAMEPatterns: []string{"github.io"},
		BodyPatterns:  []string{"There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"},
		Risk:          RiskHigh,
		Takeable:      true,
		Notes:         "Create a GitHub Pages repo matching the username/org + repo name in the CNAME.",
	},
	{
		Service:       "AWS S3",
		CNAMEPatterns: []string{".s3.amazonaws.com", ".s3-website"},
		BodyPatterns:  []string{"NoSuchBucket", "The specified bucket does not exist"},
		Risk:          RiskHigh,
		Takeable:      true,
		Notes:         "Register the S3 bucket name in the same AWS region.",
	},
	{
		Service:       "Heroku",
		CNAMEPatterns: []string{".herokudns.com", ".herokuapp.com"},
		BodyPatterns:  []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"},
		Risk:          RiskHigh,
		Takeable:      true,
		Notes:         "Create a Heroku app with the matching app name.",
	},
	{
		Service:       "Netlify",
		CNAMEPatterns: []string{".netlify.app", ".netlify.com"},
		BodyPatterns:  []string{"Not Found - Request ID"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Register a Netlify site with the matching subdomain.",
	},
	{
		Service:       "Shopify",
		CNAMEPatterns: []string{".myshopify.com"},
		BodyPatterns:  []string{"Sorry, this shop is currently unavailable", "Only one step left!"},
		Risk:          RiskHigh,
		Takeable:      true,
		Notes:         "Create a Shopify store with the matching shop name.",
	},
	{
		Service:       "Fastly",
		CNAMEPatterns: []string{".fastly.net"},
		BodyPatterns:  []string{"Fastly error: unknown domain", "please check that this domain has been added to a service"},
		Risk:          RiskHigh,
		Takeable:      true,
		Notes:         "Add the domain to a new Fastly service.",
	},
	{
		Service:       "Azure",
		CNAMEPatterns: []string{".azurewebsites.net", ".cloudapp.net", ".azure.com", ".blob.core.windows.net", ".trafficmanager.net"},
		BodyPatterns:  []string{"404 Web Site not found", "The resource you are looking for has been removed"},
		Risk:          RiskHigh,
		Takeable:      true,
		Notes:         "Create an Azure app service / storage with the matching name.",
	},
	{
		Service:       "Zendesk",
		CNAMEPatterns: []string{".zendesk.com"},
		BodyPatterns:  []string{"Help Center Closed", "Oops, this help center no longer exists"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Register a Zendesk account with the matching subdomain.",
	},
	{
		Service:       "WordPress.com",
		CNAMEPatterns: []string{".wordpress.com"},
		BodyPatterns:  []string{"Do you want to register", "doesn't exist"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Create a WordPress.com blog matching the subdomain.",
	},
	{
		Service:       "Ghost",
		CNAMEPatterns: []string{".ghost.io"},
		BodyPatterns:  []string{"The thing you were looking for is no longer here"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Create a Ghost blog with the matching subdomain.",
	},
	{
		Service:       "Tumblr",
		CNAMEPatterns: []string{".tumblr.com"},
		BodyPatterns:  []string{"Whatever you were looking for doesn't currently exist at this address"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Create a Tumblr blog matching the subdomain.",
	},
	{
		Service:       "Cargo",
		CNAMEPatterns: []string{"cargocollective.com"},
		BodyPatterns:  []string{"404 Not Found"},
		Risk:          RiskMedium,
		Takeable:      false,
		Notes:         "Resource unclaimed but takeover process unclear.",
	},
	{
		Service:       "Campaign Monitor",
		CNAMEPatterns: []string{"createsend.com"},
		BodyPatterns:  []string{"Double check the URL"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Register a Campaign Monitor account with the matching subdomain.",
	},
	{
		Service:       "HubSpot",
		CNAMEPatterns: []string{"hubspot.net", ".hs-sites.com"},
		BodyPatterns:  []string{"This page isn't available", "Domain is not configured"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Create a HubSpot site with the matching domain.",
	},
	{
		Service:       "Squarespace",
		CNAMEPatterns: []string{"squarespace.com"},
		BodyPatterns:  []string{"No Such Account", "squarespace.com"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Create a Squarespace site with the matching template URL.",
	},
	{
		Service:       "Pantheon",
		CNAMEPatterns: []string{".pantheonsite.io", "pantheon.io"},
		BodyPatterns:  []string{"The gods are wise", "404 error unknown site"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Create a Pantheon site matching the subdomain.",
	},
	{
		Service:       "Strikingly",
		CNAMEPatterns: []string{".strikingly.com"},
		BodyPatterns:  []string{"page not found"},
		Risk:          RiskLow,
		Takeable:      true,
		Notes:         "Create a Strikingly page with the matching subdomain.",
	},
	{
		Service:       "Surge.sh",
		CNAMEPatterns: []string{".surge.sh"},
		BodyPatterns:  []string{"project not found"},
		Risk:          RiskHigh,
		Takeable:      true,
		Notes:         "Run: surge --domain <subdomain>",
	},
	{
		Service:       "UserVoice",
		CNAMEPatterns: []string{".uservoice.com"},
		BodyPatterns:  []string{"This UserVoice subdomain is currently available!"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Register a UserVoice account with the matching subdomain.",
	},
	{
		Service:       "Bitbucket",
		CNAMEPatterns: []string{".bitbucket.io"},
		BodyPatterns:  []string{"Repository not found"},
		Risk:          RiskHigh,
		Takeable:      true,
		Notes:         "Create a Bitbucket Pages repo matching the username + repo name.",
	},
	{
		Service:       "Intercom",
		CNAMEPatterns: []string{".custom.intercom.help"},
		BodyPatterns:  []string{"This page doesn't exist"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Create an Intercom help center with the matching subdomain.",
	},
	{
		Service:       "Readme.io",
		CNAMEPatterns: []string{".readme.io"},
		BodyPatterns:  []string{"Project doesnt exist... yet!"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Create a Readme.io project with the matching slug.",
	},
	{
		Service:       "Fly.io",
		CNAMEPatterns: []string{".fly.dev"},
		BodyPatterns:  []string{"404 Not Found", "unknown app"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Deploy a Fly.io app with the matching app name.",
	},
	{
		Service:       "Render",
		CNAMEPatterns: []string{".onrender.com"},
		BodyPatterns:  []string{"There's nothing here, yet"},
		Risk:          RiskMedium,
		Takeable:      true,
		Notes:         "Create a Render service with the matching name.",
	},
	{
		Service:       "Vercel",
		CNAMEPatterns: []string{".vercel.app", ".now.sh"},
		BodyPatterns:  []string{"The deployment could not be found", "404: NOT_FOUND"},
		Risk:          RiskHigh,
		Takeable:      true,
		Notes:         "Deploy a Vercel project and assign the matching domain.",
	},
}

// ForCNAME returns all fingerprints that match the given CNAME target.
func ForCNAME(cnameTarget string) []Fingerprint {
	var matches []Fingerprint
	for _, fp := range All {
		if fp.Matches(cnameTarget) {
			matches = append(matches, fp)
		}
	}
	return matches
}

// bodyPatternRe precompiles a case-sensitive contains check.
// (Used internally for fast body scanning across multiple fingerprints.)
func MatchBody(body string, fingerprints []Fingerprint) *Fingerprint {
	for i := range fingerprints {
		if fingerprints[i].BodyVulnerable(body) {
			return &fingerprints[i]
		}
	}
	return nil
}

// RiskOrder returns a numeric priority for sorting (lower = more severe).
func RiskOrder(r Risk) int {
	switch r {
	case RiskCritical:
		return 0
	case RiskHigh:
		return 1
	case RiskMedium:
		return 2
	case RiskLow:
		return 3
	default:
		return 4
	}
}

// compile-time check that regexp package imported
var _ = regexp.MustCompile
