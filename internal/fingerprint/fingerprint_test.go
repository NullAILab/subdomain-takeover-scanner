package fingerprint_test

import (
	"testing"

	"github.com/nullailab/subdomain-takeover-scanner/internal/fingerprint"
)

func TestFingerprintMatches(t *testing.T) {
	tests := []struct {
		fp      fingerprint.Fingerprint
		cname   string
		want    bool
	}{
		{
			fp:    fingerprint.Fingerprint{CNAMEPatterns: []string{"github.io"}},
			cname: "myorg.github.io",
			want:  true,
		},
		{
			fp:    fingerprint.Fingerprint{CNAMEPatterns: []string{"github.io"}},
			cname: "MYORG.GitHub.IO",
			want:  true,
		},
		{
			fp:    fingerprint.Fingerprint{CNAMEPatterns: []string{"github.io"}},
			cname: "example.com",
			want:  false,
		},
		{
			fp:    fingerprint.Fingerprint{CNAMEPatterns: []string{".s3.amazonaws.com", ".s3-website"}},
			cname: "mybucket.s3.amazonaws.com",
			want:  true,
		},
		{
			fp:    fingerprint.Fingerprint{CNAMEPatterns: []string{".s3.amazonaws.com", ".s3-website"}},
			cname: "mybucket.s3-website.us-east-1.amazonaws.com",
			want:  true,
		},
	}

	for _, tt := range tests {
		got := tt.fp.Matches(tt.cname)
		if got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.cname, got, tt.want)
		}
	}
}

func TestFingerprintBodyVulnerable(t *testing.T) {
	fp := fingerprint.Fingerprint{
		BodyPatterns: []string{"There isn't a GitHub Pages site here", "For root URLs"},
	}

	if !fp.BodyVulnerable("There isn't a GitHub Pages site here.") {
		t.Error("expected body to match GitHub Pages pattern")
	}
	if fp.BodyVulnerable("Welcome to my site!") {
		t.Error("expected no match for normal body")
	}
}

func TestForCNAME(t *testing.T) {
	fps := fingerprint.ForCNAME("myapp.herokuapp.com")
	if len(fps) == 0 {
		t.Fatal("expected at least one fingerprint for herokuapp.com")
	}
	found := false
	for _, fp := range fps {
		if fp.Service == "Heroku" {
			found = true
		}
	}
	if !found {
		t.Error("expected Heroku fingerprint for herokuapp.com CNAME")
	}
}

func TestForCNAMENoMatch(t *testing.T) {
	fps := fingerprint.ForCNAME("something.internal.corp")
	if len(fps) != 0 {
		t.Errorf("expected no fingerprints for internal domain, got %d", len(fps))
	}
}

func TestMatchBody(t *testing.T) {
	fps := []fingerprint.Fingerprint{
		{Service: "GitHub Pages", BodyPatterns: []string{"There isn't a GitHub Pages site here"}},
		{Service: "Heroku", BodyPatterns: []string{"No such app"}},
	}

	matched := fingerprint.MatchBody("No such app found on Heroku", fps)
	if matched == nil {
		t.Fatal("expected Heroku to match")
	}
	if matched.Service != "Heroku" {
		t.Errorf("expected Heroku, got %s", matched.Service)
	}
}

func TestMatchBodyNoMatch(t *testing.T) {
	fps := []fingerprint.Fingerprint{
		{Service: "GitHub Pages", BodyPatterns: []string{"There isn't a GitHub Pages site here"}},
	}
	if fingerprint.MatchBody("Hello world", fps) != nil {
		t.Error("expected no match for normal body")
	}
}

func TestRiskOrder(t *testing.T) {
	if fingerprint.RiskOrder(fingerprint.RiskCritical) >= fingerprint.RiskOrder(fingerprint.RiskHigh) {
		t.Error("CRITICAL should sort before HIGH")
	}
	if fingerprint.RiskOrder(fingerprint.RiskHigh) >= fingerprint.RiskOrder(fingerprint.RiskMedium) {
		t.Error("HIGH should sort before MEDIUM")
	}
	if fingerprint.RiskOrder(fingerprint.RiskMedium) >= fingerprint.RiskOrder(fingerprint.RiskLow) {
		t.Error("MEDIUM should sort before LOW")
	}
}

func TestAllFingerprintsHaveRequiredFields(t *testing.T) {
	for _, fp := range fingerprint.All {
		if fp.Service == "" {
			t.Errorf("fingerprint missing Service: %+v", fp)
		}
		if len(fp.CNAMEPatterns) == 0 {
			t.Errorf("fingerprint %q has no CNAMEPatterns", fp.Service)
		}
		if len(fp.BodyPatterns) == 0 {
			t.Errorf("fingerprint %q has no BodyPatterns", fp.Service)
		}
		if fp.Risk == "" {
			t.Errorf("fingerprint %q has no Risk", fp.Service)
		}
	}
}

func TestAllFingerprintCount(t *testing.T) {
	if len(fingerprint.All) < 20 {
		t.Errorf("expected at least 20 fingerprints, got %d", len(fingerprint.All))
	}
}

func TestKnownServicesPresent(t *testing.T) {
	services := make(map[string]bool)
	for _, fp := range fingerprint.All {
		services[fp.Service] = true
	}
	required := []string{
		"GitHub Pages", "AWS S3", "Heroku", "Netlify",
		"Shopify", "Fastly", "Azure", "Vercel",
	}
	for _, svc := range required {
		if !services[svc] {
			t.Errorf("missing required fingerprint: %s", svc)
		}
	}
}
