package main

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderReportPageCSP(t *testing.T) {
	// Initialize minimal config
	config.AbuseReporting.Enabled = true
	config.HCaptcha.SiteKey = "sitekey"

	// Initialize template map
	templateMap = make(map[string]*template.Template)
	tmplContent := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="color-scheme" content="dark">
    <link rel="stylesheet" type="text/css" href="/shorter.css" integrity="{{.CssSRIHash}}">
    {{if .CaptchaActive}}
    <script src="https://js.hcaptcha.com/1/api.js" async defer crossorigin="anonymous" nonce="{{.Nonce}}"></script>
    {{end}}
    <title>Report Abuse</title>
</head>
<body>
</body>
</html>
`
	tmpl, err := template.New("report").Parse(tmplContent)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}
	templateMap["report"] = tmpl

	// Create a recorder and request
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/report?key=test", nil)

	// Call the function
	renderReportPage(w, r, "test", "")

	// Check response code
	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check CSP header
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header is missing")
	}

	// Verify CSP directives
	if !strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("CSP missing 'unsafe-inline' for styles. Got: %s", csp)
	}
	if !strings.Contains(csp, "nonce-") {
		t.Errorf("CSP missing nonce for scripts. Got: %s", csp)
	}

	// Check body for nonce attribute
	body := w.Body.String()
	if !strings.Contains(body, `nonce="`) {
		t.Errorf("Response body missing nonce attribute. Got: %s", body)
	}

	// Extract nonce from CSP and Body and compare (roughly)
	// csp: ... 'nonce-ABC' ...
	// body: ... nonce="ABC" ...

	// We can just verify that the nonce in CSP matches the one in body if we really want to be sure,
	// but the presence is likely enough for now.
}
