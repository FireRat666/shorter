package main

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// validate validates if string s contains only characters in charset. validate is not a crypto related function so no need for constant time
func validate(s string) bool {
	if len(s) == 0 {
		return true
	}

	if s[len(s)-1] == '~' {
		s = s[:len(s)-1]
	}

	for _, char := range s {
		if !strings.Contains(customKeyCharset, string(char)) {
			return false
		}
	}
	return true
}

func addHeaders(w http.ResponseWriter, _ *http.Request) {
	// Set the Content-Security-Policy header if it's defined in the config.
	if config.CSP != "" {
		w.Header().Set("Content-Security-Policy", config.CSP)
	}

	// --- Additional Security Headers ---
	// Prevent the browser from interpreting files as a different MIME type.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Prevent the page from being displayed in a frame, iframe, or object.
	w.Header().Set("X-Frame-Options", "DENY")
	// Control what information is sent with the Referer header.
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	// Enable the XSS filter in older browsers.
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	// Note: HSTS (Strict-Transport-Security) is typically best handled by the load balancer
	// or reverse proxy (like Render's) that terminates TLS.
}

// getSubdomainConfig returns the specific configuration for a given host,
// falling back to the default configuration if no specific one is found.
// It starts with the default configuration and then overrides it with any
// settings specified for the particular host.
func getSubdomainConfig(host string) SubdomainConfig {
	// Start with a copy of the default configuration.
	mergedConfig := config.Defaults

	// Check if a specific configuration exists for this host.
	if subConfig, ok := config.Subdomains[host]; ok {
		// Override defaults with specific settings if they are not zero-valued.
		if subConfig.LinkLen1Timeout != "" {
			mergedConfig.LinkLen1Timeout = subConfig.LinkLen1Timeout
		}
		if subConfig.LinkLen2Timeout != "" {
			mergedConfig.LinkLen2Timeout = subConfig.LinkLen2Timeout
		}
		if subConfig.LinkLen3Timeout != "" {
			mergedConfig.LinkLen3Timeout = subConfig.LinkLen3Timeout
		}
		if subConfig.CustomTimeout != "" {
			mergedConfig.CustomTimeout = subConfig.CustomTimeout
		}
		if subConfig.LinkLen1Display != "" {
			mergedConfig.LinkLen1Display = subConfig.LinkLen1Display
		}
		if subConfig.LinkLen2Display != "" {
			mergedConfig.LinkLen2Display = subConfig.LinkLen2Display
		}
		if subConfig.LinkLen3Display != "" {
			mergedConfig.LinkLen3Display = subConfig.LinkLen3Display
		}
		if subConfig.CustomDisplay != "" {
			mergedConfig.CustomDisplay = subConfig.CustomDisplay
		}
		if subConfig.LinkAccessMaxNr != 0 {
			mergedConfig.LinkAccessMaxNr = subConfig.LinkAccessMaxNr
		}
		// If a subdomain defines its own static links, they completely override the defaults.
		if subConfig.StaticLinks != nil {
			mergedConfig.StaticLinks = subConfig.StaticLinks
		}
	}

	// Ensure the StaticLinks map is never nil to prevent panics.
	if mergedConfig.StaticLinks == nil {
		mergedConfig.StaticLinks = make(map[string]string)
	}

	return mergedConfig
}

// validRequest returns true if the host string matches any of the valid hosts specified in the config and if the request is of a valid method (GET, POST)
func validRequest(r *http.Request) bool {
	var validHost, validType bool
	for _, d := range config.DomainNames {
		if r.Host == d {
			validHost = true
			break
		}
	}

	// If the host was not in the main DomainNames list, check if it's defined
	// as a key in the Subdomains map. This avoids redundant configuration.
	if !validHost {
		_, validHost = config.Subdomains[r.Host]
	}

	if r.Method == "GET" || r.Method == "POST" {
		validType = true
	}

	return validHost && validType
}

var customResolver *net.Resolver

func initResolver() {
	if len(config.MalwareProtection.CustomDNSServers) > 0 {
		dialer := &net.Dialer{
			Timeout: 5 * time.Second,
		}
		customResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Randomly select a DNS server from the list for each dial to improve resilience.
				server := config.MalwareProtection.CustomDNSServers[rand.Intn(len(config.MalwareProtection.CustomDNSServers))]
				return dialer.DialContext(ctx, "udp", server)
			},
		}
		if slogger != nil {
			slogger.Info("Using custom DNS resolver for malware checks", "servers", config.MalwareProtection.CustomDNSServers)
		}
	}
}

// isURLBlockedByDNSBL checks if the domain of a given URL is listed on any of the configured DNSBL servers.
func isURLBlockedByDNSBL(urlToCheck string) (bool, error) {
	if !config.MalwareProtection.Enabled || len(config.MalwareProtection.DNSBLServers) == 0 {
		return false, nil
	}

	resolver := net.DefaultResolver
	if customResolver != nil {
		resolver = customResolver
	}

	parsedURL, err := url.Parse(urlToCheck)
	if err != nil {
		return false, fmt.Errorf("could not parse URL for DNSBL check: %w", err)
	}
	host := parsedURL.Hostname()

	// Determine the list of IPs to check.
	var ipsToCheck []net.IP
	// First, check if the host is already a literal IP address.
	ip := net.ParseIP(host)
	if ip != nil {
		// If it is, that's the only IP we need to check.
		ipsToCheck = []net.IP{ip}
	} else {
		// If it's a domain name, resolve it to its IP addresses.
		resolvedIPs, err := resolver.LookupIP(context.Background(), "ip", host)
		if err != nil {
			// This can happen for legitimate new domains. We log it but don't treat it as a block.
			slogger.Info("Could not resolve host for DNSBL check", "host", host, "error", err)
			return false, nil
		}
		ipsToCheck = resolvedIPs
	}

	for _, currentIP := range ipsToCheck {
		// We only check IPv4 addresses as they are the most common in these blocklists.
		ipv4 := currentIP.To4()
		if ipv4 == nil {
			continue
		}

		// Reverse the IP address octets for the DNSBL query.
		reversedIP := fmt.Sprintf("%d.%d.%d.%d", ipv4[3], ipv4[2], ipv4[1], ipv4[0])

		for _, server := range config.MalwareProtection.DNSBLServers {
			query := fmt.Sprintf("%s.%s", reversedIP, server)
			// If the lookup returns any address, it means the IP is on the blocklist.
			addrs, err := resolver.LookupHost(context.Background(), query)
			if err != nil {
				if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
					// This is the expected result for a clean IP, so we continue to the next server.
					continue
				}
				// Any other error is a network or configuration problem that should be reported.
				return false, fmt.Errorf("DNSBL lookup failed for %s: %w", query, err)
			}
			if len(addrs) > 0 {
				slogger.Warn("Blocked URL due to DNSBL match", "url", urlToCheck, "ip", currentIP.String(), "dnsbl_server", server)
				return true, nil
			}
		}
	}

	if slogger != nil {
		slogger.Debug("URL passed DNSBL check", "url", urlToCheck)
	}
	return false, nil
}

func lowRAM() bool {
	return config.LowRAM
}

// findDataDir locates the data directory by searching in common locations.
// It prioritizes the directory next to the executable, then the current working directory.
func findDataDir(baseDirName string) (string, error) {
	// 1. Check for path relative to the executable
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		relPath := filepath.Join(exeDir, baseDirName)
		if _, err := os.Stat(relPath); err == nil {
			// Found it next to the executable
			return relPath, nil
		}
	}

	// 2. If not found, check the current working directory
	cwd, err := os.Getwd()
	if err == nil {
		cwdPath := filepath.Join(cwd, baseDirName)
		if _, err := os.Stat(cwdPath); err == nil {
			// Found it in the CWD
			return cwdPath, nil
		}
	}

	return "", fmt.Errorf("could not find data directory '%s' relative to executable or current working directory", baseDirName)
}

func compress(data []byte) (compressedData []byte, err error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompress(data []byte) (string, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer r.Close()
	var b bytes.Buffer
	if _, err := io.Copy(&b, r); err != nil {
		return "", err
	}
	return b.String(), nil
}

// logErrors will write the error to the log file and send an HTTP error to the user.
func logErrors(w http.ResponseWriter, r *http.Request, userMessage string, statusCode int, logMessage string) {
	if slogger != nil {
		slogger.Error(logMessage,
			slog.Int("status", statusCode),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("user_agent", r.UserAgent()),
			slog.String("referer", r.Referer()),
		)
	}

	// Ensure all error pages also receive security headers.
	addHeaders(w, r)

	// Attempt to render the themed error page.
	errorTmpl, ok := templateMap["error"]
	if !ok {
		// Fallback for safety if the template is missing.
		http.Error(w, userMessage, statusCode)
		return
	}

	w.WriteHeader(statusCode)
	vars := errorPageVars{
		StatusCode: statusCode,
		Message:    userMessage,
	}
	// We don't check the error here, as we can't send another error response.
	_ = errorTmpl.Execute(w, vars)
}

// logOK logs successful requests.
func logOK(r *http.Request, statusCode int) {
	if slogger != nil {
		slogger.Info("handled request",
			slog.Int("status", statusCode),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", r.RemoteAddr),
		)
	}
}

//go:embed embedded/index.default.tmpl
var defaultIndexHTMLFormat string

//go:embed embedded/showLink.default.tmpl
var defaultShowLinkHTML string

//go:embed embedded/showText.default.tmpl
var defaultShowTextHTML string

//go:embed embedded/error.default.tmpl
var defaultErrorHTML string

//go:embed embedded/admin.default.tmpl
var defaultAdminHTML string

//go:embed embedded/admin_edit.default.tmpl
var defaultAdminEditHTML string

//go:embed embedded/admin_edit_static_link.default.tmpl
var defaultAdminEditStaticLinkHTML string

func initTemplates() {
	// templateMap should be used as read only after initTemplates() has returned
	templateMap = make(map[string]*template.Template)

	// Create index page from embedded default, or custom file if it exists.
	loadTemplate("index", defaultIndexHTMLFormat)
	// Create page for showing links from embedded default, or custom file if it exists.
	loadTemplate("showLink", defaultShowLinkHTML)
	// Create page for showing text dumps from embedded default, or custom file if it exists.
	loadTemplate("showText", defaultShowTextHTML)
	// Create an admin page.
	loadTemplate("admin", defaultAdminHTML)
	// Create an admin edit page.
	loadTemplate("admin_edit", defaultAdminEditHTML)
	// Create a page for editing static links.
	loadTemplate("admin_edit_static_link", defaultAdminEditStaticLinkHTML)
	// Create a generic error page.
	loadTemplate("error", defaultErrorHTML)
}

func loadTemplate(templateName, defaultTmplStr string) {
	// The location for user-provided custom templates.
	templatePath := filepath.Join(config.BaseDir, "templates", templateName+".tmpl")

	// Try to parse the custom template file from disk.
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		// If the file doesn't exist or fails to parse, fall back to the embedded default.
		tmpl = template.Must(template.New(templateName).Parse(defaultTmplStr))
	} else if slogger != nil {
		slogger.Info("Successfully loaded custom template", "path", templatePath)
	}

	// Store the loaded or default template in the map with a simple key.
	templateMap[templateName] = tmpl
}

func initImages() {
	ImageMap = make(map[string][]byte)
	imageDir := filepath.Join(config.BaseDir, "images")

	files, err := os.ReadDir(imageDir)
	if err != nil {
		if slogger != nil {
			slogger.Warn("Error reading image directory, images may not be available", "path", imageDir, "error", err)
		}
		// If we can't read the directory, we stop. This avoids using any old, hardcoded fallbacks.
		return
	}

	for _, file := range files {
		// We only care about files, not subdirectories
		if file.IsDir() {
			continue
		}

		fileName := file.Name()
		// Load only common image types to avoid loading other files by mistake
		if strings.HasSuffix(fileName, ".png") || strings.HasSuffix(fileName, ".ico") || strings.HasSuffix(fileName, ".svg") {
			filePath := filepath.Join(imageDir, fileName)
			data, err := os.ReadFile(filePath)
			if err != nil {
				slogger.Error("Error reading image file", "path", filePath, "error", err)
				continue // Skip this file and try the next one
			}
			ImageMap[fileName] = data
			if slogger != nil {
				slogger.Info("Successfully loaded image", "name", fileName, "size_bytes", len(data))
			}
		}
	}
}
