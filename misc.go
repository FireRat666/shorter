package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

	// Set the Content-Security-Policy, but ONLY if it hasn't been set already.
	// This allows specific middleware (like CspAdminMiddleware) to set a custom
	// policy with a nonce, which will not be overwritten by this general function.
	if w.Header().Get("Content-Security-Policy") == "" && config.CSP != "" {
		w.Header().Set("Content-Security-Policy", config.CSP)
	}
}

// getSubdomainConfig returns the specific configuration for a given host,
// falling back to the default configuration if no specific one is found.
// It starts with the default configuration and then overrides it with any
// settings specified for the particular host.
func getSubdomainConfig(host string) SubdomainConfig {
	// Start with the global config values.
	mergedConfig := SubdomainConfig{
		LinkLen1:         config.LinkLen1,
		LinkLen2:         config.LinkLen2,
		LinkLen3:         config.LinkLen3,
		MaxKeyLen:        config.MaxKeyLen,
		MaxRequestSize:   config.MaxRequestSize,
		MaxTextSize:      config.MaxTextSize,
		MinSizeToGzip:    config.MinSizeToGzip,
		FileUploadsEnabled: &config.FileUploadsEnabled,
		// Initialize AnonymousRateLimit with a copy of the global config's values
		AnonymousRateLimit: &AnonymousRateLimitConfig{
			Enabled: config.AnonymousRateLimit.Enabled,
			Every:   config.AnonymousRateLimit.Every,
		},
		RateLimit1: &RateLimitXYConfig{},
		RateLimit2: &RateLimitXYConfig{},
		LinkLen1Timeout:  config.Defaults.LinkLen1Timeout,
		LinkLen1Display:  config.Defaults.LinkLen1Display,
		LinkLen2Timeout:  config.Defaults.LinkLen2Timeout,
		LinkLen2Display:  config.Defaults.LinkLen2Display,
		LinkLen3Timeout:  config.Defaults.LinkLen3Timeout,
		LinkLen3Display:  config.Defaults.LinkLen3Display,
		CustomTimeout:    config.Defaults.CustomTimeout,
		CustomDisplay:    config.Defaults.CustomDisplay,
		LinkAccessMaxNr:  config.Defaults.LinkAccessMaxNr,
		StaticLinks:      config.Defaults.StaticLinks,
	}

	// Check if a specific configuration exists for this host.
	if subConfig, ok := config.Subdomains[host]; ok {
		// Override defaults with specific settings if they are not zero-valued.
		if subConfig.LinkLen1 != 0 {
			mergedConfig.LinkLen1 = subConfig.LinkLen1
		}
		if subConfig.LinkLen2 != 0 {
			mergedConfig.LinkLen2 = subConfig.LinkLen2
		}
		if subConfig.LinkLen3 != 0 {
			mergedConfig.LinkLen3 = subConfig.LinkLen3
		}
		if subConfig.MaxKeyLen != 0 {
			mergedConfig.MaxKeyLen = subConfig.MaxKeyLen
		}
		if subConfig.MaxRequestSize != 0 {
			mergedConfig.MaxRequestSize = subConfig.MaxRequestSize
		}
		if subConfig.MaxTextSize != 0 {
			mergedConfig.MaxTextSize = subConfig.MaxTextSize
		}
		if subConfig.MinSizeToGzip != 0 {
			mergedConfig.MinSizeToGzip = subConfig.MinSizeToGzip
		}
		// For boolean pointers, check if the pointer itself is non-nil.
		if subConfig.FileUploadsEnabled != nil {
			mergedConfig.FileUploadsEnabled = subConfig.FileUploadsEnabled
		}
		// Handle AnonymousRateLimit merging
		if subConfig.AnonymousRateLimit != nil {
			// If 'Enabled' is explicitly set in subConfig, use it.
			// Otherwise, keep the global 'Enabled' setting.
			// This handles the case where 'Enabled' is omitted or explicitly false in subConfig.
			if subConfig.AnonymousRateLimit.Enabled || (subConfig.AnonymousRateLimit.Every != "" && !subConfig.AnonymousRateLimit.Enabled) {
				// If Enabled is true, or if Every is set and Enabled is explicitly false, use subConfig's Enabled.
				mergedConfig.AnonymousRateLimit.Enabled = subConfig.AnonymousRateLimit.Enabled
			}

			// If 'Every' is explicitly set in subConfig, use it.
			if subConfig.AnonymousRateLimit.Every != "" {
				mergedConfig.AnonymousRateLimit.Every = subConfig.AnonymousRateLimit.Every
			}
		}
		if subConfig.RateLimit1 != nil {
			mergedConfig.RateLimit1 = subConfig.RateLimit1
		}
		if subConfig.RateLimit2 != nil {
			mergedConfig.RateLimit2 = subConfig.RateLimit2
		}
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
	// After consolidation at startup, config.Subdomains contains all valid hosts.
	_, validHost := config.Subdomains[r.Host]

	// Allow GET, POST, and HEAD. HEAD is important for health checks from deployment platforms.
	validType := r.Method == http.MethodGet || r.Method == http.MethodPost || r.Method == http.MethodHead

	return validHost && validType
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

// formatFileSize converts a size in bytes to a human-readable string.
func formatFileSize(size int64) string {
	const (
		_  = iota
		KB = 1 << (10 * iota)
		MB
		GB
		TB
	)
	switch {
	case size >= TB:
		return fmt.Sprintf("%.2f TB", float64(size)/float64(TB))
	case size >= GB:
		return fmt.Sprintf("%.2f GB", float64(size)/float64(GB))
	case size >= MB:
		return fmt.Sprintf("%.2f MB", float64(size)/float64(MB))
	case size >= KB:
		return fmt.Sprintf("%.2f KB", float64(size)/float64(KB))
	}
	return fmt.Sprintf("%d B", size)
}

// deleteUploadedFile removes a file from the uploads directory.
// It logs a warning if the deletion fails for any reason other than the file not existing.
func deleteUploadedFile(key string) {
	if key == "" {
		return
	}
	filePath := filepath.Join(config.BaseDir, "uploads", key)
	err := os.Remove(filePath)
	if err != nil && !os.IsNotExist(err) {
		slogger.Warn("Failed to delete uploaded file", "path", filePath, "error", err)
	} else if err == nil {
		slogger.Info("Successfully deleted uploaded file", "path", filePath)
	}
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
		CssSRIHash: cssSRIHash,
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