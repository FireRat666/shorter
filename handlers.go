package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/FireRat666/shorter/web"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
)

func handleRoot(mux *http.ServeMux) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		// This is the main entry point for all non-specific requests.
		// We first add security headers and validate the request host.
		addHeaders(w, r)
		if !validRequest(r) {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Error: invalid request host.")
			return
		}

		// Route the request based on its method.
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			handleGET(w, r)
		case http.MethodPost:
			handlePOST(w, r)
		default:
			// For any other method, return a 405 Method Not Allowed.
			logErrors(w, r, "Method Not Allowed", http.StatusMethodNotAllowed, "Unsupported method: "+r.Method)
		}
	}
	mux.HandleFunc("/", handler)
}

// handlePOST handles all POST requests for creating new links.
func handlePOST(w http.ResponseWriter, r *http.Request) {
	// Get the specific configuration for the requested host.
	subdomainCfg := getSubdomainConfig(r.Host)

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	err := r.ParseMultipartForm(config.MaxFileSize)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusBadRequest, "Error parsing form: "+url.QueryEscape(err.Error()))
		return
	}

	// Determine link expiration and key length based on the selected form option
	length := r.Form.Get("len")
	var linkTimeout time.Duration
	var keyLength int
	switch length {
	case "1":
		linkTimeout, err = time.ParseDuration(subdomainCfg.LinkLen1Timeout)
		keyLength = config.LinkLen1
	case "2":
		linkTimeout, err = time.ParseDuration(subdomainCfg.LinkLen2Timeout)
		keyLength = config.LinkLen2
	case "3":
		linkTimeout, err = time.ParseDuration(subdomainCfg.LinkLen3Timeout)
		keyLength = config.LinkLen3
	case "custom":
		linkTimeout, err = time.ParseDuration(subdomainCfg.CustomTimeout)
		keyLength = 0 // Custom key, length is variable
	default:
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Error: Invalid len argument.")
		return
	}

	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Error parsing link timeout duration: "+err.Error())
		return
	}

	// Check if request is a custom key request and report error if it is invalid
	customKey := ""
	if length == "custom" {
		customKey = r.Form.Get("custom")
		if !validate(customKey) || len(customKey) < 4 || len(customKey) > config.MaxKeyLen {
			logErrors(w, r, errInvalidCustomKey, http.StatusBadRequest, "Invalid custom key.")
			return
		}

		// Check if custom key is already in use in the database
		existingLink, err := getLinkFromDB(r.Context(), customKey, r.Host)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Error checking for existing key: "+err.Error())
			return
		}
		if existingLink != nil {
			logErrors(w, r, errInvalidKeyUsed, http.StatusConflict, "Custom key is already in use.")
			return
		}
	}

	// Get how many times the link can be used before becoming invalid, 0 represents no limit
	xTimes, err := strconv.Atoi(r.Form.Get("xTimes"))
	if err != nil || xTimes < 0 {
		xTimes = 0 // 0 means unlimited
	} else if xTimes > subdomainCfg.LinkAccessMaxNr {
		xTimes = subdomainCfg.LinkAccessMaxNr
	}

	// Handle different request types
	requestType := r.Form.Get("requestType")
	link := &Link{
		Key:          customKey,
		Domain:       r.Host,
		TimesAllowed: xTimes,
		ExpiresAt:    time.Now().Add(linkTimeout),
	}

	switch requestType {
	case "url":
		formURL := r.Form.Get("url")
		if formURL == "" {
			logErrors(w, r, "URL cannot be empty.", http.StatusBadRequest, "Empty URL submitted")
			return
		}

		// Prepend https:// if no scheme is present.
		if !strings.HasPrefix(formURL, "http://") && !strings.HasPrefix(formURL, "https://") {
			formURL = "https://" + formURL
		}

		// Validate the final URL structure.
		if _, err := url.ParseRequestURI(formURL); err != nil {
			logErrors(w, r, "The provided URL appears to be invalid.", http.StatusBadRequest, "Invalid URL after normalization")
			return
		}

		// Check the URL against the blocklist.
		isBlocked, err := isURLBlockedByDNSBL(formURL)
		if err != nil || isBlocked {
			if err != nil {
				slogger.Error("DNSBL check failed, blocking submission", "url", formURL, "error", err)
			}
			logErrors(w, r, "The provided URL is not allowed.", http.StatusBadRequest, "Blocked malicious URL submission")
			return
		}
		link.LinkType = "url"
		link.Data = []byte(formURL)
		link.IsCompressed = false
		createAndRespond(w, r, link, keyLength, scheme)
	case "text":
		if lowRAM() {
			logErrors(w, r, errServerError, http.StatusInternalServerError, errLowRAM)
			return
		}
		textBlob := r.Form.Get("text")
		textBytes := []byte(textBlob)
		link.LinkType = "text"
		link.Data = textBytes
		link.IsCompressed = false

		if len(textBytes) > config.MinSizeToGzip {
			compressed, err := compress(textBytes)
			if err == nil && len(textBytes) > len(compressed) {
				link.Data = compressed
				link.IsCompressed = true
			}
		}

		createAndRespond(w, r, link, keyLength, scheme)
	default:
		logErrors(w, r, errNotImplemented, http.StatusNotImplemented, "Error: Invalid requestType argument.")
	}
}

// sessionAuth is a middleware that protects handlers by requiring a valid session cookie.
func sessionAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			// If the cookie is not present, redirect to the login page.
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Validate the session token from the cookie.
		session, err := getSessionByToken(r.Context(), cookie.Value)
		if err != nil {
			// A database error occurred.
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to validate session: "+err.Error())
			return
		}

		if session == nil {
			// The session is invalid or expired. Redirect to the login page.
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// If the session is valid, call the next handler.
		next.ServeHTTP(w, r)
	}
}

// handleAdminRoutes sets up a sub-router for all admin-related endpoints.
// It applies the basicAuth middleware to each handler and then wraps the
// entire sub-router with the CSP middleware for enhanced security.
func handleAdminRoutes(mux *http.ServeMux) {
	// Create a new router for admin-only endpoints.
	adminRouter := http.NewServeMux()

	// Register the admin handlers, each wrapped in our new sessionAuth middleware.
	// The paths are relative to the "/admin" prefix that will be stripped.
	adminRouter.HandleFunc("/", sessionAuth(handleAdmin)) // Matches /admin
	adminRouter.HandleFunc("/edit", sessionAuth(handleAdminEditPage))
	adminRouter.HandleFunc("/edit_static_link", sessionAuth(handleAdminEditStaticLinkPage))
	adminRouter.HandleFunc("/logout", sessionAuth(handleAdminLogout)) // Logout must be protected

	// Create a handler that first strips the "/admin" prefix, then passes to the adminRouter.
	// This is the standard way to handle sub-routing.
	adminHandler := http.StripPrefix("/admin", adminRouter)

	// Wrap the StripPrefix handler with our CSP middleware.
	finalAdminHandler := web.CspAdminMiddleware(adminHandler)

	mux.Handle("/admin/", finalAdminHandler)
}

// handleAdminLogout deletes the user's session from the database and clears the cookie.
func handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		// If there's no cookie, there's nothing to do.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Delete the session from the database.
	if err := deleteSessionByToken(r.Context(), cookie.Value); err != nil {
		// Log the error, but proceed with logout anyway.
		slogger.Error("Failed to delete session from database during logout", "error", err)
	}

	// Clear the cookie by setting its expiration to a time in the past.
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Unix(0, 0),
		Path:    "/",
	})

	// Redirect to the homepage.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleAdmin serves the admin dashboard page.
func handleAdmin(w http.ResponseWriter, r *http.Request) {
	// Added for debugging: Log every request that reaches the admin handler.
	if slogger != nil {
		slogger.Debug("Admin handler reached", "method", r.Method, "path", r.URL.Path, "form_action", r.FormValue("action"))
	}

	// This handler is only for the root of the admin section ("/admin" or "/admin/").
	// After StripPrefix, the path for these is "/". Any other path that falls
	// through to here (like a request for a static asset) is a 404.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Route request based on HTTP method.
	if r.Method == http.MethodPost {
		// Further route POST requests based on the 'action' form value.
		if err := r.ParseForm(); err != nil {
			logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Admin form parse error: "+err.Error())
			return
		}
		switch r.FormValue("action") {
		case "create":
			handleAdminCreateSubdomain(w, r)
		case "delete":
			handleAdminDeleteSubdomain(w, r)
		default:
			logErrors(w, r, "Invalid admin action.", http.StatusBadRequest, "Unknown admin action submitted")
		}
		return
	}

	addHeaders(w, r)
	adminTmpl, ok := templateMap["admin"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin template")
		return
	}

	// Create a map for display that explicitly excludes the primary domain.
	displaySubdomains := make(map[string]SubdomainConfig)
	for domain, subConfig := range config.Subdomains {
		if domain != config.PrimaryDomain {
			displaySubdomains[domain] = subConfig
		}
	}

	pageVars := adminPageVars{
		Subdomains:          displaySubdomains,
		PrimaryDomainConfig: getSubdomainConfig(config.PrimaryDomain),
		Defaults:            config.Defaults,
		PrimaryDomain:       config.PrimaryDomain,
		CssSRIHash:          cssSRIHash,
		AdminJsSRIHash:      adminJsSRIHash,
	}

	if err := adminTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

func handleAdminCreateSubdomain(w http.ResponseWriter, r *http.Request) {
	subdomainName := r.FormValue("subdomain")

	// Basic validation
	if subdomainName == "" {
		logErrors(w, r, "Subdomain name cannot be empty.", http.StatusBadRequest, "Admin submitted empty subdomain name")
		return
	}

	// Parse form values into a config struct.
	newConfig, err := parseSubdomainForm(r)
	if err != nil {
		logErrors(w, r, err.Error(), http.StatusBadRequest, "Admin form validation failed: "+err.Error())
		return
	}
	// Initialize with empty static links for a new subdomain.
	newConfig.StaticLinks = make(map[string]string)

	// Add the new subdomain to the in-memory config.
	config.Subdomains[subdomainName] = newConfig

	// Persist the changes to the database.
	if err := saveSubdomainConfigToDB(r.Context(), subdomainName, newConfig); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to save configuration to database: "+err.Error())
		return
	}

	// Redirect back to the admin page to show the updated list.
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleAdminDeleteSubdomain(w http.ResponseWriter, r *http.Request) {
	subdomainName := r.FormValue("subdomain")
	if subdomainName == "" {
		logErrors(w, r, "Subdomain name cannot be empty.", http.StatusBadRequest, "Admin delete request missing subdomain name")
		return
	}

	// As a safeguard, prevent the primary domain from being deleted.
	if subdomainName == config.PrimaryDomain {
		logErrors(w, r, "Cannot delete the primary domain.", http.StatusBadRequest, "Attempted to delete primary domain: "+subdomainName)
		return
	}

	// Check that the subdomain actually exists in our configuration.
	if _, ok := config.Subdomains[subdomainName]; !ok {
		logErrors(w, r, "Subdomain not found.", http.StatusNotFound, "Attempted to delete non-existent subdomain: "+subdomainName)
		return
	}

	if slogger != nil {
		slogger.Info("Starting deletion process for subdomain", "subdomain", subdomainName)
	}

	// Also delete all dynamic links associated with this subdomain.
	if err := deleteLinksForDomain(r.Context(), subdomainName); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to delete associated links from database: "+err.Error())
		return
	}

	if slogger != nil {
		slogger.Info("Finished deleting dynamic links for subdomain", "subdomain", subdomainName)
	}

	// Remove the subdomain from the database.
	if err := deleteSubdomainFromDB(r.Context(), subdomainName); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to delete subdomain from database: "+err.Error())
		return
	}

	if slogger != nil {
		slogger.Info("Finished deleting subdomain config from database", "subdomain", subdomainName)
	}

	// Remove the subdomain from the in-memory config.
	delete(config.Subdomains, subdomainName)
	if slogger != nil {
		slogger.Info("Successfully removed subdomain from in-memory map", "subdomain", subdomainName)
	}

	// Redirect back to the admin page.
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleAdminEditPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			logErrors(w, r, "Missing domain parameter.", http.StatusBadRequest, "Admin edit page requested without domain")
			return
		}

		// Confirm that the domain is a configured domain.
		// After consolidation, config.Subdomains contains all valid domains.
		subdomainCfg, ok := config.Subdomains[domain]
		if !ok {
			logErrors(w, r, "Domain not found.", http.StatusNotFound, "Admin tried to edit non-existent domain: "+domain)
			return
		}

		editTmpl, ok := templateMap["admin_edit"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_edit template")
			return
		}

		links, err := getLinksForDomain(r.Context(), domain)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve links for domain: "+err.Error())
			return
		}

		pageVars := adminEditPageVars{
			Domain:         domain,
			Config:         subdomainCfg,
			Defaults:       config.Defaults,
			Links:          links,
			CssSRIHash:     cssSRIHash,
			AdminJsSRIHash: adminJsSRIHash,
		}

		addHeaders(w, r)
		if err := editTmpl.Execute(w, pageVars); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_edit template: "+err.Error())
		}
		logOK(r, http.StatusOK)

	case http.MethodPost:
		// Process form submissions for the edit page
		if err := r.ParseForm(); err != nil {
			logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Admin edit form parse error: "+err.Error())
			return
		}
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			logErrors(w, r, "Missing domain parameter.", http.StatusBadRequest, "Admin edit action submitted without domain")
			return
		}

		switch r.FormValue("action") {
		case "update_config":
			handleAdminUpdateConfig(w, r, domain)
		case "add_static_link":
			handleAdminAddStaticLink(w, r, domain)
		case "delete_static_link":
			handleAdminDeleteStaticLink(w, r, domain)
		case "delete_dynamic_link":
			handleAdminDeleteDynamicLink(w, r, domain)
		default:
			logErrors(w, r, "Invalid admin action.", http.StatusBadRequest, "Unknown admin edit action submitted")
		}

	default:
		addHeaders(w, r)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAdminUpdateConfig(w http.ResponseWriter, r *http.Request, domain string) {
	updatedConfig, err := parseSubdomainForm(r)
	if err != nil {
		logErrors(w, r, err.Error(), http.StatusBadRequest, "Admin form validation failed: "+err.Error())
		return
	}

	// Get the current configuration to preserve the static links, which are not
	// editable on this form.
	currentConfig := getSubdomainConfig(domain)
	updatedConfig.StaticLinks = currentConfig.StaticLinks

	// Update the in-memory config.
	config.Subdomains[domain] = updatedConfig

	// Persist the changes to the database.
	if err := saveSubdomainConfigToDB(r.Context(), domain, updatedConfig); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to save updated configuration to database: "+err.Error())
		return
	}

	// Redirect back to the admin page to show the updated list.
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func handleAdminAddStaticLink(w http.ResponseWriter, r *http.Request, domain string) {
	key := r.FormValue("new_static_key")
	destURL := r.FormValue("new_static_url")

	if key == "" || destURL == "" {
		logErrors(w, r, "Key and Destination URL cannot be empty.", http.StatusBadRequest, "Admin submitted empty static link field")
		return
	}

	// Prepend https:// if no scheme is present.
	if !strings.HasPrefix(destURL, "http://") && !strings.HasPrefix(destURL, "https://") {
		destURL = "https://" + destURL
	}

	// Validate the final URL structure.
	if _, err := url.ParseRequestURI(destURL); err != nil {
		logErrors(w, r, "The provided Destination URL appears to be invalid.", http.StatusBadRequest, "Invalid static link URL after normalization")
		return
	}

	// Get the current config, add the new static link, and save it back.
	subdomainCfg := getSubdomainConfig(domain)
	subdomainCfg.StaticLinks[key] = destURL
	config.Subdomains[domain] = subdomainCfg // Update in-memory config

	if err := saveSubdomainConfigToDB(r.Context(), domain, subdomainCfg); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to add static link: "+err.Error())
		return
	}

	// Redirect back to the edit page.
	http.Redirect(w, r, "/admin/edit?domain="+domain, http.StatusSeeOther)
}

func handleAdminDeleteStaticLink(w http.ResponseWriter, r *http.Request, domain string) {
	key := r.FormValue("static_key")
	if key == "" {
		logErrors(w, r, "Static link key cannot be empty.", http.StatusBadRequest, "Admin delete static link request missing key")
		return
	}

	// Get the current config, delete the static link, and save it back.
	subdomainCfg := getSubdomainConfig(domain)
	delete(subdomainCfg.StaticLinks, key)
	config.Subdomains[domain] = subdomainCfg // Update in-memory config

	if err := saveSubdomainConfigToDB(r.Context(), domain, subdomainCfg); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to delete static link: "+err.Error())
		return
	}

	// Redirect back to the edit page.
	http.Redirect(w, r, "/admin/edit?domain="+domain, http.StatusSeeOther)
}

func handleAdminDeleteDynamicLink(w http.ResponseWriter, r *http.Request, domain string) {
	key := r.FormValue("link_key")
	if key == "" {
		logErrors(w, r, "Link key cannot be empty.", http.StatusBadRequest, "Admin delete dynamic link request missing key")
		return
	}

	// Remove the link from the database.
	if err := deleteLink(r.Context(), key, domain); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to delete link from database: "+err.Error())
		return
	}

	// Redirect back to the edit page.
	http.Redirect(w, r, "/admin/edit?domain="+domain, http.StatusSeeOther)
}

func handleAdminEditStaticLinkPage(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	key := r.URL.Query().Get("key")

	if domain == "" || key == "" {
		logErrors(w, r, "Missing domain or key parameter.", http.StatusBadRequest, "Admin edit static link page requested without domain or key")
		return
	}

	// Get the current config for this domain to find the static link.
	subdomainCfg := getSubdomainConfig(domain)
	destination, ok := subdomainCfg.StaticLinks[key]
	if !ok {
		logErrors(w, r, "Static link not found.", http.StatusNotFound, "Admin tried to edit non-existent static link")
		return
	}

	switch r.Method {
	case http.MethodGet:
		editTmpl, ok := templateMap["admin_edit_static_link"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_edit_static_link template")
			return
		}

		pageVars := adminEditStaticLinkPageVars{
			Domain:      domain,
			Key:         key,
			Destination: destination,
			CssSRIHash:  cssSRIHash,
		}

		addHeaders(w, r)
		if err := editTmpl.Execute(w, pageVars); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_edit_static_link template: "+err.Error())
		}
		logOK(r, http.StatusOK)

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Admin edit static link form parse error: "+err.Error())
			return
		}
		newDestURL := r.FormValue("new_static_url")
		if !strings.HasPrefix(newDestURL, "http://") && !strings.HasPrefix(newDestURL, "https://") {
			newDestURL = "https://" + newDestURL
		}

		// Update the destination URL and save the entire subdomain config back to the DB.
		subdomainCfg.StaticLinks[key] = newDestURL
		config.Subdomains[domain] = subdomainCfg // Update in-memory config

		if err := saveSubdomainConfigToDB(r.Context(), domain, subdomainCfg); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to update static link: "+err.Error())
			return
		}

		// Redirect back to the main edit page for the domain.
		http.Redirect(w, r, "/admin/edit?domain="+domain, http.StatusSeeOther)
	}
}

func handleCSPReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var report CSPReport
	err := json.NewDecoder(r.Body).Decode(&report)
	if err != nil {
		// Don't log the error to the user, just to the server logs.
		slogger.Warn("Failed to decode CSP report", "error", err)
		return
	}

	slogger.Warn("CSP Violation Reported", "report", report.CSPReport)
	// Respond with a 204 No Content, as is standard for reporting endpoints.
	w.WriteHeader(http.StatusNoContent)
}

// parseSubdomainForm extracts and validates subdomain configuration from a form submission.
// This helper is used by both create and update handlers to reduce code duplication.
func parseSubdomainForm(r *http.Request) (SubdomainConfig, error) {
	// When parsing the form, an empty value means "use the default",
	// so we store an empty string/zero value in the config to represent this.
	// The getSubdomainConfig function will then correctly merge these overrides
	// with the site-wide defaults.
	newConfig := SubdomainConfig{
		LinkLen1Timeout: r.FormValue("link_len1_timeout"),
		LinkLen1Display: r.FormValue("link_len1_display"),
		LinkLen2Timeout: r.FormValue("link_len2_timeout"),
		LinkLen2Display: r.FormValue("link_len2_display"),
		LinkLen3Timeout: r.FormValue("link_len3_timeout"),
		LinkLen3Display: r.FormValue("link_len3_display"),
		CustomTimeout:   r.FormValue("custom_timeout"),
		CustomDisplay:   r.FormValue("custom_display"),
	}

	// For the numeric value, if it's empty or invalid, we store 0,
	// which also signifies "use the default" in our merge logic.
	maxUsesStr := r.FormValue("max_uses")
	var maxUses int
	if maxUsesStr != "" {
		var err error
		maxUses, err = strconv.Atoi(maxUsesStr)
		if err != nil || maxUses < 0 {
			return SubdomainConfig{}, fmt.Errorf("invalid value for Max Uses: %s", maxUsesStr)
		}
	}
	newConfig.LinkAccessMaxNr = maxUses

	// Validate all timeout duration formats if they are not empty.
	timeouts := []string{
		newConfig.LinkLen1Timeout, newConfig.LinkLen2Timeout, newConfig.LinkLen3Timeout, newConfig.CustomTimeout,
	}
	for _, t := range timeouts {
		if t != "" {
			if _, err := time.ParseDuration(t); err != nil {
				return SubdomainConfig{}, fmt.Errorf("invalid timeout duration format: %s", t)
			}
		}
	}
	return newConfig, nil
}

// handleLoginPage serves the login page for GET requests and handles login form submissions for POST requests.
func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// If the user is already logged in, redirect them to the admin dashboard.
	cookie, err := r.Cookie("session_token")
	if err == nil {
		session, _ := getSessionByToken(r.Context(), cookie.Value)
		if session != nil {
			http.Redirect(w, r, "/admin/", http.StatusSeeOther)
			return
		}
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Login form parse error: "+err.Error())
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		// Validate credentials against the configuration.
		if username != config.Admin.User || bcrypt.CompareHashAndPassword([]byte(config.Admin.PassHash), []byte(password)) != nil {
			// Authentication failed. Redirect back to login page with an error message.
			slogger.Warn("Failed login attempt", "user", username)
			http.Redirect(w, r, "/login?error=Invalid+username+or+password", http.StatusSeeOther)
			return
		}

		// Authentication successful.
		// In the next step, we will create a session here.
		slogger.Info("Admin user successfully authenticated", "user", username)

		// Create a new session for the user.
		session, err := createSession(r.Context(), username)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to create session: "+err.Error())
			return
		}

		// Set the session token in a secure cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    session.Token,
			Expires:  session.ExpiresAt,
			HttpOnly: true,
			Secure:   r.TLS != nil, // Only send over HTTPS
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})

		// Redirect to the admin dashboard.
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
	}

	// Handle GET request to display the login page.
	addHeaders(w, r)
	loginTmpl, ok := templateMap["login"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load login template")
		return
	}

	pageVars := loginPageVars{
		CssSRIHash: cssSRIHash,
		Error:      r.URL.Query().Get("error"),
	}

	if err := loginTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute login template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

// handleGET will handle GET requests and redirect to the saved link for a key, return a saved textblob or return a file
func handleGET(w http.ResponseWriter, r *http.Request) {

	// This is a safeguard. Requests for static assets should be caught by their specific
	// handlers. If a request for such a path reaches this general-purpose handler, it
	// means the specific handler was not registered (likely due to a missing file at
	// startup). We should return a 404 Not Found instead of trying to process it as a
	// short link.
	if strings.HasPrefix(r.URL.Path, "/js/") ||
		strings.HasPrefix(r.URL.Path, "/css/") ||
		strings.HasPrefix(r.URL.Path, "/img/") ||
		strings.HasPrefix(r.URL.Path, "/admin/") {
		logErrors(w, r, "Not Found", http.StatusNotFound, "Static asset or reserved path not found, handler not registered: "+r.URL.Path)
		return
	}

	// remove / from the beginning of url and remove any character after the key
	key := r.URL.Path[1:]
	extradataindex := strings.IndexAny(key, "/")
	if extradataindex >= 0 {
		key = key[:extradataindex]
	}

	// Get the specific configuration for the requested host.
	subdomainCfg := getSubdomainConfig(r.Host)

	// Return Index page if GET request without a key
	if len(key) == 0 {
		// Check for quick add feature: a GET request to the root with a query string.
		if r.URL.RawQuery != "" {
			formURL := r.URL.RawQuery // The raw query is the URL.

			// Prepend https:// if no scheme is present.
			if !strings.HasPrefix(formURL, "http://") && !strings.HasPrefix(formURL, "https://") {
				formURL = "https://" + formURL
			}

			// Validate the final URL structure.
			if _, err := url.ParseRequestURI(formURL); err != nil {
				logErrors(w, r, "The provided URL appears to be invalid.", http.StatusBadRequest, "Invalid quick-add URL after normalization")
				return
			}

			// Check the URL against the blocklist.
			isBlocked, err := isURLBlockedByDNSBL(formURL)
			if err != nil || isBlocked {
				if err != nil {
					slogger.Error("DNSBL check failed, blocking submission", "url", formURL, "error", err)
				}
				logErrors(w, r, "The provided URL is not allowed.", http.StatusBadRequest, "Blocked malicious URL submission")
				return
			}

			linkTimeout, err := time.ParseDuration(subdomainCfg.LinkLen1Timeout)
			if err != nil {
				logErrors(w, r, errServerError, http.StatusInternalServerError, "Error parsing default link timeout duration: "+err.Error())
				return
			}

			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}

			link := &Link{
				Domain:       r.Host,
				LinkType:     "url",
				Data:         []byte(formURL),
				IsCompressed: false,
				TimesAllowed: 0, // Default to unlimited uses within the timeout period.
				ExpiresAt:    time.Now().Add(linkTimeout),
			}

			createAndRespond(w, r, link, config.LinkLen1, scheme)
			return
		}

		indexTmpl, ok := templateMap["index"]
		if !ok || indexTmpl == nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load index template")
			return
		}
		// Prepare the data for the index page template.
		pageVars := IndexPageVars{
			CssSRIHash:      cssSRIHash,
			LinkLen1Display: subdomainCfg.LinkLen1Display,
			LinkLen2Display: subdomainCfg.LinkLen2Display,
			LinkLen3Display: subdomainCfg.LinkLen3Display,
			CustomDisplay:   subdomainCfg.CustomDisplay,
			LinkAccessMaxNr: subdomainCfg.LinkAccessMaxNr,
		}

		if err := indexTmpl.Execute(w, pageVars); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute index template: "+err.Error())
			return
		}
		logOK(r, http.StatusOK)
		return
	}

	// verify that key only consists of valid characters
	if !validate(key) {
		logErrors(w, r, errInvalidKey, http.StatusBadRequest, "Invalid characters in key.")
		return
	}

	var showLink bool
	if key[len(key)-1] == '~' {
		key = key[:len(key)-1]
		showLink = true
	}

	// start by checking static key map
	if destURL, ok := subdomainCfg.StaticLinks[key]; ok {
		if showLink {
			// If inspection is requested, show the destination URL as plain text.
			logOK(r, http.StatusOK)
			w.Header().Add("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte(r.Host + "/" + key + "\n\nis a static link pointing to \n\n" + html.EscapeString(destURL)))
		} else {
			// Otherwise, perform the permanent redirect.
			logOK(r, http.StatusPermanentRedirect)
			http.Redirect(w, r, destURL, http.StatusPermanentRedirect)
		}
		return
	}

	// Retrieve the link from the database
	lnk, err := getLinkFromDB(r.Context(), key, r.Host)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Error retrieving link from DB: "+err.Error())
		return
	}

	// If link is not found, it might be a file request or a 404
	if lnk == nil {
		logErrors(w, r, errInvalidKey, http.StatusNotFound, "Link not found, expired, or used up: "+key)
		return
	}

	// Add security headers to all successful link/text/file views.
	addHeaders(w, r)

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	switch lnk.LinkType {
	case "url":
		if showLink {
			logOK(r, http.StatusOK)
			w.Header().Add("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte(r.Host + "/" + key + "\n\nis pointing to \n\n" + html.EscapeString(string(lnk.Data))))
			return
		}
		// This is a standard URL shortener request. Render the intermediate page.
		w.Header().Add("Content-Type", "text/html; charset=utf-8")
		t, ok := templateMap["showLink"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not find showLink template")
			return
		}
		tmplArgs := showLinkVars{
			Domain:        scheme + "://" + r.Host,
			Data:          string(lnk.Data),
			Timeout:       lnk.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:  lnk.TimesAllowed,
			RemainingUses: lnk.TimesAllowed - (lnk.TimesUsed + 1),
			CssSRIHash:    cssSRIHash,
		}
		if err := t.Execute(w, tmplArgs); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute showLink template: "+err.Error())
			return
		}
		logOK(r, http.StatusOK)
		return
	case "text":
		if showLink {
			w.Header().Add("Content-Type", "text/plain; charset=utf-8")
			logOK(r, http.StatusOK)
			w.Write([]byte(r.Host + "/" + key + "\n\nis pointing to a " + r.Host + " Text dump"))
			return
		}

		var textContent string
		if lnk.IsCompressed {
			decompressed, err := decompress(lnk.Data)
			if err != nil {
				logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to decompress text data: "+err.Error())
				return
			}
			textContent = decompressed
		} else {
			textContent = string(lnk.Data)
		}

		w.Header().Add("Content-Type", "text/html; charset=utf-8")
		t, ok := templateMap["showText"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not find showText template")
			return
		}

		tmplArgs := showTextVars{
			Domain:            scheme + "://" + r.Host,
			Data:              textContent,
			Timeout:           lnk.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:      lnk.TimesAllowed,
			RemainingUses:     lnk.TimesAllowed - (lnk.TimesUsed + 1),
			CssSRIHash:        cssSRIHash,
			ShowTextJsSRIHash: showTextJsSRIHash,
		}
		if err := t.Execute(w, tmplArgs); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute showText template: "+err.Error())
		}
		logOK(r, http.StatusOK)
		return
	default:
		logErrors(w, r, errServerError, http.StatusInternalServerError, "invalid LinkType "+url.QueryEscape(lnk.LinkType))
		return
	}
}

func createAndRespond(w http.ResponseWriter, r *http.Request, link *Link, keyLength int, scheme string) {
	ctx := r.Context()
	var err error

	// If the key is empty (not a custom key), generate a random one.
	if link.Key == "" {
		// Retry a few times in case of a random key collision.
		for i := 0; i < 5; i++ {
			link.Key, err = generateRandomKey(keyLength)
			if err != nil {
				logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate random key: "+err.Error())
				return
			}
			err = createLinkInDB(ctx, *link)

			// If the insert was successful, break the loop.
			if err == nil {
				break
			}

			// Check if the error is a PostgreSQL unique violation (duplicate key).
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				// This is a key collision. The loop will continue and try again.
				slogger.Debug("Key collision detected, retrying...", "key", link.Key, "attempt", i+1)
				continue
			}

			// If it's any other type of error, break the loop immediately.
			break
		}
	} else {
		// This is a custom key, attempt to insert it once.
		err = createLinkInDB(ctx, *link)
	}

	if err != nil {
		var pgErr *pgconn.PgError
		// Check if the final error was a duplicate key error.
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// keyLength is 0 for custom keys, non-zero for random keys.
			if keyLength == 0 {
				logErrors(w, r, errInvalidKeyUsed, http.StatusConflict, "Custom key is already in use: "+err.Error())
			} else {
				logErrors(w, r, "Could not generate a unique link. Please try a longer link length.", http.StatusConflict, "Failed to create link after multiple key collision retries: "+err.Error())
			}
			return
		}
		// For all other errors, use the generic server error message.
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to create link in database: "+err.Error())
		return
	}

	// Respond to the user with the success page.
	addHeaders(w, r)
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	t, ok := templateMap["showLink"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not find showLink template")
		return
	}

	fullURL := scheme + "://" + r.Host + "/" + link.Key
	tmplArgs := showLinkVars{
		Domain:        scheme + "://" + r.Host,
		Data:          fullURL,
		Timeout:       link.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
		TimesAllowed:  link.TimesAllowed,
		RemainingUses: link.TimesAllowed, // On creation, remaining uses equals times allowed.
		CssSRIHash:    cssSRIHash,
	}
	if err := t.Execute(w, tmplArgs); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute showLink template: "+err.Error())
	}
	logOK(r, http.StatusCreated)
}

func handleCSS(mux *http.ServeMux) error {
	f, err := os.ReadFile(filepath.Join(config.BaseDir, "css", "shorter.css"))
	if err != nil {
		return fmt.Errorf("missing shorter.css in %s/css/: %w", config.BaseDir, err)
	}

	mux.HandleFunc("/shorter.css", getSingleFileHandler(f, "text/css"))
	return nil
}

func handleJS(mux *http.ServeMux) {
	// The jsFileMap is already populated by calculateSRIHashes at startup.
	// We just need to create handlers for each file in the map.
	// This ensures the content being served is identical to the content that was hashed.
	for fileName, fileBytes := range jsFileMap {
		// The path for the handler should be /js/<fileName>
		path := "/js/" + fileName
		mux.HandleFunc(path, getSingleFileHandler(fileBytes, "application/javascript"))
	}
}

func getSingleFileHandler(f []byte, mimeType string) (handleFile func(w http.ResponseWriter, r *http.Request)) {
	var buf bytes.Buffer
	tryGzip := true
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(f)
	if err != nil {
		tryGzip = false
	}
	zw.Close()
	cf := buf.Bytes()

	handleFile = func(w http.ResponseWriter, r *http.Request) {
		addHeaders(w, r)
		w.Header().Add("Content-Type", mimeType)
		w.Header().Add("Cache-Control", "max-age=2592000, public")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && tryGzip {
			w.Header().Add("content-encoding", "gzip")
			w.Write(cf)
			return
		}
		w.Write(f)
	}
	return
}

func getImgHandler(imageName string, mimeType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addHeaders(w, r)
		w.Header().Add("Content-Type", mimeType)
		w.Header().Add("Cache-Control", "max-age=2592000, public")
		// Serve the image directly from the map using its simple filename key.
		if data, ok := ImageMap[imageName]; ok {
			w.Write(data)
		} else {
			// If the image isn't in the map, it wasn't loaded. Return a 404.
			http.NotFound(w, r)
		}
	}
}

// handleImages sets up handlers for image files.
// It relies on initImages() having been called first to populate the ImageMap.
func handleImages(mux *http.ServeMux) {
	// The ImageMap is already populated by initImages() at startup.
	// We just need to create handlers for each image in the map.
	for imageName := range ImageMap {
		// Determine MIME type based on file extension.
		var mimeType string
		switch {
		case strings.HasSuffix(imageName, ".png"):
			mimeType = "image/png"
		case strings.HasSuffix(imageName, ".ico"):
			mimeType = "image/x-icon"
		case strings.HasSuffix(imageName, ".svg"):
			mimeType = "image/svg+xml"
		default:
			// Skip files with unsupported extensions.
			if slogger != nil {
				slogger.Warn("Skipping image handler for unsupported file", "name", imageName)
			}
			continue
		}

		// The path for the handler should be /<imageName>
		path := "/" + imageName
		mux.HandleFunc(path, getImgHandler(imageName, mimeType))
		// Special case for favicon.ico, which browsers often request.
		// If we have a favicon.png, also serve it at /favicon.ico.
		if imageName == "favicon.png" {
			mux.HandleFunc("/favicon.ico", getImgHandler("favicon.png", "image/x-icon"))
		}
	}
}

// handleRobots will return the robots.txt located in the Template dir specified in the config file, if no robots.txt file is found we return a 404 error
func handleRobots(mux *http.ServeMux) {
	f, err := os.ReadFile(filepath.Join(config.BaseDir, "robots.txt"))
	if err != nil {
		if slogger != nil {
			slogger.Info("Missing robots.txt in Template dir, will return 404 for /robots.txt requests")
		}
		handler404 := func(w http.ResponseWriter, r *http.Request) {
			addHeaders(w, r)
			http.Error(w, "Not Found", http.StatusNotFound)
		}
		mux.HandleFunc("/robots.txt", handler404)
		return
	}
	handleRobots := func(w http.ResponseWriter, r *http.Request) {
		addHeaders(w, r)
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Cache-Control", "max-age=2592000, public")
		w.Write(f)
	}
	mux.HandleFunc("/robots.txt", handleRobots)
}
