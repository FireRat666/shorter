package main

import (
	"fmt"
	"image/png"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FireRat666/shorter/web"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// handleAdminRoutes sets up a sub-router for all admin-related endpoints.
// It applies the sessionAuth middleware to each handler and then wraps the
// entire sub-router with the CSP middleware for enhanced security.
func handleAdminRoutes(mux *http.ServeMux) {
	// Create a new router for admin-only endpoints.
	adminRouter := http.NewServeMux()

	// Register the admin handlers, each wrapped in our new sessionAuth middleware.
	// The paths are relative to the "/admin" prefix that will be stripped.
	adminRouter.HandleFunc("/", sessionAuth(handleAdmin)) // Matches /admin
	adminRouter.HandleFunc("/edit", sessionAuth(handleAdminEditPage))
	adminRouter.HandleFunc("/edit_static_link", sessionAuth(handleAdminEditStaticLinkPage))
	adminRouter.HandleFunc("/api-keys", sessionAuth(handleAdminAPIKeysPage))
	adminRouter.HandleFunc("/edit-link", sessionAuth(handleAdminEditLinkPage))
	adminRouter.HandleFunc("/security", sessionAuth(handleAdminSecurityPage))
	adminRouter.HandleFunc("/stats", sessionAuth(handleAdminStatsPage))
	adminRouter.HandleFunc("/logout", sessionAuth(handleAdminLogout)) // Logout must be protected

	// Add the new handlers for the lazy-loaded statistic partials.
	adminRouter.HandleFunc("/stats/overall", sessionAuth(adminStatsOverallHandler))
	adminRouter.HandleFunc("/stats/top-links", sessionAuth(adminStatsTopLinksHandler))
	adminRouter.HandleFunc("/stats/recent-activity", sessionAuth(adminStatsRecentActivityHandler))
	adminRouter.HandleFunc("/security/qr", sessionAuth(handleAdminSecurityQR))
	adminRouter.HandleFunc("/stats/creator-stats", sessionAuth(adminStatsCreatorStatsHandler))
	adminRouter.HandleFunc("/stats/domain-list", sessionAuth(adminStatsDomainListHandler))
	adminRouter.HandleFunc("/stats/domain-details", sessionAuth(adminStatsDomainDetailsHandler))
	adminRouter.HandleFunc("/stats/reset", sessionAuth(handleAdminResetStats))

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
		action := r.FormValue("action")
		// Wrap all state-changing actions in CSRF protection.
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch action {
			case "create":
				handleAdminCreateSubdomain(w, r)
			case "delete":
				handleAdminDeleteSubdomain(w, r)
			default:
				logErrors(w, r, "Invalid admin action.", http.StatusBadRequest, "Unknown admin action submitted")
			}
		})
		csrfProtect(handler)(w, r)
		return
	}

	adminTmpl, ok := templateMap["admin"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin template")
		return
	}

	csrfToken := getOrSetCSRFToken(w, r)

	// Create a map for display that explicitly excludes the primary domain.
	displaySubdomains := make(map[string]SubdomainConfig)
	for domain, subConfig := range config.Subdomains {
		if domain != config.PrimaryDomain {
			displaySubdomains[domain] = subConfig
		}
	}

	// Get site-wide statistics.
	allLinks, err := getAllActiveLinks(r.Context())
	if err != nil {
		// Log the error but don't fail the page load. The stats will just be zero.
		slogger.Error("Failed to retrieve site-wide link statistics", "error", err)
	}

	var totalClicks int
	for _, link := range allLinks {
		totalClicks += link.TimesUsed
	}

	pageVars := adminPageVars{
		Subdomains:          displaySubdomains,
		PrimaryDomainConfig: getSubdomainConfig(config.PrimaryDomain),
		Defaults:            config.Defaults,
		PrimaryDomain:       config.PrimaryDomain,
		CssSRIHash:          cssSRIHash,
		AdminJsSRIHash:      adminJsSRIHash,
		TotalLinks:          len(allLinks),
		TotalClicks:         totalClicks,
		CSRFToken:           csrfToken,
	}

	if err := adminTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

// handleAdminSecurityPage serves the 2FA setup and status page.
func handleAdminSecurityPage(w http.ResponseWriter, r *http.Request) {
	securityTmpl, ok := templateMap["admin_security"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_security template")
		return
	}

	pageVars := struct {
		TOTPEnabled bool
		TOTPSecret  string
		CssSRIHash  string
	}{
		TOTPEnabled: config.Admin.TOTPEnabled,
		TOTPSecret:  config.Admin.TOTPSecret,
		CssSRIHash:  cssSRIHash,
	}

	if err := securityTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_security template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

// handleAdminSecurityQR generates and serves the QR code for 2FA setup.
func handleAdminSecurityQR(w http.ResponseWriter, r *http.Request) {
	if !config.Admin.TOTPEnabled || config.Admin.TOTPSecret == "" {
		http.Error(w, "2FA is not configured on the server.", http.StatusNotFound)
		return
	}

	// Generate a TOTP key object from the secret.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      config.PrimaryDomain,
		AccountName: config.Admin.User,
		Secret:      []byte(config.Admin.TOTPSecret),
	})
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate TOTP key for QR code: "+err.Error())
		return
	}

	// Generate the QR code image and serve it.
	img, err := key.Image(256, 256)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate QR code image: "+err.Error())
		return
	}

	// Encode the image directly to the response writer.
	w.Header().Set("Content-Type", "image/png")
	if err := png.Encode(w, img); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to encode QR code image: "+err.Error())
	}
}

// handleAdminStatsPage serves the detailed statistics page.
// It only loads the initial, fast stats. Slower stats are lazy-loaded.
func handleAdminStatsPage(w http.ResponseWriter, r *http.Request) {
	statsTmpl, ok := templateMap["admin_stats"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_stats template")
		return
	}

	// Note: TopLinks and CreatorStats are intentionally omitted here.
	// All stats are now loaded via async requests to their own handlers.
	pageVars := statsPageVars{
		CssSRIHash: cssSRIHash,
	}

	// Retrieve the nonce from the context, which was set by the CSP middleware.
	// It's safe to ignore the 'ok' here; if it's missing, an empty string will be used,
	// and the script tag's nonce attribute will be empty, causing it to be blocked by CSP.
	nonce, _ := r.Context().Value(web.NonceContextKey).(string)
	pageVars.Nonce = nonce
	// Pass the CSRF token for the reset form.
	pageVars.CSRFToken = getOrSetCSRFToken(w, r)

	if err := statsTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_stats template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

// adminStatsOverallHandler handles the async request for the "Overall" stats partial.
// It explicitly runs ANALYZE first to ensure the estimates are up-to-date.
func adminStatsOverallHandler(w http.ResponseWriter, r *http.Request) {
	// First, run ANALYZE to ensure the database planner has fresh statistics.
	analyzeTables(r.Context())

	// Now, get the overall stats, which will use the fresh estimates.
	stats, err := getOverallStats(r.Context())
	if err != nil {
		slogger.Error("Failed to get overall stats", "error", err)
		http.Error(w, "Failed to load overall stats data.", http.StatusInternalServerError)
		return
	}

	// Create a minimal data struct for the partial template.
	data := struct {
		Stats *LinkStats
	}{
		Stats: stats,
	}

	// Render the partial template directly.
	tmpl, ok := templateMap["admin_stats_overall.partial"]
	if !ok {
		slogger.Error("Unable to load admin_stats_overall.partial template")
		http.Error(w, "Template not found.", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		slogger.Error("Unable to execute admin_stats_overall.partial template", "error", err)
		http.Error(w, "Failed to render template.", http.StatusInternalServerError)
	}
}

// adminStatsTopLinksHandler handles the async request for the "Top Links" partial.
func adminStatsTopLinksHandler(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const limit = 10
	offset := (page - 1) * limit

	totalLinks, err := getTotalActiveLinkCount(r.Context())
	if err != nil {
		slogger.Error("Failed to get total active link count for pagination", "error", err)
		http.Error(w, "Failed to load link data.", http.StatusInternalServerError)
		return
	}

	topLinks, err := getTopLinks(r.Context(), limit, offset)
	if err != nil {
		// We don't use logErrors here because we want to return a partial, not a full error page.
		// A simple 500 with a log message is sufficient. The JS will catch the non-200 response.
		slogger.Error("Failed to get top links stats", "error", err)
		http.Error(w, "Failed to load top links data.", http.StatusInternalServerError)
		return
	}

	totalPages := int(math.Ceil(float64(totalLinks) / float64(limit)))

	// Create a minimal data struct for the partial template.
	data := struct {
		TopLinks    []Link
		TotalLinks  int
		CurrentPage int
		TotalPages  int
		HasPrev     bool
		HasNext     bool
	}{
		TopLinks:    topLinks,
		TotalLinks:  totalLinks,
		CurrentPage: page,
		TotalPages:  totalPages,
		HasPrev:     page > 1,
		HasNext:     page < totalPages,
	}

	// Render the partial template directly.
	tmpl, ok := templateMap["admin_stats_top_links.partial"]
	if !ok {
		slogger.Error("Unable to load admin_stats_top_links.partial template")
		http.Error(w, "Template not found.", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		slogger.Error("Unable to execute admin_stats_top_links.partial template", "error", err)
		http.Error(w, "Failed to render template.", http.StatusInternalServerError)
	}
}

// adminStatsRecentActivityHandler handles the async request for the "Recent Activity" partial.
func adminStatsRecentActivityHandler(w http.ResponseWriter, r *http.Request) {
	// This fetches all stats, but we only need the time-based ones for this partial.
	// The queries are indexed and fast, so this is acceptable.
	stats, err := getLinkStats(r.Context())
	if err != nil {
		slogger.Error("Failed to get recent activity stats", "error", err)
		http.Error(w, "Failed to load recent activity data.", http.StatusInternalServerError)
		return
	}

	// Create a minimal data struct for the partial template.
	data := struct {
		Stats *LinkStats
	}{
		Stats: stats,
	}

	// Render the partial template directly.
	tmpl, ok := templateMap["admin_stats_recent_activity.partial"]
	if !ok {
		slogger.Error("Unable to load admin_stats_recent_activity.partial template")
		http.Error(w, "Template not found.", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		slogger.Error("Unable to execute admin_stats_recent_activity.partial template", "error", err)
		http.Error(w, "Failed to render template.", http.StatusInternalServerError)
	}
}

// adminStatsDomainListHandler serves a partial containing a dropdown of all configured domains.
func adminStatsDomainListHandler(w http.ResponseWriter, r *http.Request) {
	var domains []string
	for domain := range config.Subdomains {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	data := struct {
		Domains []string
	}{
		Domains: domains,
	}

	tmpl, ok := templateMap["admin_stats_domain_list.partial"]
	if !ok {
		slogger.Error("Unable to load admin_stats_domain_list.partial template")
		http.Error(w, "Template not found.", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		slogger.Error("Unable to execute admin_stats_domain_list.partial template", "error", err)
		http.Error(w, "Failed to render template.", http.StatusInternalServerError)
	}
}

// adminStatsDomainDetailsHandler serves a partial with statistics for a single, specified domain.
func adminStatsDomainDetailsHandler(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain parameter is required.", http.StatusBadRequest)
		return
	}
	if _, ok := config.Subdomains[domain]; !ok {
		http.Error(w, "Domain not configured.", http.StatusBadRequest)
		return
	}

	stats, err := getStatsForDomain(r.Context(), domain)
	if err != nil {
		slogger.Error("Failed to get stats for domain", "domain", domain, "error", err)
		http.Error(w, "Failed to load domain details.", http.StatusInternalServerError)
		return
	}

	data := struct{ Stats *DomainStats }{Stats: stats}

	tmpl, ok := templateMap["admin_stats_domain_details.partial"]
	if !ok {
		slogger.Error("Unable to load admin_stats_domain_details.partial template")
		http.Error(w, "Template not found.", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		slogger.Error("Unable to execute admin_stats_domain_details.partial template", "error", err)
		http.Error(w, "Failed to render template.", http.StatusInternalServerError)
	}
}

// adminStatsCreatorStatsHandler handles the async request for the "Creator Stats" partial.
func adminStatsCreatorStatsHandler(w http.ResponseWriter, r *http.Request) {
	creatorStats, err := getCreatorStats(r.Context())
	if err != nil {
		slogger.Error("Failed to get creator stats", "error", err)
		http.Error(w, "Failed to load creator stats data.", http.StatusInternalServerError)
		return
	}

	// Create a minimal data struct for the partial template.
	data := struct {
		CreatorStats []CreatorStats
	}{
		CreatorStats: creatorStats,
	}

	// Render the partial template directly.
	tmpl, ok := templateMap["admin_stats_creator_stats.partial"]
	if !ok {
		slogger.Error("Unable to load admin_stats_creator_stats.partial template")
		http.Error(w, "Template not found.", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		slogger.Error("Unable to execute admin_stats_creator_stats.partial template", "error", err)
		http.Error(w, "Failed to render template.", http.StatusInternalServerError)
	}
}

// handleAdminResetStats handles the request to reset all historical statistics.
func handleAdminResetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/stats", http.StatusSeeOther)
		return
	}

	// Wrap the core logic in CSRF protection.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := resetAllStatistics(r.Context()); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to reset statistics: "+err.Error())
			return
		}

		slogger.Info("All statistics have been reset by admin")
		// Redirect back to the stats page.
		http.Redirect(w, r, "/admin/stats", http.StatusSeeOther)
	})

	csrfProtect(handler)(w, r)
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

		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		const limit = 25 // Show 25 links per page
		offset := (page - 1) * limit

		totalLinks, err := getLinkCountForDomain(r.Context(), domain)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve link count for domain: "+err.Error())
			return
		}

		links, err := getLinksForDomain(r.Context(), domain, limit, offset)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve links for domain: "+err.Error())
			return
		}

		totalPages := int(math.Ceil(float64(totalLinks) / float64(limit)))

		pageVars := adminEditPageVars{
			Domain:         domain,
			Config:         subdomainCfg,
			Defaults:       config.Defaults,
			Links:          links,
			CurrentPage:    page,
			TotalPages:     totalPages,
			HasPrev:        page > 1,
			HasNext:        page < totalPages,
			CssSRIHash:     cssSRIHash,
			AdminJsSRIHash: adminJsSRIHash,
		}

		pageVars.CSRFToken = getOrSetCSRFToken(w, r)

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

		action := r.FormValue("action")
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch action {
			case "update_config":
				handleAdminUpdateConfig(w, r, domain)
			case "add_static_link":
				handleAdminAddStaticLink(w, r, domain)
			case "delete_static_link":
				handleAdminDeleteStaticLink(w, r, domain)
			case "delete_multiple_dynamic_links":
				handleAdminDeleteMultipleDynamicLinks(w, r, domain)
			default:
				logErrors(w, r, "Invalid admin action.", http.StatusBadRequest, "Unknown admin edit action submitted")
			}
		})
		csrfProtect(handler)(w, r)

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

func handleAdminDeleteMultipleDynamicLinks(w http.ResponseWriter, r *http.Request, domain string) {
	// r.Form is already parsed by the calling function.
	linkKeys := r.Form["link_keys"]
	if len(linkKeys) == 0 {
		// If no checkboxes were selected, just redirect back.
		http.Redirect(w, r, "/admin/edit?domain="+domain, http.StatusSeeOther)
		return
	}

	var errorOccurred bool
	for _, key := range linkKeys {
		if err := deleteLink(r.Context(), key, domain); err != nil {
			// Log the error but continue trying to delete the others.
			slogger.Error("Failed to delete dynamic link during bulk operation", "key", key, "domain", domain, "error", err)
			errorOccurred = true
		}
	}

	if errorOccurred {
		slogger.Warn("One or more links could not be deleted during bulk operation", "domain", domain)
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

		pageVars.CSRFToken = getOrSetCSRFToken(w, r)

		if err := editTmpl.Execute(w, pageVars); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_edit_static_link template: "+err.Error())
		}
		logOK(r, http.StatusOK)

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Admin edit static link form parse error: "+err.Error())
			return
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		})
		csrfProtect(handler)(w, r)
	}
}

// handleAdminEditLinkPage serves the page for editing a dynamic link's properties.
func handleAdminEditLinkPage(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	key := r.URL.Query().Get("key")

	if domain == "" || key == "" {
		logErrors(w, r, "Missing domain or key parameter.", http.StatusBadRequest, "Admin edit link page requested without domain or key")
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleAdminEditLinkPageGET(w, r, domain, key)
	case http.MethodPost:
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleAdminEditLinkPagePOST(w, r, domain, key)
		})
		csrfProtect(handler)(w, r)
	default:
		addHeaders(w, r)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAdminEditLinkPageGET(w http.ResponseWriter, r *http.Request, domain, key string) {
	// Retrieve the link's details for editing.
	link, err := getLinkDetails(r.Context(), key, domain)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve link details: "+err.Error())
		return
	}
	if link == nil {
		logErrors(w, r, "Link not found.", http.StatusNotFound, "Admin tried to edit non-existent link: "+key)
		return
	}

	// Decompress text data for display in the textarea.
	var dataString string
	if link.LinkType == "text" {
		if link.IsCompressed {
			decompressed, err := decompress(link.Data)
			if err != nil {
				logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to decompress text data for editing: "+err.Error())
				return
			}
			dataString = decompressed
		} else {
			dataString = string(link.Data)
		}
	} else {
		dataString = string(link.Data)
	}

	editTmpl, ok := templateMap["admin_edit_link"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_edit_link template")
		return
	}

	pageVars := adminEditLinkPageVars{
		Link:       *link,
		DataString: dataString,
		CssSRIHash: cssSRIHash,
	}

	pageVars.CSRFToken = getOrSetCSRFToken(w, r)

	if err := editTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_edit_link template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

func handleAdminEditLinkPagePOST(w http.ResponseWriter, r *http.Request, domain, key string) {
	// Get the existing link to ensure it exists and to have its current state.
	link, err := getLinkDetails(r.Context(), key, domain)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve link for update: "+err.Error())
		return
	}
	if link == nil {
		logErrors(w, r, "Link not found.", http.StatusNotFound, "Admin tried to update non-existent link: "+key)
		return
	}

	// Parse the form data.
	if err := r.ParseForm(); err != nil {
		logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Admin edit link form parse error: "+err.Error())
		return
	}

	// Update the link's data based on its type.
	switch link.LinkType {
	case "url":
		destURL := r.FormValue("destination_url")
		if destURL == "" {
			logErrors(w, r, "Destination URL cannot be empty.", http.StatusBadRequest, "Admin submitted empty destination URL")
			return
		}
		if len(destURL) > config.MaxURLSize {
			logErrors(w, r, "URL is too long.", http.StatusRequestEntityTooLarge, fmt.Sprintf("Submitted URL length %d exceeds maximum of %d", len(destURL), config.MaxURLSize))
			return
		}
		link.Data = []byte(destURL)
		link.IsCompressed = false
	case "text":
		textContent := r.FormValue("text_content")
		if len(textContent) > config.MaxTextSize {
			logErrors(w, r, "Text content is too large.", http.StatusRequestEntityTooLarge, fmt.Sprintf("Submitted text size %d exceeds maximum of %d", len(textContent), config.MaxTextSize))
			return
		}
		textBytes := []byte(textContent)
		link.Data = textBytes
		link.IsCompressed = false
		if len(textBytes) > config.MinSizeToGzip {
			compressed, err := compress(textBytes)
			if err == nil && len(textBytes) > len(compressed) {
				link.Data = compressed
				link.IsCompressed = true
			}
		}
	}

	// Update ExpiresAt.
	expiresAtStr := r.FormValue("expires_at")
	expiresAt, err := time.Parse("2006-01-02 15:04:05", expiresAtStr)
	if err != nil {
		logErrors(w, r, "Invalid date format for Expires At.", http.StatusBadRequest, "Invalid expires_at format: "+expiresAtStr)
		return
	}
	link.ExpiresAt = expiresAt

	// Update TimesAllowed.
	timesAllowedStr := r.FormValue("times_allowed")
	timesAllowed, err := strconv.Atoi(timesAllowedStr)
	if err != nil || timesAllowed < 0 {
		logErrors(w, r, "Invalid value for Max Uses.", http.StatusBadRequest, "Invalid times_allowed value: "+timesAllowedStr)
		return
	}
	link.TimesAllowed = timesAllowed

	// Update password if a new one was provided.
	removePassword := r.FormValue("remove_password") == "true"
	newPassword := r.FormValue("password")

	if removePassword {
		link.PasswordHash.Valid = false
		link.PasswordHash.String = ""
	} else if newPassword != "" {
		// A new password was entered, so we hash and set it.
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to hash new password: "+err.Error())
			return
		}
		link.PasswordHash.String = string(hashedPassword)
		link.PasswordHash.Valid = true
	}
	// If neither condition is met, the password remains unchanged.

	// Persist the changes to the database.
	if err := updateLink(r.Context(), *link); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to update link in database: "+err.Error())
		return
	}

	// Redirect back to the subdomain edit page.
	http.Redirect(w, r, "/admin/edit?domain="+domain, http.StatusSeeOther)
}

// handleAdminAPIKeysPage serves the API key management page and handles key generation/deletion.
func handleAdminAPIKeysPage(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not get user ID from context for API key management")
		return
	}

	if r.Method == http.MethodPost {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "API key management form parse error: "+err.Error())
				return
			}

			switch r.FormValue("action") {
			case "generate":
				newKey, err := createAPIKey(r.Context(), userID)
				if err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate new API key: "+err.Error())
					return
				}
				// Redirect with the new key as a query param so it can be displayed.
				http.Redirect(w, r, "/admin/api-keys?newKey="+url.QueryEscape(newKey.Token), http.StatusSeeOther)
			case "delete":
				tokenToDelete := r.FormValue("token")
				if tokenToDelete == "" {
					logErrors(w, r, "Token cannot be empty.", http.StatusBadRequest, "API key deletion request missing token")
					return
				}
				if err := deleteAPIKey(r.Context(), tokenToDelete); err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to delete API key: "+err.Error())
					return
				}
				http.Redirect(w, r, "/admin/api-keys", http.StatusSeeOther)
			default:
				logErrors(w, r, "Invalid action.", http.StatusBadRequest, "Unknown API key management action")
			}
		})
		csrfProtect(handler)(w, r)
		return
	}

	// Handle GET request.
	keys, err := getAPIKeysForUser(r.Context(), userID)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve API keys: "+err.Error())
		return
	}

	apiKeysTmpl, ok := templateMap["admin_api_keys"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_api_keys template")
		return
	}

	pageVars := adminAPIKeysPageVars{
		APIKeys:        keys,
		NewKey:         r.URL.Query().Get("newKey"),
		AdminJsSRIHash: adminJsSRIHash,
		CssSRIHash:     cssSRIHash,
		CSRFToken:      getOrSetCSRFToken(w, r),
	}

	if err := apiKeysTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_api_keys template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}
