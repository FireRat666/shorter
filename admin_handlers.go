package main

import (
	"database/sql"
	"encoding/json"
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
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// adminAPIKeysPageVars holds data for the admin API keys template.
type adminAPIKeysPageVars struct {
	APIKeys              []UserAPIKey
	Users                []User
	NewKey               string
	CurrentPage          int
	TotalPages           int
	HasPrev              bool
	HasNext              bool
	SearchQuery          string
	CSRFToken            string
	AdminJsSRIHash       string
	CssSRIHash           string
	Error                string
	CurrentRequestDomain string
}

// handleAdminRoutes sets up a sub-router for all admin-related endpoints.
// It applies the sessionAuth middleware to each handler and then wraps the
// entire sub-router with the CSP middleware for enhanced security.
func handleAdminRoutes(mux *http.ServeMux) {
	// Add the unauthenticated admin login route.
	mux.HandleFunc("/admin/login", handleAdminLoginPage)

	// Create a new router for admin-only endpoints.
	adminRouter := http.NewServeMux()

	// Register the admin handlers, each wrapped in our new sessionAuth middleware.
	// The paths are relative to the "/admin" prefix that will be stripped.
	adminRouter.HandleFunc("/", SessionAuth(roleAuth("super_admin")(handleAdmin))) // Matches /admin
	adminRouter.HandleFunc("/edit", SessionAuth(roleAuth("domain_admin")(handleAdminEditPage)))
	adminRouter.HandleFunc("/edit-user", SessionAuth(roleAuth("domain_admin")(handleAdminEditUserPage)))
	adminRouter.HandleFunc("/edit_static_link", SessionAuth(roleAuth("domain_admin")(handleAdminEditStaticLinkPage)))
	adminRouter.HandleFunc("/edit-link", SessionAuth(roleAuth("moderator")(handleAdminEditLinkPage)))
	adminRouter.HandleFunc("/abuse-reports", SessionAuth(roleAuth("moderator")(handleAdminAbuseReportsPage)))
	adminRouter.HandleFunc("/security", SessionAuth(handleAdminSecurityPage))
	adminRouter.HandleFunc("/stats", SessionAuth(roleAuth("super_admin")(handleAdminStatsPage)))
	adminRouter.HandleFunc("/users", SessionAuth(roleAuth("domain_admin")(handleAdminUsersPage)))
	adminRouter.HandleFunc("/users/create", SessionAuth(roleAuth("domain_admin")(handleAdminCreateUser)))
	adminRouter.HandleFunc("/users/update", SessionAuth(roleAuth("domain_admin")(handleAdminUpdateUser)))
	adminRouter.HandleFunc("/users/delete", SessionAuth(roleAuth("domain_admin")(handleAdminDeleteUser)))
	adminRouter.HandleFunc("/api-keys", SessionAuth(roleAuth("super_admin")(handleAdminAPIKeysPage))) // New API Keys route

	// Add the new handlers for the lazy-loaded statistic partials.
	adminRouter.HandleFunc("/stats/overall", SessionAuth(roleAuth("super_admin")(adminStatsOverallHandler)))
	adminRouter.HandleFunc("/stats/top-links", SessionAuth(roleAuth("super_admin")(adminStatsTopLinksHandler)))
	adminRouter.HandleFunc("/stats/recent-activity", SessionAuth(roleAuth("super_admin")(adminStatsRecentActivityHandler)))
	adminRouter.HandleFunc("/stats/activity-chart-data", SessionAuth(roleAuth("super_admin")(adminStatsActivityChartDataHandler)))
	adminRouter.HandleFunc("/security/qr", SessionAuth(handleAdminSecurityQR))
	adminRouter.HandleFunc("/stats/creator-stats", SessionAuth(roleAuth("super_admin")(adminStatsCreatorStatsHandler)))
	adminRouter.HandleFunc("/stats/domain-list", SessionAuth(roleAuth("super_admin")(adminStatsDomainListHandler)))
	adminRouter.HandleFunc("/stats/domain-details", SessionAuth(roleAuth("super_admin")(adminStatsDomainDetailsHandler)))
	adminRouter.HandleFunc("/stats/reset", SessionAuth(roleAuth("super_admin")(handleAdminResetStats)))

	// Create a handler that first strips the "/admin" prefix, then passes to the adminRouter.
	// This is the standard way to handle sub-routing.
	adminHandler := http.StripPrefix("/admin", adminRouter)

	// Wrap the StripPrefix handler with our CSP middleware.
	finalAdminHandler := web.CspAdminMiddleware(adminHandler)

	mux.Handle("/admin/", finalAdminHandler)
}

// handleAdminLoginPage serves the admin login page.
func handleAdminLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		handleLogin(w, r)
		return
	}

	// If the user is already logged in as an admin, redirect them to the dashboard.
	cookie, err := r.Cookie("session_token")
	if err == nil {
		session, _ := getSessionByToken(r.Context(), cookie.Value)
		if session != nil {
			user, _ := getUserByID(r.Context(), session.UserID)
			if user != nil && (user.Role == "super_admin" || user.Role == "domain_admin") {
				http.Redirect(w, r, "/admin/", http.StatusSeeOther)
				return
			}
		}
	}

	loginTmpl, ok := templateMap["admin_login"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_login template")
		return
	}

	captchaActive := config.HCaptcha.EnableForLogin && config.HCaptcha.SiteKey != ""

	pageVars := struct {
		CssSRIHash      string
		Error           string
		CSRFToken       string
		CaptchaActive   bool
		HCaptchaSiteKey string
	}{
		CssSRIHash:      cssSRIHash,
		Error:           r.URL.Query().Get("error"),
		CSRFToken:       getOrSetCSRFToken(w, r),
		CaptchaActive:   captchaActive,
		HCaptchaSiteKey: config.HCaptcha.SiteKey,
	}

	if err := loginTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_login template: "+err.Error())
	}
	logOK(r, http.StatusOK)
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
	for domain := range config.Subdomains {
		if domain != config.PrimaryDomain {
			displaySubdomains[domain] = getSubdomainConfig(domain)
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

// handleAdminAbuseReportsPage serves the page for viewing and managing abuse reports.
func handleAdminAbuseReportsPage(w http.ResponseWriter, r *http.Request) {
	adminUser := getUserFromContext(r) // Get adminUser here
	if adminUser == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not get admin user from context for abuse reports")
		return
	}

	if r.Method == http.MethodPost {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Abuse report update form parse error: "+err.Error())
				return
			}
			action := r.FormValue("action")
			switch action {
			case "update_status":
				reportID, err := strconv.ParseInt(r.FormValue("report_id"), 10, 64)
				if err != nil {
					logErrors(w, r, "Invalid report ID.", http.StatusBadRequest, "Invalid report_id for status update")
					return
				}
				newStatus := r.FormValue("new_status")
				if newStatus != "new" && newStatus != "reviewed" && newStatus != "resolved" {
					logErrors(w, r, "Invalid status value.", http.StatusBadRequest, "Invalid new_status for report")
					return
				}
				if err := updateAbuseReportStatus(r.Context(), reportID, newStatus); err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to update abuse report status: "+err.Error())
					return
				}
			case "delete_report":
				reportID, err := strconv.ParseInt(r.FormValue("report_id"), 10, 64)
				if err != nil {
					logErrors(w, r, "Invalid report ID.", http.StatusBadRequest, "Invalid report_id for deletion")
					return
				}
				if err := deleteAbuseReport(r.Context(), reportID); err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to delete abuse report: "+err.Error())
					return
				}
			}
			// Redirect back to the same page to show the update.
			http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
		})
		csrfProtect(handler)(w, r)
		return
	}

	// Handle GET request
	searchQuery := r.URL.Query().Get("q")
	filter := r.URL.Query().Get("filter") // Define filter here
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const limit = 20
	offset := (page - 1) * limit

	totalReports, err := getAbuseReportCount(r.Context(), filter, searchQuery)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve abuse report count: "+err.Error())
		return
	}

	reports, err := getAbuseReports(r.Context(), filter, searchQuery, limit, offset)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve abuse reports: "+err.Error())
		return
	}

	totalPages := int(math.Ceil(float64(totalReports) / float64(limit)))

	tmpl, ok := templateMap["admin_abuse_reports"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_abuse_reports template")
		return
	}

	// Determine the domain to use for the Users link.
	// If the adminUser is a super_admin and their domain is empty, use the primary domain.
	// Otherwise, use the adminUser's domain.
	domainForUsersLink := adminUser.Domain
	if adminUser.Role == "super_admin" && domainForUsersLink == "" {
		domainForUsersLink = config.PrimaryDomain
	}

	pageVars := adminAbuseReportsPageVars{
		Reports:     reports,
		CurrentPage: page,
		TotalPages:  totalPages,
		HasPrev:     page > 1,
		HasNext:     page < totalPages,
		SearchQuery: searchQuery,
		Filter:      filter,
		CssSRIHash:  cssSRIHash,
		CSRFToken:   getOrSetCSRFToken(w, r),
		Domain:      domainForUsersLink, // Use the determined domain
	}

	nonce, _ := r.Context().Value(web.NonceContextKey).(string)
	pageVars.Nonce = nonce

	if err := tmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_abuse_reports template: "+err.Error())
	}
}

// handleAdminSecurityPage serves the 2FA setup and status page.
func handleAdminSecurityPage(w http.ResponseWriter, r *http.Request) {
	adminUser := getUserFromContext(r)
	if adminUser == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not get admin user from context")
		return
	}

	if r.Method == http.MethodPost {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Security form parse error: "+err.Error())
				return
			}

			action := r.FormValue("action")
			switch action {
			case "enable-2fa":
				secret, err := totp.Generate(totp.GenerateOpts{Issuer: r.Host, AccountName: adminUser.Username})
				if err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate TOTP secret: "+err.Error())
					return
				}

				if err := provisionTOTP(r.Context(), adminUser.ID, secret.Secret()); err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to provision 2FA: "+err.Error())
					return
				}
			case "verify-2fa":
				code := r.FormValue("totp_code")
				if !adminUser.TempTOTPSecret.Valid || !totp.Validate(code, adminUser.TempTOTPSecret.String) {
					renderAdminSecurityPage(w, r, adminUser, "Invalid verification code.")
					return
				}
				if err := enableTOTP(r.Context(), adminUser.ID, adminUser.TempTOTPSecret.String); err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to enable 2FA: "+err.Error())
					return
				}
			case "disable-2fa":
				code := r.FormValue("totp_code")
				if !adminUser.TOTPSecret.Valid || !totp.Validate(code, adminUser.TOTPSecret.String) {
					renderAdminSecurityPage(w, r, adminUser, "Invalid verification code.")
					return
				}

				if err := disableTOTP(r.Context(), adminUser.ID); err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to disable 2FA: "+err.Error())
					return
				}
			}
			http.Redirect(w, r, "/admin/security", http.StatusSeeOther)
		})
		csrfProtect(handler)(w, r)
		return
	}

	renderAdminSecurityPage(w, r, adminUser, r.URL.Query().Get("error"))
}

func renderAdminSecurityPage(w http.ResponseWriter, r *http.Request, adminUser *User, errorMsg string) {
	securityTmpl, ok := templateMap["admin_security"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_security template")
		return
	}
	// Determine the domain to use for the Users link.
	// If the adminUser is a super_admin and their domain is empty, use the primary domain.
	// Otherwise, use the adminUser's domain.
	domainForUsersLink := adminUser.Domain
	if adminUser.Role == "super_admin" && domainForUsersLink == "" {
		domainForUsersLink = config.PrimaryDomain
	}

	pageVars := struct {
		TOTPEnabled      bool
		TOTPSecret       string
		CssSRIHash       string
		Error            string
		CSRFToken        string
		TOTPProvisioning bool
		Domain           string
	}{
		TOTPEnabled:      adminUser.TOTPEnabled,
		TOTPSecret:       adminUser.TempTOTPSecret.String, // Show the temp secret for provisioning
		CssSRIHash:       cssSRIHash,
		Error:            errorMsg,
		CSRFToken:        getOrSetCSRFToken(w, r),
		TOTPProvisioning: adminUser.TempTOTPSecret.Valid,
		Domain:           domainForUsersLink,
	}

	if err := securityTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_security template: "+err.Error())
	}
}

// handleAdminSecurityQR generates and serves the QR code for 2FA setup.
func handleAdminSecurityQR(w http.ResponseWriter, r *http.Request) {
	adminUser := getUserFromContext(r)
	if adminUser == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not get admin user from context")
		return
	}

	// The secret to display is the temporary one during provisioning.
	if !adminUser.TempTOTPSecret.Valid {
		http.Error(w, "2FA is not being provisioned for this admin user.", http.StatusNotFound)
		return
	}
	secret := adminUser.TempTOTPSecret.String

	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", r.Host, adminUser.Username, secret, r.Host))
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate TOTP key for QR code: "+err.Error())
		return
	}

	img, err := key.Image(256, 256)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate QR code image: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "image/png")
	if err := png.Encode(w, img); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to encode QR code image: "+err.Error())
	}
}

// handleAdminStatsPage serves the detailed statistics page.
// It only loads the initial, fast stats. Slower stats are lazy-loaded.
func handleAdminStatsPage(w http.ResponseWriter, r *http.Request) {
	adminUser := getUserFromContext(r)
	if adminUser == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not get admin user from context for stats page")
		return
	}

	statsTmpl, ok := templateMap["admin_stats"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_stats template")
		return
	}

	// Determine the domain to use for the Users link.
	// If the adminUser is a super_admin and their domain is empty, use the primary domain.
	// Otherwise, use the adminUser's domain.
	domainForUsersLink := adminUser.Domain
	if adminUser.Role == "super_admin" && domainForUsersLink == "" {
		domainForUsersLink = config.PrimaryDomain
	}

	// Note: TopLinks and CreatorStats are intentionally omitted here.
	// All stats are now loaded via async requests to their own handlers.
	pageVars := statsPageVars{
		CssSRIHash: cssSRIHash,
		Domain:     domainForUsersLink, // Populate the Domain field with the determined value
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

// adminStatsActivityChartDataHandler serves recent activity data formatted for Chart.js.
func adminStatsActivityChartDataHandler(w http.ResponseWriter, r *http.Request) {
	chartData, err := getChartData(r.Context())
	if err != nil {
		slogger.Error("Failed to get chart data", "error", err)
		http.Error(w, "Failed to load chart data.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(chartData); err != nil {
		slogger.Error("Failed to encode chart data to JSON", "error", err)
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
	user := getUserFromContext(r)
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		logErrors(w, r, "Missing domain parameter.", http.StatusBadRequest, "Admin edit page requested without domain")
		return
	}

	// Security check: Ensure the user has permission for this domain.
	if user.Role != "super_admin" && user.Domain != domain {
		logErrors(w, r, "Forbidden", http.StatusForbidden, fmt.Sprintf("User %s does not have permission for domain %s", user.Username, domain))
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Get the fully resolved config for the domain.
		subdomainCfg := getSubdomainConfig(domain)

		// Create a struct holding the true default values for the template to compare against.
		templateDefaults := config.Defaults
		templateDefaults.LinkLen1 = config.LinkLen1
		templateDefaults.LinkLen2 = config.LinkLen2
		templateDefaults.LinkLen3 = config.LinkLen3
		templateDefaults.MaxKeyLen = config.MaxKeyLen
		templateDefaults.MaxRequestSize = config.MaxRequestSize
		templateDefaults.MaxTextSize = config.MaxTextSize
		templateDefaults.MinSizeToGzip = config.MinSizeToGzip
		// Initialize AnonymousRateLimit as a copy of the default, not a pointer to the global config.
		if config.Defaults.AnonymousRateLimit != nil {
			anonRateLimitCopy := *config.Defaults.AnonymousRateLimit
			templateDefaults.AnonymousRateLimit = &anonRateLimitCopy
		} else {
			templateDefaults.AnonymousRateLimit = &AnonymousRateLimitConfig{Enabled: false, Every: "30s"} // Fallback default
		}

		// Explicitly set the effective default for FileUploadsEnabled
		if config.Defaults.FileUploadsEnabled == nil {
			defaultFalse := false
			templateDefaults.FileUploadsEnabled = &defaultFalse
		} else {
			fileUploadsEnabledCopy := *config.Defaults.FileUploadsEnabled
			templateDefaults.FileUploadsEnabled = &fileUploadsEnabledCopy
		}

		// Explicitly set the effective default for RegistrationEnabled
		if config.Defaults.RegistrationEnabled == nil {
			defaultFalse := false
			templateDefaults.RegistrationEnabled = &defaultFalse
		} else {
			registrationEnabledCopy := *config.Defaults.RegistrationEnabled
			templateDefaults.RegistrationEnabled = &registrationEnabledCopy
		}

		// Explicitly set the effective defaults for Captcha settings
		if config.HCaptcha.EnableForLogin {
			defaultTrue := true
			templateDefaults.EnableForLogin = &defaultTrue
		} else {
			defaultFalse := false
			templateDefaults.EnableForLogin = &defaultFalse
		}

		if config.HCaptcha.EnableForRegistration {
			defaultTrue := true
			templateDefaults.EnableForRegistration = &defaultTrue
		} else {
			defaultFalse := false
			templateDefaults.EnableForRegistration = &defaultFalse
		}

		if config.AbuseReporting.CaptchaEnabled {
			defaultTrue := true
			templateDefaults.AbuseReportingCaptchaEnabled = &defaultTrue
		} else {
			defaultFalse := false
			templateDefaults.AbuseReportingCaptchaEnabled = &defaultFalse
		}

		editTmpl, ok := templateMap["admin_edit"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_edit template")
			return
		}

		searchQuery := r.URL.Query().Get("q")

		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		const limit = 25 // Show 25 links per page
		offset := (page - 1) * limit

		var totalLinks int
		var links []Link
		var err error

		if user.Role == "user" {
			totalLinks, err = getLinkCountForDomainAndUser(r.Context(), domain, user.ID, searchQuery)
			if err == nil {
				links, err = getLinksForDomainAndUser(r.Context(), domain, user.ID, searchQuery, limit, offset)
			}
		} else {
			totalLinks, err = getLinkCountForDomain(r.Context(), domain, searchQuery)
			if err == nil {
				links, err = getLinksForDomain(r.Context(), domain, searchQuery, limit, offset)
			}
		}

		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve links: "+err.Error())
			return
		}

		totalPages := int(math.Ceil(float64(totalLinks) / float64(limit)))

		pageVars := adminEditPageVars{
			Domain:         domain,
			Config:         subdomainCfg,
			Defaults:       templateDefaults, // Pass the correctly populated defaults
			Links:          links,
			CurrentPage:    page,
			TotalPages:     totalPages,
			HasPrev:        page > 1,
			HasNext:        page < totalPages,
			SearchQuery:    searchQuery,
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
	http.Redirect(w, r, "/admin/edit?domain="+domain, http.StatusSeeOther)
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
	user := getUserFromContext(r)
	// Security Check: Ensure the user has permission to manage this domain.
	// Super admins can manage any domain.
	// Domain admins and moderators can only manage their assigned domain.
	if user.Role == "domain_admin" || user.Role == "moderator" {
		if user.Domain != domain {
			logErrors(w, r, "Forbidden", http.StatusForbidden, fmt.Sprintf("User %s does not have permission to delete links from domain %s", user.Username, domain))
			return
		}
	}

	// r.Form is already parsed by the calling function.
	linkKeys := r.Form["link_keys"]
	if len(linkKeys) == 0 {
		// If no checkboxes were selected, just redirect back.
		http.Redirect(w, r, "/admin/edit?domain="+domain, http.StatusSeeOther)
		return
	}

	var errorOccurred bool
	for _, key := range linkKeys {
		// Security Check: Before deleting, ensure the user has permission for the specific link.
		// This is an extra layer of defense, especially for the "user" role.
		if user.Role == "user" {
			link, err := getLinkDetails(r.Context(), key, domain)
			if err != nil || link == nil || !link.UserID.Valid || link.UserID.Int64 != user.ID {
				slogger.Warn("Permission denied for user to delete link during bulk operation", "user", user.Username, "key", key, "domain", domain)
				errorOccurred = true
				continue // Skip to the next key
			}
		}

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
	user := getUserFromContext(r)
	domain := r.URL.Query().Get("domain")
	key := r.URL.Query().Get("key")

	if domain == "" || key == "" {
		logErrors(w, r, "Missing domain or key parameter.", http.StatusBadRequest, "Admin edit static link page requested without domain or key")
		return
	}

	// Security check: Ensure the user has permission for this domain.
	if user.Role != "super_admin" && user.Domain != domain {
		logErrors(w, r, "Forbidden", http.StatusForbidden, fmt.Sprintf("User %s does not have permission for domain %s", user.Username, domain))
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
	user := getUserFromContext(r)
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

	// Security Check: Ensure user has permission to edit this specific link.
	hasPermission := false
	switch user.Role {
	case "super_admin":
		hasPermission = true
	case "domain_admin", "moderator":
		if user.Domain == link.Domain {
			hasPermission = true
		}
	case "user":
		if link.UserID.Valid && link.UserID.Int64 == user.ID {
			hasPermission = true
		}
	}

	if !hasPermission {
		logErrors(w, r, "Forbidden", http.StatusForbidden, fmt.Sprintf("User %s does not have permission to edit link %s on domain %s", user.Username, key, domain))
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
		Link:        *link,
		DataString:  dataString,
		Description: link.Description,
		CssSRIHash:  cssSRIHash,
	}

	pageVars.CSRFToken = getOrSetCSRFToken(w, r)

	if err := editTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_edit_link template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

func handleAdminEditLinkPagePOST(w http.ResponseWriter, r *http.Request, domain, key string) {
	user := getUserFromContext(r)
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

	// Security Check: Ensure user has permission to edit this specific link.
	hasPermission := false
	switch user.Role {
	case "super_admin":
		hasPermission = true
	case "domain_admin", "moderator":
		if user.Domain == link.Domain {
			hasPermission = true
		}
	case "user":
		if link.UserID.Valid && link.UserID.Int64 == user.ID {
			hasPermission = true
		}
	}

	if !hasPermission {
		logErrors(w, r, "Forbidden", http.StatusForbidden, fmt.Sprintf("User %s does not have permission to edit link %s on domain %s", user.Username, key, domain))
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

	// Update description.=
	description := r.FormValue("description")
	if description == "" {
		link.Description = sql.NullString{Valid: false}
	} else {
		link.Description = sql.NullString{String: description, Valid: true}
	}
	// Persist the changes to the database.
	if err := updateLink(r.Context(), *link); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to update link in database: "+err.Error())
		return
	}

	// Redirect back to the subdomain edit page.
	http.Redirect(w, r, "/admin/edit?domain="+domain, http.StatusSeeOther)
}

func parseSubdomainForm(r *http.Request) (SubdomainConfig, error) {
	// This helper function parses form values and returns a SubdomainConfig.
	// It's used by both create and update handlers.
	// Note: This function does NOT handle StaticLinks, as they are managed
	// separately on the edit page.
	newConfig := SubdomainConfig{}

	// Helper function to parse an integer form value.
	parseInt := func(formValue string) (int, error) {
		if formValue == "" {
			return 0, nil // Treat empty string as zero, to be ignored.
		}
		return strconv.Atoi(formValue)
	}

	// Helper function to parse an int64 form value.
	parseInt64 := func(formValue string) (int64, error) {
		if formValue == "" {
			return 0, nil // Treat empty string as zero.
		}
		return strconv.ParseInt(formValue, 10, 64)
	}

	var err error
	newConfig.LinkLen1, err = parseInt(r.FormValue("LinkLen1"))
	if err != nil {
		return SubdomainConfig{}, fmt.Errorf("invalid value for Link Length 1: %s", r.FormValue("LinkLen1"))
	}
	newConfig.LinkLen2, err = parseInt(r.FormValue("LinkLen2"))
	if err != nil {
		return SubdomainConfig{}, fmt.Errorf("invalid value for Link Length 2: %s", r.FormValue("LinkLen2"))
	}
	newConfig.LinkLen3, err = parseInt(r.FormValue("LinkLen3"))
	if err != nil {
		return SubdomainConfig{}, fmt.Errorf("invalid value for Link Length 3: %s", r.FormValue("LinkLen3"))
	}
	newConfig.MaxKeyLen, err = parseInt(r.FormValue("MaxKeyLen"))
	if err != nil {
		return SubdomainConfig{}, fmt.Errorf("invalid value for Max Key Length: %s", r.FormValue("MaxKeyLen"))
	}
	newConfig.MaxRequestSize, err = parseInt64(r.FormValue("MaxRequestSize"))
	if err != nil {
		return SubdomainConfig{}, fmt.Errorf("invalid value for Max Request Size: %s", r.FormValue("MaxRequestSize"))
	}

	newConfig.MaxTextSize, err = parseInt(r.FormValue("MaxTextSize"))
	if err != nil {
		return SubdomainConfig{}, fmt.Errorf("invalid value for Max Text Size: %s", r.FormValue("MaxTextSize"))
	}
	newConfig.MinSizeToGzip, err = parseInt(r.FormValue("MinSizeToGzip"))
	if err != nil {
		return SubdomainConfig{}, fmt.Errorf("invalid value for Min Size to Gzip: %s", r.FormValue("MinSizeToGzip"))
	}

	// FileUploadsEnabled is a boolean checkbox.
	fileUploadsEnabled := r.FormValue("FileUploadsEnabled") == "on"
	newConfig.FileUploadsEnabled = &fileUploadsEnabled

	// RegistrationEnabled is a boolean checkbox.
	registrationEnabled := r.FormValue("RegistrationEnabled") == "on"
	newConfig.RegistrationEnabled = &registrationEnabled

	// Captcha settings are boolean checkboxes.
	enableForLogin := r.FormValue("EnableForLogin") == "on"
	newConfig.EnableForLogin = &enableForLogin

	enableForRegistration := r.FormValue("EnableForRegistration") == "on"
	newConfig.EnableForRegistration = &enableForRegistration

	abuseReportingCaptchaEnabled := r.FormValue("AbuseReportingCaptchaEnabled") == "on"
	newConfig.AbuseReportingCaptchaEnabled = &abuseReportingCaptchaEnabled

	// AnonymousRateLimit.Enabled is a boolean checkbox.
	anonymousRateLimitEnabled := r.FormValue("AnonymousRateLimitEnabled") == "on"
	anonymousRateLimitEvery := r.FormValue("AnonymousRateLimitEvery")
	newConfig.AnonymousRateLimit = &AnonymousRateLimitConfig{Enabled: anonymousRateLimitEnabled, Every: anonymousRateLimitEvery}

	// RateLimit1
	rateLimit1Enabled := r.FormValue("RateLimit1Enabled") == "on"
	rateLimit1X, err := parseInt(r.FormValue("RateLimit1X"))
	if err != nil {
		return SubdomainConfig{}, fmt.Errorf("invalid value for Rate Limit 1 X: %s", r.FormValue("RateLimit1X"))
	}
	rateLimit1Y := r.FormValue("RateLimit1Y")
	newConfig.RateLimit1 = &RateLimitXYConfig{Enabled: rateLimit1Enabled, X: rateLimit1X, Y: rateLimit1Y}

	// RateLimit2
	rateLimit2Enabled := r.FormValue("RateLimit2Enabled") == "on"
	rateLimit2X, err := parseInt(r.FormValue("RateLimit2X"))
	if err != nil {
		return SubdomainConfig{}, fmt.Errorf("invalid value for Rate Limit 2 X: %s", r.FormValue("RateLimit2X"))
	}
	rateLimit2Y := r.FormValue("RateLimit2Y")
	newConfig.RateLimit2 = &RateLimitXYConfig{Enabled: rateLimit2Enabled, X: rateLimit2X, Y: rateLimit2Y}

	// Timeouts and Display settings are strings, so we just assign them.
	// The getSubdomainConfig function will then correctly merge these overrides
	// with the global defaults.
	newConfig.LinkLen1Timeout = r.FormValue("LinkLen1Timeout")
	newConfig.LinkLen1Display = r.FormValue("LinkLen1Display")
	newConfig.LinkLen2Timeout = r.FormValue("LinkLen2Timeout")
	newConfig.LinkLen2Display = r.FormValue("LinkLen2Display")
	newConfig.LinkLen3Timeout = r.FormValue("LinkLen3Timeout")
	newConfig.LinkLen3Display = r.FormValue("LinkLen3Display")
	newConfig.CustomTimeout = r.FormValue("CustomTimeout")
	newConfig.CustomDisplay = r.FormValue("CustomDisplay")

	maxUsesStr := r.FormValue("LinkAccessMaxNr")
	if maxUsesStr != "" {
		maxUses, err := strconv.Atoi(maxUsesStr)
		if err != nil {
			return SubdomainConfig{}, fmt.Errorf("invalid value for Max Uses: %s", maxUsesStr)
		}
		newConfig.LinkAccessMaxNr = maxUses
	}

	return newConfig, nil
}

// handleAdminUsersPage serves the user management page for a domain.
func handleAdminUsersPage(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	domain := r.URL.Query().Get("domain")

	// If the user is a domain admin, they can only manage their own domain.
	if user.Role == "domain_admin" {
		domain = user.Domain
	}

	if domain == "" {
		logErrors(w, r, "Missing domain parameter.", http.StatusBadRequest, "Admin users page requested without domain")
		return
	}

	// Security check: Super admin can manage any domain, domain admin only their own.
	if user.Role != "super_admin" && user.Domain != domain {
		logErrors(w, r, "Forbidden", http.StatusForbidden, fmt.Sprintf("User %s does not have permission for domain %s", user.Username, domain))
		return
	}

	searchQuery := r.URL.Query().Get("q")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const limit = 25
	offset := (page - 1) * limit

	totalUsers, err := getUserCountForDomain(r.Context(), domain, searchQuery)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve user count for domain: "+err.Error())
		return
	}

	users, err := getUsersForDomain(r.Context(), domain, searchQuery, limit, offset)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve users for domain: "+err.Error())
		return
	}

	totalPages := int(math.Ceil(float64(totalUsers) / float64(limit)))

	tmpl, ok := templateMap["admin_users"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_users template")
		return
	}

	type adminUsersPageVars struct {
		Domain      string
		Users       []User
		CurrentPage int
		TotalPages  int
		HasPrev     bool
		HasNext     bool
		SearchQuery string
		CssSRIHash  string
		CSRFToken   string
		Error       string
	}

	pageVars := adminUsersPageVars{
		Domain:      domain,
		Users:       users,
		CurrentPage: page,
		TotalPages:  totalPages,
		HasPrev:     page > 1,
		HasNext:     page < totalPages,
		SearchQuery: searchQuery,
		CssSRIHash:  cssSRIHash,
		CSRFToken:   getOrSetCSRFToken(w, r),
		Error:       r.URL.Query().Get("error"),
	}

	if err := tmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_users template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

// handleAdminCreateUser handles the creation of a new user in a domain.
func handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := getUserFromContext(r)
	domain := r.FormValue("domain")

	// Security check
	if user.Role != "super_admin" && user.Domain != domain {
		logErrors(w, r, "Forbidden", http.StatusForbidden, "User does not have permission to create users in this domain")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	role := r.FormValue("role")

	if username == "" || password == "" || role == "" {
		http.Redirect(w, r, fmt.Sprintf("/admin/users?domain=%s&error=Username, password, and role are required", url.QueryEscape(domain)), http.StatusSeeOther)
		return
	}

	// Domain admins can only create users and moderators
	if user.Role == "domain_admin" && (role != "user" && role != "moderator") {
		http.Redirect(w, r, fmt.Sprintf("/admin/users?domain=%s&error=Invalid role", url.QueryEscape(domain)), http.StatusSeeOther)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to hash password: "+err.Error())
		return
	}

	newUser := &User{
		Username: username,
		Password: string(hashedPassword),
		Role:     role,
		Domain:   domain,
	}

	if err := createUserInDomain(r.Context(), newUser); err != nil {
		if strings.Contains(err.Error(), "violates unique constraint") {
			http.Redirect(w, r, fmt.Sprintf("/admin/users?domain=%s&error=Username already exists", url.QueryEscape(domain)), http.StatusSeeOther)
		} else {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to create user: "+err.Error())
		}
		return
	}

	http.Redirect(w, r, "/admin/users?domain="+url.QueryEscape(domain), http.StatusSeeOther)
}

// handleAdminUpdateUser handles updating a user's role.
func handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	adminUser := getUserFromContext(r)
	domain := r.FormValue("domain")
	userID, err := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
	if err != nil {
		logErrors(w, r, "Invalid user ID.", http.StatusBadRequest, "Invalid user_id for update")
		return
	}
	newRole := r.FormValue("role")

	// Security check
	if adminUser.Role != "super_admin" && adminUser.Domain != domain {
		logErrors(w, r, "Forbidden", http.StatusForbidden, "User does not have permission to update users in this domain")
		return
	}

	// Domain admins can only assign 'user' and 'moderator' roles.
	if adminUser.Role == "domain_admin" && (newRole != "user" && newRole != "moderator") {
		http.Redirect(w, r, fmt.Sprintf("/admin/users?domain=%s&error=Invalid role", url.QueryEscape(domain)), http.StatusSeeOther)
		return
	}

	userToUpdate, err := getUserByID(r.Context(), userID)
	if err != nil || userToUpdate == nil {
		logErrors(w, r, "User not found.", http.StatusNotFound, "User to update not found")
		return
	}

	// Ensure the user being updated belongs to the correct domain.
	if userToUpdate.Domain != domain {
		logErrors(w, r, "Forbidden", http.StatusForbidden, "User to update does not belong to this domain")
		return
	}

	userToUpdate.Role = newRole
	if err := updateUser(r.Context(), userToUpdate); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to update user: "+err.Error())
		return
	}

	http.Redirect(w, r, "/admin/users?domain="+url.QueryEscape(domain), http.StatusSeeOther)
}

// handleAdminDeleteUser handles deleting a user.
func handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	adminUser := getUserFromContext(r)
	domain := r.FormValue("domain")
	userID, err := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
	if err != nil {
		logErrors(w, r, "Invalid user ID.", http.StatusBadRequest, "Invalid user_id for deletion")
		return
	}

	// Security check
	if adminUser.Role != "super_admin" && adminUser.Domain != domain {
		logErrors(w, r, "Forbidden", http.StatusForbidden, "User does not have permission to delete users in this domain")
		return
	}

	userToDelete, err := getUserByID(r.Context(), userID)
	if err != nil || userToDelete == nil {
		logErrors(w, r, "User not found.", http.StatusNotFound, "User to delete not found")
		return
	}

	// Ensure the user being deleted belongs to the correct domain.
	if userToDelete.Domain != domain {
		logErrors(w, r, "Forbidden", http.StatusForbidden, "User to delete does not belong to this domain")
		return
	}

	if err := deleteUserByID(r.Context(), userID); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to delete user: "+err.Error())
		return
	}

	http.Redirect(w, r, "/admin/users?domain="+url.QueryEscape(domain), http.StatusSeeOther)
}

// handleAdminEditUserPage serves the page for editing a user's details.
func handleAdminEditUserPage(w http.ResponseWriter, r *http.Request) {
	adminUser := getUserFromContext(r)
	domain := r.URL.Query().Get("domain")
	userID, err := strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64)
	if err != nil {
		logErrors(w, r, "Invalid user ID.", http.StatusBadRequest, "Invalid user_id for edit")
		return
	}

	// Security check: Super admin can manage any domain, domain admin only their own.
	if adminUser.Role != "super_admin" && adminUser.Domain != domain {
		logErrors(w, r, "Forbidden", http.StatusForbidden, fmt.Sprintf("User %s does not have permission for domain %s", adminUser.Username, domain))
		return
	}

	userToEdit, err := getUserByID(r.Context(), userID)
	if err != nil || userToEdit == nil {
		logErrors(w, r, "User not found.", http.StatusNotFound, "User to edit not found")
		return
	}

	// Ensure the user being edited belongs to the correct domain.
	if userToEdit.Domain != domain {
		logErrors(w, r, "Forbidden", http.StatusForbidden, "User to edit does not belong to this domain")
		return
	}

	tmpl, ok := templateMap["admin_edit_user"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_edit_user template")
		return
	}

	type adminEditUserPageVars struct {
		User       *User
		Domain     string
		AdminRole  string
		Error      string
		CssSRIHash string
		CSRFToken  string
	}

	pageVars := adminEditUserPageVars{
		User:       userToEdit,
		Domain:     domain,
		AdminRole:  adminUser.Role,
		Error:      r.URL.Query().Get("error"),
		CssSRIHash: cssSRIHash,
		CSRFToken:  getOrSetCSRFToken(w, r),
	}

	if err := tmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_edit_user template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

// handleAdminAPIKeysPage serves the admin API key management page.
func handleAdminAPIKeysPage(w http.ResponseWriter, r *http.Request) {
	adminUser := getUserFromContext(r)
	if adminUser == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not get admin user from context for API key management")
		return
	}

	if r.Method == http.MethodPost {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Admin API key management form parse error: "+err.Error())
				return
			}

			action := r.FormValue("action")
			switch action {
			case "generate":
				userIDStr := r.FormValue("user_id")
				description := r.FormValue("description")

				var userID int64
				var err error

				var nullDescription sql.NullString
				if description != "" {
					nullDescription = sql.NullString{String: description, Valid: true}
				}

				if userIDStr == "" {
					// If user_id is not provided, default to the current admin's ID
					userID = adminUser.ID
				} else {
					// Otherwise, parse the provided user_id
					userID, err = strconv.ParseInt(userIDStr, 10, 64)
					if err != nil {
						logErrors(w, r, "Invalid User ID.", http.StatusBadRequest, "Invalid user_id for API key generation")
						return
					}
				}

				// Ensure the user exists (only if a user_id was explicitly provided and parsed)
				// If userID was defaulted to adminUser.ID, we already know adminUser exists.
				if userIDStr != "" { // Only check if user_id was explicitly provided
					targetUser, err := getUserByID(r.Context(), userID)
					if err != nil || targetUser == nil {
						logErrors(w, r, "User not found.", http.StatusNotFound, fmt.Sprintf("User with ID %d not found for API key generation", userID))
						return
					}
				}

				newKey, err := createAPIKey(r.Context(), userID, nullDescription)
				if err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate new API key: "+err.Error())
					return
				}
				http.Redirect(w, r, "/admin/api-keys?newKey="+url.QueryEscape(newKey.Token), http.StatusSeeOther)
			case "delete":
				tokenToDelete := r.FormValue("token")
				if tokenToDelete == "" {
					logErrors(w, r, "Token cannot be empty.", http.StatusBadRequest, "API key deletion request missing token")
					return
				}

				// Admin can delete any key, no user ID check needed here.
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

	// Handle GET request
	searchQuery := r.URL.Query().Get("q")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const limit = 25 // Display more keys for admin view
	offset := (page - 1) * limit

	totalKeys, err := getAPIKeyCount(r.Context(), searchQuery) // This function needs to be implemented to get count for all keys
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve API key count: "+err.Error())
		return
	}

	apiKeys, err := getAllAPIKeys(r.Context(), searchQuery, limit, offset) // This function needs to be implemented to get all keys
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve API keys: "+err.Error())
		return
	}

	// Fetch usernames for each API key
	users := make([]User, len(apiKeys))
	for i, key := range apiKeys {
		user, err := getUserByID(r.Context(), key.UserID)
		if err != nil {
			slogger.Error("Failed to retrieve user for API key", "userID", key.UserID, "error", err)
			// Continue, but the username for this key will be empty
			users[i] = User{Username: "Unknown"}
		} else {
			users[i] = *user
		}
	}

	totalPages := int(math.Ceil(float64(totalKeys) / float64(limit)))

	apiKeysTmpl, ok := templateMap["admin_api_keys"] // This template needs to be created
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin_api_keys template")
		return
	}

	pageVars := adminAPIKeysPageVars{
		APIKeys:              apiKeys,
		Users:                users,
		NewKey:               r.URL.Query().Get("newKey"),
		CurrentPage:          page,
		TotalPages:           totalPages,
		HasPrev:              page > 1,
		HasNext:              page < totalPages,
		SearchQuery:          searchQuery,
		CSRFToken:            getOrSetCSRFToken(w, r),
		AdminJsSRIHash:       adminJsSRIHash,
		CssSRIHash:           cssSRIHash,
		Error:                r.URL.Query().Get("error"),
		CurrentRequestDomain: r.Host,
	}

	if err := apiKeysTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin_api_keys template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}
