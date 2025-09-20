package main

import (
	"math"
	"net/http"
	"strconv"
)

func handleModeratorRoutes(mux *http.ServeMux) {
	moderatorRouter := http.NewServeMux()
	moderatorRouter.HandleFunc("/", SessionAuth(roleAuth("moderator")(handleModeratorDashboardPage)))
	moderatorRouter.HandleFunc("/delete-links", SessionAuth(roleAuth("moderator")(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		csrfProtect(http.HandlerFunc(handleModeratorDeleteMultipleDynamicLinks))(w, r)
	})))

	moderatorHandler := http.StripPrefix("/moderator", moderatorRouter)
	mux.Handle("/moderator/", moderatorHandler)
}

// handleModeratorDashboardPage serves the main dashboard for a logged-in moderator,
// showing a paginated list of all links within their assigned domain.
func handleModeratorDashboardPage(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	domain := user.Domain

	if r.Method != http.MethodGet {
		addHeaders(w, r)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dashboardTmpl, ok := templateMap["moderator_dashboard"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load moderator_dashboard template")
		return
	}

	searchQuery := r.URL.Query().Get("q")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const limit = 25
	offset := (page - 1) * limit

	totalLinks, err := getLinkCountForDomain(r.Context(), domain, searchQuery)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve link count for domain: "+err.Error())
		return
	}

	links, err := getLinksForDomain(r.Context(), domain, searchQuery, limit, offset)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve links for domain: "+err.Error())
		return
	}

	totalPages := int(math.Ceil(float64(totalLinks) / float64(limit)))

	type moderatorDashboardPageVars struct {
		Domain      string
		Links       []Link
		CurrentPage int
		TotalPages  int
		HasPrev     bool
		HasNext     bool
		SearchQuery string
		CssSRIHash  string
		CSRFToken   string
	}

	pageVars := moderatorDashboardPageVars{
		Domain:      domain,
		Links:       links,
		CurrentPage: page,
		TotalPages:  totalPages,
		HasPrev:     page > 1,
		HasNext:     page < totalPages,
		SearchQuery: searchQuery,
		CssSRIHash:  cssSRIHash,
		CSRFToken:   getOrSetCSRFToken(w, r),
	}

	if err := dashboardTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute moderator_dashboard template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

// handleModeratorDeleteMultipleDynamicLinks handles the bulk deletion of links by a moderator.
func handleModeratorDeleteMultipleDynamicLinks(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	domain := user.Domain // The domain is from the user, not a parameter.

	if err := r.ParseForm(); err != nil {
		logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Moderator delete form parse error: "+err.Error())
		return
	}

	linkKeys := r.Form["link_keys"]
	if len(linkKeys) == 0 {
		http.Redirect(w, r, "/moderator/", http.StatusSeeOther)
		return
	}

	var errorOccurred bool
	for _, key := range linkKeys {
		// The moderator's permission for the domain is already confirmed by the roleAuth middleware
		// and by using user.Domain. This is inherently secure.
		if err := deleteLink(r.Context(), key, domain); err != nil {
			slogger.Error("Failed to delete dynamic link during moderator bulk operation", "key", key, "domain", domain, "error", err)
			errorOccurred = true
		}
	}

	if errorOccurred {
		slogger.Warn("One or more links could not be deleted during moderator bulk operation", "domain", domain)
	}

	http.Redirect(w, r, "/moderator/", http.StatusSeeOther)
}
