package main

import (
	"database/sql"
	"fmt"
	"image/png"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func handleUserRoutes(mux *http.ServeMux) {
	userRouter := http.NewServeMux()
	userRouter.HandleFunc("/", SessionAuth(roleAuth("user")(handleUserDashboardPage))) // New
	userRouter.HandleFunc("/edit-link", SessionAuth(roleAuth("user")(handleUserEditLinkPage)))
	userRouter.HandleFunc("/security", SessionAuth(roleAuth("user")(handleUserSecurityPage)))
	userRouter.HandleFunc("/security/qr", SessionAuth(roleAuth("user")(handleUserSecurityQR)))
	userRouter.HandleFunc("/api-keys", SessionAuth(roleAuth("user")(handleUserAPIKeysPage)))

	userHandler := http.StripPrefix("/user", userRouter)
	mux.Handle("/user/", userHandler)
}

// handleUserDashboardPage serves the main dashboard for a logged-in user,
// showing a paginated list of their own links.
func handleUserDashboardPage(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)

	// For a regular user, their dashboard is always for their assigned domain.
	domain := user.Domain

	switch r.Method {
	case http.MethodGet:
		dashboardTmpl, ok := templateMap["user_dashboard"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load user_dashboard template")
			return
		}

		searchQuery := r.URL.Query().Get("q")
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		const limit = 25
		offset := (page - 1) * limit

		totalLinks, err := getLinkCountForDomainAndUser(r.Context(), domain, user.ID, searchQuery)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve link count for user: "+err.Error())
			return
		}

		links, err := getLinksForDomainAndUser(r.Context(), domain, user.ID, searchQuery, limit, offset)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve links for user: "+err.Error())
			return
		}

		totalPages := int(math.Ceil(float64(totalLinks) / float64(limit)))

		pageVars := userDashboardPageVars{
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
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute user_dashboard template: "+err.Error())
		}
		logOK(r, http.StatusOK)

	default:
		addHeaders(w, r)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleUserEditLinkPage(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	key := r.URL.Query().Get("key")

	if domain == "" || key == "" {
		logErrors(w, r, "Missing domain or key parameter.", http.StatusBadRequest, "User edit link page requested without domain or key")
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleUserEditLinkPageGET(w, r, domain, key)
	case http.MethodPost:
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleUserEditLinkPagePOST(w, r, domain, key)
		})
		csrfProtect(handler)(w, r)
	default:
		addHeaders(w, r)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleUserEditLinkPageGET(w http.ResponseWriter, r *http.Request, domain, key string) {
	user := getUserFromContext(r)
	link, err := getLinkDetails(r.Context(), key, domain)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve link details: "+err.Error())
		return
	}
	if link == nil || !link.UserID.Valid || link.UserID.Int64 != user.ID {
		logErrors(w, r, "Not Found", http.StatusNotFound, "User tried to edit a link they do not own")
		return
	}

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

	editTmpl, ok := templateMap["user_edit_link"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load user_edit_link template")
		return
	}

	pageVars := userEditLinkPageVars{
		Link:        *link,
		DataString:  dataString,
		Description: link.Description,
		CssSRIHash:  cssSRIHash,
		CSRFToken:   getOrSetCSRFToken(w, r),
	}

	if err := editTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute user_edit_link template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

func handleUserEditLinkPagePOST(w http.ResponseWriter, r *http.Request, domain, key string) {
	user := getUserFromContext(r)
	link, err := getLinkDetails(r.Context(), key, domain)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve link for update: "+err.Error())
		return
	}
	if link == nil || !link.UserID.Valid || link.UserID.Int64 != user.ID {
		logErrors(w, r, "Not Found", http.StatusNotFound, "User tried to update a link they do not own")
		return
	}

	if err := r.ParseForm(); err != nil {
		logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "User edit link form parse error: "+err.Error())
		return
	}

	destURL := r.FormValue("destination_url")
	if destURL == "" {
		logErrors(w, r, "Destination URL cannot be empty.", http.StatusBadRequest, "User submitted empty destination URL")
		return
	}
	if len(destURL) > config.MaxURLSize {
		logErrors(w, r, "URL is too long.", http.StatusRequestEntityTooLarge, fmt.Sprintf("Submitted URL length %d exceeds maximum of %d", len(destURL), config.MaxURLSize))
		return
	}
	link.Data = []byte(destURL)
	link.IsCompressed = false

	// Determine the new expiration based on the link's key length
	subdomainCfg := getSubdomainConfig(link.Domain)
	var linkTimeout time.Duration

	keyLen := len(link.Key)
	if keyLen <= subdomainCfg.LinkLen1 {
		linkTimeout, _ = time.ParseDuration(subdomainCfg.LinkLen1Timeout)
	} else if keyLen <= subdomainCfg.LinkLen2 {
		linkTimeout, _ = time.ParseDuration(subdomainCfg.LinkLen2Timeout)
	} else if keyLen <= subdomainCfg.LinkLen3 {
		linkTimeout, _ = time.ParseDuration(subdomainCfg.LinkLen3Timeout)
	} else {
		linkTimeout, _ = time.ParseDuration(subdomainCfg.CustomTimeout)
	}

	if linkTimeout == 0 {
		// Fallback to a default if parsing fails or timeout is zero, to prevent permanent links
		linkTimeout = 24 * time.Hour
	}
	link.ExpiresAt = time.Now().Add(linkTimeout)

	timesAllowedStr := r.FormValue("times_allowed")
	timesAllowed, err := strconv.Atoi(timesAllowedStr)
	if err != nil || timesAllowed < 0 {
		logErrors(w, r, "Invalid value for Max Uses.", http.StatusBadRequest, "Invalid times_allowed value: "+timesAllowedStr)
		return
	}
	link.TimesAllowed = timesAllowed

	removePassword := r.FormValue("remove_password") == "true"
	newPassword := r.FormValue("password")

	if removePassword {
		link.PasswordHash.Valid = false
		link.PasswordHash.String = ""
	} else if newPassword != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to hash new password: "+err.Error())
			return
		}
		link.PasswordHash.String = string(hashedPassword)
		link.PasswordHash.Valid = true
	}

	description := r.FormValue("description")
	if description == "" {
		link.Description = sql.NullString{Valid: false}
	} else {
		link.Description = sql.NullString{String: description, Valid: true}
	}

	if err := updateLink(r.Context(), *link); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to update link in database: "+err.Error())
		return
	}

	http.Redirect(w, r, "/user/", http.StatusSeeOther)
}

func handleUserSecurityPage(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	if user == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not get user from context")
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
				secret, err := totp.Generate(totp.GenerateOpts{Issuer: r.Host, AccountName: user.Username})
				if err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate TOTP secret: "+err.Error())
					return
				}

				if err := provisionTOTP(r.Context(), user.ID, secret.Secret()); err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to provision 2FA: "+err.Error())
					return
				}
			case "verify-2fa":
				code := r.FormValue("totp_code")
				if !user.TempTOTPSecret.Valid || !totp.Validate(code, user.TempTOTPSecret.String) {
					renderUserSecurityPage(w, r, user, "Invalid verification code.")
					return
				}
				if err := enableTOTP(r.Context(), user.ID, user.TempTOTPSecret.String); err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to enable 2FA: "+err.Error())
					return
				}
			case "disable-2fa":
				code := r.FormValue("totp_code")
				if !user.TOTPSecret.Valid || !totp.Validate(code, user.TOTPSecret.String) {
					renderUserSecurityPage(w, r, user, "Invalid verification code.")
					return
				}

				if err := disableTOTP(r.Context(), user.ID); err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to disable 2FA: "+err.Error())
					return
				}
			case "delete-account":
				if user.TOTPEnabled {
					code := r.FormValue("totp_code")
					if !user.TOTPSecret.Valid || !totp.Validate(code, user.TOTPSecret.String) {
						renderUserSecurityPage(w, r, user, "Invalid verification code for account deletion.")
						return
					}
				}

				if err := deleteUserByID(r.Context(), user.ID); err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to delete user account: "+err.Error())
					return
				}

				// Clear the session cookie and redirect to the homepage.
				http.SetCookie(w, &http.Cookie{
					Name:    "session_token",
					Value:   "",
					Expires: time.Unix(0, 0),
					Path:    "/",
				})
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return // Explicitly return to stop further execution
			}
			http.Redirect(w, r, "/user/security", http.StatusSeeOther)
		})
		csrfProtect(handler)(w, r)
		return
	}

	renderUserSecurityPage(w, r, user, "")
}

func renderUserSecurityPage(w http.ResponseWriter, r *http.Request, user *User, errorMsg string) {
	securityTmpl, ok := templateMap["user_security"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load user_security template")
		return
	}

	pageVars := struct {
		TOTPEnabled      bool
		TOTPSecret       string
		CssSRIHash       string
		Error            string
		CSRFToken        string
		TOTPProvisioning bool
	}{
		TOTPEnabled:      user.TOTPEnabled,
		TOTPSecret:       user.TempTOTPSecret.String, // Show the temp secret for provisioning
		CssSRIHash:       cssSRIHash,
		Error:            errorMsg,
		CSRFToken:        getOrSetCSRFToken(w, r),
		TOTPProvisioning: user.TempTOTPSecret.Valid,
	}

	if err := securityTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute user_security template: "+err.Error())
	}
}

func handleUserSecurityQR(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	if user == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not get user from context")
		return
	}

	// The secret to display is the temporary one during provisioning.
	if !user.TempTOTPSecret.Valid {
		http.Error(w, "2FA is not being provisioned for this user.", http.StatusNotFound)
		return
	}
	secret := user.TempTOTPSecret.String

	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", r.Host, user.Username, secret, r.Host))
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

// handleUserAPIKeysPage serves the API key management page and handles key generation/deletion.
func handleUserAPIKeysPage(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	if user == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not get user from context for API key management")
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
				description := r.FormValue("description")
				var nullDescription sql.NullString
				if description != "" {
					nullDescription = sql.NullString{String: description, Valid: true}
				}
				newKey, err := createAPIKey(r.Context(), user.ID, nullDescription)
				if err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate new API key: "+err.Error())
					return
				}
				// Redirect with the new key as a query param so it can be displayed.
				http.Redirect(w, r, "/user/api-keys?newKey="+url.QueryEscape(newKey.Token), http.StatusSeeOther)
			case "delete":
				tokenToDelete := r.FormValue("token")
				if tokenToDelete == "" {
					logErrors(w, r, "Token cannot be empty.", http.StatusBadRequest, "API key deletion request missing token")
					return
				}
				// Security check: ensure the key belongs to the user trying to delete it.
				key, err := getAPIKeyByToken(r.Context(), tokenToDelete)
				if err != nil || key == nil || key.UserID != user.ID {
					logErrors(w, r, "Forbidden", http.StatusForbidden, "User does not have permission to delete this API key.")
					return
				}

				if err := deleteAPIKey(r.Context(), tokenToDelete); err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to delete API key: "+err.Error())
					return
				}
				http.Redirect(w, r, "/user/api-keys", http.StatusSeeOther)
			default:
				logErrors(w, r, "Invalid action.", http.StatusBadRequest, "Unknown API key management action")
			}
		})
		csrfProtect(handler)(w, r)
		return
	}

	// Handle GET request.
	searchQuery := r.URL.Query().Get("q")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const limit = 10
	offset := (page - 1) * limit

	totalKeys, err := getAPIKeyCountForUser(r.Context(), user.ID, searchQuery)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve API key count: "+err.Error())
		return
	}

	keys, err := getAPIKeysForUser(r.Context(), user.ID, searchQuery, limit, offset)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to retrieve API keys: "+err.Error())
		return
	}

	totalPages := int(math.Ceil(float64(totalKeys) / float64(limit)))

	apiKeysTmpl, ok := templateMap["user_api_keys"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load user_api_keys template")
		return
	}

	pageVars := userAPIKeysPageVars{
		APIKeys:     keys,
		NewKey:      r.URL.Query().Get("newKey"),
		CurrentPage: page,
		TotalPages:  totalPages,
		HasPrev:     page > 1,
		HasNext:     page < totalPages,
		SearchQuery: searchQuery,
		CSRFToken:   getOrSetCSRFToken(w, r),
		CssSRIHash:  cssSRIHash,
	}

	if err := apiKeysTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute user_api_keys template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}
