package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

func handleRoot(mux *http.ServeMux) {
	mux.HandleFunc("/login/2fa", handle2FALoginPage)
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
			// If the request is for the root path, serve the index page.
			if r.URL.Path == "/" {
				serveIndexPage(w, r)
				return
			}
			handleGET(w, r)
		case http.MethodPost:
			// If the POST is to the root path, it's a new link creation.
			if r.URL.Path == "/" {
				csrfProtect(handlePOST)(w, r) // Protect link creation
			} else {
				// Otherwise, it's likely a password submission for an existing link.
				handleGET(w, r)
			}
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

	// Determine link expiration and key length based on the selected form option
	length := r.Form.Get("len")
	var linkTimeout time.Duration
	var keyLength int
	var err error
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

	// Check if an admin is logged in and associate the link with them.
	// This applies to links created via the main form.
	sessionCookie, err := r.Cookie("session_token")
	if err == nil {
		session, _ := getSessionByToken(r.Context(), sessionCookie.Value)
		if session != nil {
			link.CreatedBy.String = session.UserID
			link.CreatedBy.Valid = true
		}
	}

	// Check for and hash the password if provided.
	password := r.Form.Get("password")
	if password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to hash password: "+err.Error())
			return
		}
		link.PasswordHash.String = string(hashedPassword)
		link.PasswordHash.Valid = true
	}

	switch requestType {
	case "url":
		formURL := r.Form.Get("url")
		if formURL == "" {
			logErrors(w, r, "URL cannot be empty.", http.StatusBadRequest, "Empty URL submitted")
			return
		}

		if len(formURL) > config.MaxURLSize {
			logErrors(w, r, "URL is too long.", http.StatusRequestEntityTooLarge, fmt.Sprintf("Submitted URL length %d exceeds maximum of %d", len(formURL), config.MaxURLSize))
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

		if len(textBlob) > config.MaxTextSize {
			logErrors(w, r, "Text content is too large.", http.StatusRequestEntityTooLarge, fmt.Sprintf("Submitted text size %d exceeds maximum of %d", len(textBlob), config.MaxTextSize))
			return
		}

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
	case "file":
		if !config.FileUploadsEnabled {
			logErrors(w, r, "File uploads are disabled on this server.", http.StatusForbidden, "Attempted file upload while feature is disabled")
			return
		}
		if lowRAM() {
			logErrors(w, r, errServerError, http.StatusInternalServerError, errLowRAM)
			return
		}
		// Use ParseMultipartForm to handle file uploads.
		if err := r.ParseMultipartForm(config.MaxRequestSize); err != nil {
			// Check for the specific error when the content type is wrong.
			if errors.Is(err, http.ErrNotMultipart) {
				logErrors(w, r, "Invalid form encoding for file upload.", http.StatusBadRequest, "File upload attempt with wrong form enctype: "+err.Error())
			} else {
				logErrors(w, r, "Request body is too large or malformed.", http.StatusRequestEntityTooLarge, "Failed to parse multipart form: "+err.Error())
			}
			return
		}
		file, handler, err := r.FormFile("file")
		if err != nil {
			logErrors(w, r, "Invalid file upload.", http.StatusBadRequest, "Failed to get file from form: "+err.Error())
			return
		}
		defer file.Close()

		fileBytes, err := io.ReadAll(file)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to read uploaded file: "+err.Error())
			return
		}

		// Store the original filename in the `data` field, and the content in `is_compressed` for now.
		// A schema change would be better, but this works without one.
		link.LinkType = "file"
		link.Data = []byte(handler.Filename) // Store filename
		link.IsCompressed = false            // We won't compress file data for now.
		createAndRespond(w, r, link, keyLength, scheme, fileBytes)
	default:
		logErrors(w, r, errNotImplemented, http.StatusNotImplemented, "Error: Invalid requestType argument.")
	}
}

// A private key type to use for context values. This prevents collisions.
type contextKey string

const userContextKey = contextKey("userID")

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

		// Add user ID to the request context for downstream handlers.
		ctx := context.WithValue(r.Context(), userContextKey, session.UserID)

		// If the session is valid, call the next handler with the new context.
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// getOrSetCSRFToken ensures a CSRF token exists for the current user, creating one if necessary.
// It prioritizes the session-bound token for logged-in users and falls back to a cookie
// for anonymous users. It returns the token.
func getOrSetCSRFToken(w http.ResponseWriter, r *http.Request) string {
	// 1. Check for an existing session first. A logged-in user's CSRF token is bound to their session.
	sessionCookie, err := r.Cookie("session_token")
	if err == nil {
		session, _ := getSessionByToken(r.Context(), sessionCookie.Value)
		if session != nil && session.CSRFToken != "" {
			return session.CSRFToken
		}
	}

	// 2. If no session, check for a standalone CSRF cookie for anonymous users.
	csrfCookie, err := r.Cookie("csrf_token")
	if err == nil && csrfCookie.Value != "" {
		return csrfCookie.Value
	}

	// 3. If no token exists anywhere, generate a new one.
	token, err := generateSessionToken() // Reusing the secure token generator
	if err != nil {
		slogger.Error("Failed to generate CSRF token for anonymous user", "error", err)
		return "" // The CSRF check will fail later, which is the safe default.
	}

	// 4. Set the new token in a cookie for the anonymous user.
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour), // Give it a reasonable lifetime.
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	return token
}

// csrfProtect is a middleware that protects against CSRF attacks.
// It should be used on any handler that processes a state-changing POST request.
func csrfProtect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// This middleware should only be applied to POST requests.
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		// Determine the expected token.
		var expectedToken string
		// Prefer the session-bound token if the user is logged in.
		sessionCookie, err := r.Cookie("session_token")
		if err == nil {
			session, _ := getSessionByToken(r.Context(), sessionCookie.Value)
			if session != nil {
				expectedToken = session.CSRFToken
			}
		}

		// If no session token, fall back to the anonymous CSRF cookie.
		if expectedToken == "" {
			csrfCookie, err := r.Cookie("csrf_token")
			if err == nil {
				expectedToken = csrfCookie.Value
			}
		}

		if expectedToken == "" || r.FormValue("csrf_token") != expectedToken {
			logErrors(w, r, "Forbidden", http.StatusForbidden, "CSRF token mismatch or missing")
			return
		}

		next.ServeHTTP(w, r)
	}
}

// handleAPIRoutes sets up a sub-router for all API endpoints.
func handleAPIRoutes(mux *http.ServeMux) {
	apiRouter := http.NewServeMux()
	apiRouter.HandleFunc("/links", apiAuth(handleAPICreateLink))

	// This handler will strip the "/api/v1" prefix before passing to the apiRouter.
	apiHandler := http.StripPrefix("/api/v1", apiRouter)
	mux.Handle("/api/v1/", apiHandler)
}

// respondWithJSON is a helper to send JSON responses.
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		// This is a server-side error if we can't marshal our own struct.
		slogger.Error("Failed to marshal JSON response", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Internal Server Error"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// respondWithError is a helper to send structured JSON error responses.
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

// apiAuth is a middleware that protects API endpoints by requiring a valid Bearer token.
func apiAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondWithError(w, http.StatusUnauthorized, "Authorization header is required")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			respondWithError(w, http.StatusUnauthorized, "Authorization header must be in 'Bearer {token}' format")
			return
		}

		token := parts[1]
		apiKey, err := getAPIKeyByToken(r.Context(), token)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to validate API key")
			return
		}
		if apiKey == nil {
			respondWithError(w, http.StatusUnauthorized, "Invalid API key")
			return
		}

		// Add the API token itself to the context. This allows us to track link
		// creation per-key, rather than just per-user. The link creation handler
		// will use this value for the `created_by` field.
		ctx := context.WithValue(r.Context(), userContextKey, apiKey.Token)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// handleAPICreateLink handles requests to create a new link via the API.
func handleAPICreateLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	var req apiCreateLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	if req.URL == "" {
		respondWithError(w, http.StatusBadRequest, "The 'url' field is required")
		return
	}

	// Use primary domain if none is specified in the request.
	domain := req.Domain
	if domain == "" {
		domain = config.PrimaryDomain
	}
	// Validate that the requested domain is one we serve.
	if _, ok := config.Subdomains[domain]; !ok {
		respondWithError(w, http.StatusForbidden, "The requested domain is not configured on this service")
		return
	}
	// The creatorID will be the API token, as set by the apiAuth middleware.
	creatorID, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		// This should not happen if apiAuth middleware is working correctly.
		respondWithError(w, http.StatusInternalServerError, "Could not identify creator from API key.")
		return
	}

	subdomainCfg := getSubdomainConfig(domain)

	// Use default timeout if none is specified.
	timeoutStr := req.ExpiresIn
	if timeoutStr == "" {
		timeoutStr = subdomainCfg.LinkLen1Timeout
	}
	linkTimeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid 'expires_in' format. Use Go duration format (e.g., '1h', '30m').")
		return
	}

	link := &Link{
		Key:          req.CustomKey,
		Domain:       domain,
		LinkType:     "url",
		Data:         []byte(req.URL),
		IsCompressed: false,
		TimesAllowed: req.MaxUses,
		ExpiresAt:    time.Now().Add(linkTimeout),
	}
	link.CreatedBy.String = creatorID
	link.CreatedBy.Valid = true

	// Add password if provided.
	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to hash password.")
			return
		}
		link.PasswordHash.String = string(hashedPassword)
		link.PasswordHash.Valid = true
	}

	// Create the link in the database.
	if link.Key == "" {
		// No custom key provided, generate a random one.
		// Use a sensible default length for API-generated keys.
		keyLength := config.LinkLen2
		for i := 0; i < 5; i++ { // Retry a few times on collision.
			link.Key, err = generateRandomKey(keyLength)
			if err != nil {
				respondWithError(w, http.StatusInternalServerError, "Failed to generate random key.")
				return
			}
			err = createLinkInDB(r.Context(), *link)
			if err == nil {
				break // Success
			}
			if errors.Is(err, errKeyCollision) {
				slogger.Debug("API key collision, retrying...", "key", link.Key)
				continue
			}
			// Any other error is fatal for this request.
			break
		}
	} else {
		// Custom key was provided.
		err = createLinkInDB(r.Context(), *link)
	}

	if err != nil {
		if errors.Is(err, errKeyCollision) {
			respondWithError(w, http.StatusConflict, "The requested custom_key is already in use by an active link.")
		} else {
			respondWithError(w, http.StatusInternalServerError, "Failed to create link in database.")
		}
		return
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	response := apiCreateLinkResponse{
		ShortURL:  fmt.Sprintf("%s://%s/%s", scheme, link.Domain, link.Key),
		ExpiresAt: link.ExpiresAt,
	}

	respondWithJSON(w, http.StatusCreated, response)
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

	csrfToken := getOrSetCSRFToken(w, r)

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Login form parse error: "+err.Error())
			return
		}

		// Protect the login form itself from CSRF.
		if r.FormValue("csrf_token") != csrfToken {
			logErrors(w, r, "Forbidden", http.StatusForbidden, "CSRF token mismatch on login form")
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

		// If 2FA is enabled, don't create a full session yet.
		// Create a temporary, signed cookie to indicate the first factor (password) was successful.
		if config.Admin.TOTPEnabled {
			// The message is just the username. The signature proves it's from us.
			signature := generateHMAC([]byte(username))
			cookieValue := fmt.Sprintf("%s|%s", username, base64.StdEncoding.EncodeToString(signature))

			http.SetCookie(w, &http.Cookie{
				Name:     "temp_auth",
				Value:    cookieValue,
				Expires:  time.Now().Add(5 * time.Minute), // Short-lived
				HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, Path: "/",
			})
			http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
			return
		}

		// Authentication successful.
		slogger.Info("Admin user successfully authenticated", "user", username)

		// Determine session duration based on "Remember Me" checkbox.
		rememberMe := r.FormValue("remember_me") == "true"
		var sessionDuration time.Duration
		var err error

		if rememberMe {
			sessionDuration, err = time.ParseDuration(config.SessionTimeoutRememberMe)
			if err != nil {
				slogger.Error("Invalid SessionTimeoutRememberMe format, using default 24h", "duration", config.SessionTimeoutRememberMe, "error", err)
				sessionDuration = 24 * time.Hour
			}
		} else {
			sessionDuration, err = time.ParseDuration(config.SessionTimeout)
			if err != nil {
				slogger.Error("Invalid SessionTimeout format, using default 24h", "duration", config.SessionTimeout, "error", err)
				sessionDuration = 24 * time.Hour
			}
		}

		// Create a new session for the user.
		session, err := createSession(r.Context(), username, sessionDuration)
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

		// Clear the anonymous CSRF cookie, as the token is now part of the session.
		http.SetCookie(w, &http.Cookie{
			Name:    "csrf_token",
			Value:   "",
			Expires: time.Unix(0, 0),
			Path:    "/",
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
		CSRFToken:  csrfToken,
	}

	if err := loginTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute login template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

// handle2FALoginPage handles the second step of the login process for 2FA.
func handle2FALoginPage(w http.ResponseWriter, r *http.Request) {
	// This page should only be accessible if the user has passed the first login step.
	// We verify this with a temporary, signed cookie.
	cookie, err := r.Cookie("temp_auth")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// The cookie value should be "username|signature".
	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 2 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := parts[0]
	signature, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Verify the signature to ensure the cookie hasn't been tampered with.
	if !verifyHMAC([]byte(username), signature) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "2FA form parse error: "+err.Error())
			return
		}

		code := r.FormValue("totp_code")
		if !totp.Validate(code, config.Admin.TOTPSecret) {
			// Invalid code. Re-render the page with an error.
			slogger.Warn("Failed 2FA attempt", "user", username)
			render2FAPage(w, r, "Invalid verification code.")
			return
		}

		// 2FA successful. Now we can create the full, persistent session.
		slogger.Info("Admin user successfully passed 2FA", "user", username)

		// Determine session duration based on "Remember Me" checkbox from the *original* login form.
		// We'll assume a default duration here for simplicity, or you could pass it in the temp cookie.
		sessionDuration, err := time.ParseDuration(config.SessionTimeout)
		if err != nil {
			sessionDuration = 24 * time.Hour
		}

		session, err := createSession(r.Context(), username, sessionDuration)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to create session after 2FA: "+err.Error())
			return
		}

		// Set the final session cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    session.Token,
			Expires:  session.ExpiresAt,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})

		// Clear the temporary auth cookie.
		http.SetCookie(w, &http.Cookie{Name: "temp_auth", Value: "", Expires: time.Unix(0, 0), Path: "/"})

		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}

	// Handle GET request to display the 2FA page.
	render2FAPage(w, r, "")
}

// render2FAPage is a helper to render the 2FA login page.
func render2FAPage(w http.ResponseWriter, r *http.Request, errorMsg string) {
	tmpl, ok := templateMap["login_2fa"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load login_2fa template")
		return
	}
	pageVars := struct {
		Error      string
		CssSRIHash string
	}{Error: errorMsg, CssSRIHash: cssSRIHash}

	if err := tmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute login_2fa template: "+err.Error())
	}
}

func serveIndexPage(w http.ResponseWriter, r *http.Request) {
	subdomainCfg := getSubdomainConfig(r.Host)

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

	csrfToken := getOrSetCSRFToken(w, r)

	indexTmpl, ok := templateMap["index"]
	if !ok || indexTmpl == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load index template")
		return
	}
	// Prepare the data for the index page template.
	pageVars := IndexPageVars{
		CssSRIHash:         cssSRIHash,
		LinkLen1Display:    subdomainCfg.LinkLen1Display,
		LinkLen2Display:    subdomainCfg.LinkLen2Display,
		LinkLen3Display:    subdomainCfg.LinkLen3Display,
		CustomDisplay:      subdomainCfg.CustomDisplay,
		LinkAccessMaxNr:    subdomainCfg.LinkAccessMaxNr,
		MaxURLSize:         config.MaxURLSize,
		FileUploadsEnabled: config.FileUploadsEnabled,
		MaxTextSize:        config.MaxTextSize,
		CSRFToken:          csrfToken,
	}

	if err := indexTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute index template: "+err.Error())
		return
	}
	logOK(r, http.StatusOK)
}

// handleGET will handle GET requests for a specific link key.
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

	// verify that key only consists of valid characters
	if !validate(key) {
		logErrors(w, r, errInvalidKey, http.StatusBadRequest, "Invalid characters in key: "+key)
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

	// If the link is password protected, handle the verification flow.
	if lnk.PasswordHash.Valid {
		// This block handles both showing the password form (GET) and verifying the password (POST).
		if r.Method == http.MethodPost {
			// User is submitting the password.
			if err := r.ParseForm(); err != nil {
				logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Password prompt form parse error: "+err.Error())
				return
			}
			password := r.FormValue("password")
			// Compare the submitted password with the stored hash.
			if bcrypt.CompareHashAndPassword([]byte(lnk.PasswordHash.String), []byte(password)) != nil {
				// Password does not match. Re-render the prompt with an error.
				renderPasswordPrompt(w, r, key, "Invalid password.")
				return
			}
			// Password is correct. The request can now proceed to the normal link handling below.
		} else {
			// This is a GET request. Show the password prompt page.
			renderPasswordPrompt(w, r, key, "")
			return
		}
	}

	// --- From this point on, the user has either provided a correct password or the link was not protected. ---

	// For file links, we only increment usage on actual download, not on viewing the info page.
	// For all other link types, we increment usage now.
	if lnk.LinkType != "file" {
		err = incrementLinkUsage(r.Context(), key, r.Host)
		if err != nil {
			// This is not a fatal error for the user's redirect, so we just log it.
			slogger.Error("Failed to increment link usage", "key", key, "domain", r.Host, "error", err)
		}
		// The link data in `lnk` is still valid from the initial retrieval.
		// We just need to manually adjust the local `TimesUsed` for the template display.
		lnk.TimesUsed++
	}

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
		t, ok := templateMap["show_redirect"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not find show_redirect template")
			return
		}

		w.Header().Add("Content-Type", "text/html; charset=utf-8")
		tmplArgs := showRedirectPageVars{
			Domain:         scheme + "://" + r.Host,
			DestinationURL: string(lnk.Data),
			Timeout:        lnk.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:   lnk.TimesAllowed,
			RemainingUses:  lnk.TimesAllowed - lnk.TimesUsed,
			CssSRIHash:     cssSRIHash,
		}
		if err := t.Execute(w, tmplArgs); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute show_redirect template: "+err.Error())
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
			RemainingUses:     lnk.TimesAllowed - lnk.TimesUsed,
			CssSRIHash:        cssSRIHash,
			ShowTextJsSRIHash: showTextJsSRIHash,
		}
		if err := t.Execute(w, tmplArgs); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute showText template: "+err.Error())
		}
		logOK(r, http.StatusOK)
		return
	case "file":
		if !config.FileUploadsEnabled {
			logErrors(w, r, "File uploads are disabled on this server.", http.StatusForbidden, "Attempted to access a file link while feature is disabled")
			return
		}

		// Check if this is a direct download request.
		isDownloadRequest := r.URL.Query().Get("download") == "true"

		filePath := filepath.Join(config.BaseDir, "uploads", lnk.Key)

		if showLink {
			w.Header().Add("Content-Type", "text/plain; charset=utf-8")
			logOK(r, http.StatusOK)
			w.Write([]byte(r.Host + "/" + key + "\n\nis a file download for: " + html.EscapeString(string(lnk.Data))))
			return
		}

		if isDownloadRequest {
			// Increment usage count ONLY on actual download.
			err = incrementLinkUsage(r.Context(), key, r.Host)
			if err != nil {
				// This is a server error, as we failed to update the DB before serving the file.
				logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to increment link usage before download: "+err.Error())
				return
			}

			fileBytes, err := os.ReadFile(filePath)
			if err != nil {
				logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not retrieve file for download: "+err.Error())
				return
			}

			// Set headers to trigger a download in the browser.
			w.Header().Set("Content-Disposition", "attachment; filename=\""+string(lnk.Data)+"\"")
			// Detect and set the correct MIME type.
			mime := mimetype.Detect(fileBytes)
			w.Header().Set("Content-Type", mime.String())
			w.Write(fileBytes)
			logOK(r, http.StatusOK)
			return
		}

		// If not a direct download, show the intermediate page.
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not get file info: "+err.Error())
			return
		}

		t, ok := templateMap["show_file"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not find show_file template")
			return
		}

		w.Header().Add("Content-Type", "text/html; charset=utf-8")
		tmplArgs := showFilePageVars{
			Domain:        scheme + "://" + r.Host,
			FileName:      string(lnk.Data),
			FileSize:      formatFileSize(fileInfo.Size()),
			DownloadURL:   "/" + key + "?download=true",
			Timeout:       lnk.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:  lnk.TimesAllowed,
			RemainingUses: lnk.TimesAllowed - lnk.TimesUsed, // Usage has not been incremented yet.
			CssSRIHash:    cssSRIHash,
		}

		if err := t.Execute(w, tmplArgs); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute show_file template: "+err.Error())
		}
		logOK(r, http.StatusOK)
		return
	default:
		logErrors(w, r, errServerError, http.StatusInternalServerError, "invalid LinkType "+url.QueryEscape(lnk.LinkType))
		return
	}
}

// renderPasswordPrompt is a helper to render the password prompt page.
func renderPasswordPrompt(w http.ResponseWriter, r *http.Request, key, errorMsg string) {
	passwordTmpl, ok := templateMap["password_prompt"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load password_prompt template")
		return
	}

	pageVars := passwordPromptPageVars{
		Key:        key,
		Error:      errorMsg,
		CssSRIHash: cssSRIHash,
	}

	w.WriteHeader(http.StatusUnauthorized) // Signal that authorization is required.
	if err := passwordTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute password_prompt template: "+err.Error())
	}
}

func createAndRespond(w http.ResponseWriter, r *http.Request, link *Link, keyLength int, scheme string, fileData ...[]byte) {
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

			// If the insert was successful, we're done.
			if err == nil {
				break
			}

			// Check if the error was a collision with an *active* link.
			if errors.Is(err, errKeyCollision) {
				slogger.Debug("Key collision with active link, generating new key...", "key", link.Key, "attempt", i+1)
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
		if errors.Is(err, errKeyCollision) {
			// keyLength is 0 for custom keys, non-zero for random keys.
			if keyLength == 0 {
				logErrors(w, r, errInvalidKeyUsed, http.StatusConflict, "Custom key is already in use by an active link.")
			} else {
				logErrors(w, r, "Could not generate a unique link. Please try a longer link length.", http.StatusConflict, "Failed to create link after multiple key collision retries.")
			}
			return
		}
		// For all other errors, use the generic server error message.
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to create link in database: "+err.Error())
		return
	}

	// If this is a file upload, save the file to disk.
	if link.LinkType == "file" && len(fileData) > 0 {
		uploadDir := filepath.Join(config.BaseDir, "uploads")
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to create uploads directory: "+err.Error())
			return
		}
		filePath := filepath.Join(uploadDir, link.Key)
		if err := os.WriteFile(filePath, fileData[0], 0644); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to save uploaded file: "+err.Error())
			return
		}
	}

	fullURL := scheme + "://" + r.Host + "/" + link.Key

	// If the request is from a command-line tool like curl, respond with plain text.
	// This makes the quick-add feature much more script-friendly.
	// We check for common command-line user agents in a case-insensitive way.
	userAgent := strings.ToLower(r.UserAgent())
	if strings.Contains(userAgent, "curl") || strings.Contains(userAgent, "wget") || strings.Contains(userAgent, "powershell") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(fullURL + "\n"))
		logOK(r, http.StatusCreated)
		return
	}

	// Respond to the user with the success page.
	addHeaders(w, r)
	w.Header().Add("Content-Type", "text/html; charset=utf-8")

	switch link.LinkType {
	case "url":
		t, ok := templateMap["link_created"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not find link_created template")
			return
		}
		tmplArgs := linkCreatedPageVars{
			Domain:         scheme + "://" + r.Host,
			DestinationURL: string(link.Data), // The original long URL is the destination.
			ShortURL:       fullURL,           // The newly created short link.
			Timeout:        link.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:   link.TimesAllowed,
			RemainingUses:  link.TimesAllowed, // On creation, remaining uses equals times allowed.
			CssSRIHash:     cssSRIHash,
		}
		if err := t.Execute(w, tmplArgs); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute link_created template: "+err.Error())
		}
	case "text":
		t, ok := templateMap["text_dump_created"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not find text_dump_created template")
			return
		}
		tmplArgs := textDumpCreatedPageVars{
			Domain:        scheme + "://" + r.Host,
			ShortURL:      fullURL,
			Timeout:       link.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:  link.TimesAllowed,
			RemainingUses: link.TimesAllowed,
			CssSRIHash:    cssSRIHash,
		}
		if err := t.Execute(w, tmplArgs); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute text_dump_created template: "+err.Error())
		}
	case "file":
		t, ok := templateMap["file_created"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not find file_created template")
			return
		}
		tmplArgs := fileCreatedPageVars{
			Domain:        scheme + "://" + r.Host,
			ShortURL:      fullURL,
			Timeout:       link.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:  link.TimesAllowed,
			RemainingUses: link.TimesAllowed,
			CssSRIHash:    cssSRIHash,
		}
		if err := t.Execute(w, tmplArgs); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute file_created template: "+err.Error())
		}
	}
	logOK(r, http.StatusCreated)
}

// handleQRCodePage generates and serves a QR code for a given URL.
func handleQRCodePage(w http.ResponseWriter, r *http.Request) {
	urlToEncode := r.URL.Query().Get("url")
	if urlToEncode == "" {
		http.Error(w, "URL parameter is missing", http.StatusBadRequest)
		return
	}

	// Security check: Ensure the URL belongs to one of our configured domains.
	parsedURL, err := url.Parse(urlToEncode)
	if err != nil {
		http.Error(w, "Invalid URL format", http.StatusBadRequest)
		return
	}
	if _, ok := config.Subdomains[parsedURL.Host]; !ok {
		http.Error(w, "QR codes can only be generated for this service's domains.", http.StatusForbidden)
		return
	}

	// Generate the QR code as a PNG image. 256x256 is a good default size.
	png, err := qrcode.Encode(urlToEncode, qrcode.Medium, 256)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate QR code: "+err.Error())
		return
	}

	// Serve the PNG image.
	addHeaders(w, r)
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "max-age=3600, public") // Cache for 1 hour
	w.Write(png)
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
