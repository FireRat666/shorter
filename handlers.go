package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
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
	mux.HandleFunc("/report", handleReportPage)
	mux.HandleFunc("/register", handleRegisterPage)
	mux.HandleFunc("/login", handleLoginPage)
	mux.HandleFunc("/logout", handleLogout)
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
				// Chain the middlewares: rate limit -> csrf -> handler
				// Get the subdomain config here to pass to the rate limit middleware.
				subdomainCfg := getSubdomainConfig(r.Host)
				finalHandler := anonymousRateLimitMiddleware(subdomainCfg.AnonymousRateLimit, subdomainCfg.RateLimit1, subdomainCfg.RateLimit2, csrfProtect(handlePOST))
				finalHandler.ServeHTTP(w, r)
			} else {
				// Otherwise, it's likely a password submission for an existing link.
				handleGET(w, r)
			}
		default:
			// For any other method, return a 405 Method Not Allowed.
			logErrors(w, r, "Method not allowed", http.StatusMethodNotAllowed, "Unsupported method: "+r.Method)
		}
	}
	mux.HandleFunc("/", handler)
}

// handleLogout deletes the user's session from the database and clears the cookie.
func handleLogout(w http.ResponseWriter, r *http.Request) {
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
		keyLength = subdomainCfg.LinkLen1
	case "2":
		linkTimeout, err = time.ParseDuration(subdomainCfg.LinkLen2Timeout)
		keyLength = subdomainCfg.LinkLen2
	case "3":
		linkTimeout, err = time.ParseDuration(subdomainCfg.LinkLen3Timeout)
		keyLength = subdomainCfg.LinkLen3
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
		if !validate(customKey) {
			logErrors(w, r, errInvalidCustomKey, http.StatusBadRequest, "Invalid custom key.")
			return
		}
		if len(customKey) < 4 {
			logErrors(w, r, "Custom key is too short, minimum length is 4 characters.", http.StatusBadRequest, "Invalid custom key.")
			return
		}
		if len(customKey) > subdomainCfg.MaxKeyLen {
			logErrors(w, r, "Custom key is too long, maximum length is "+strconv.Itoa(subdomainCfg.MaxKeyLen)+" characters.", http.StatusBadRequest, "Invalid custom key.")
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

	// Check if a user is logged in and associate the link with them.
	sessionCookie, err := r.Cookie("session_token")
	if err == nil {
		session, _ := getSessionByToken(r.Context(), sessionCookie.Value)
		if session != nil {
			link.UserID.Int64 = session.UserID
			link.UserID.Valid = true
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
		if err != nil {
			// Fail open: If the check fails (e.g. DNS error), we log it but allow the submission.
			slogger.Warn("DNSBL check failed, allowing submission", "url", formURL, "error", err)
		} else if isBlocked {
			// Only block if we are certain it is on the blocklist.
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
		if err := r.ParseMultipartForm(subdomainCfg.MaxRequestSize); err != nil {
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

// sessionAuth is a middleware that protects handlers by requiring a valid session cookie.
func SessionAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			if strings.HasPrefix(r.URL.Path, "/admin") {
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}

		session, err := getSessionByToken(r.Context(), cookie.Value)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to validate session: "+err.Error())
			return
		}

		if session == nil {
			if strings.HasPrefix(r.URL.Path, "/admin") {
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}

		user, err := getUserByID(r.Context(), session.UserID)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to get user from session: "+err.Error())
			return
		}
		if user == nil {
			// This case is unlikely if the session is valid, but handle it defensively.
			logErrors(w, r, "Forbidden", http.StatusForbidden, "User not found for valid session")
			return
		}

		// Add the full user object to the request context.
		r = setUserInContext(r, user)

		// If the session is valid, call the next handler.
		next.ServeHTTP(w, r)
	}
}

// roleAuth is a middleware that protects handlers by requiring a minimum user role.
func roleAuth(requiredRole string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := getUserFromContext(r)
			if user == nil {
				// This should not happen if SessionAuth middleware is used before this.
				logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not get user from context")
				return
			}

			// Define role hierarchy
			roles := map[string]int{
				"user":         1,
				"moderator":    2,
				"domain_admin": 3,
				"super_admin":  4,
			}

			userLevel, ok := roles[user.Role]
			if !ok {
				logErrors(w, r, "Forbidden", http.StatusForbidden, "Unknown user role")
				return
			}

			requiredLevel, ok := roles[requiredRole]
			if !ok {
				logErrors(w, r, errServerError, http.StatusInternalServerError, "Unknown required role specified in handler")
				return
			}

			if userLevel < requiredLevel {
				logErrors(w, r, "Forbidden", http.StatusForbidden, "User does not have the required role")
				return
			}

			next.ServeHTTP(w, r)
		}
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
	apiRouter.HandleFunc("/links", apiAuth(handleAPILinks))

	// This handler will strip the "/api/v1" prefix before passing to the apiRouter.
	apiHandler := http.StripPrefix("/api/v1", apiRouter)
	mux.Handle("/api/v1/", apiHandler)
}

// handleAPILinks is a routing function that dispatches API requests for the /links
// endpoint to the correct handler based on the HTTP method.
func handleAPILinks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleAPIGetLink(w, r)
	case http.MethodPost:
		handleAPICreateLink(w, r)
	case http.MethodDelete:
		handleAPIDeleteLink(w, r)
	case http.MethodPatch:
		handleAPIUpdateLink(w, r)
	default:
		respondWithError(w, http.StatusMethodNotAllowed, fmt.Sprintf("Method %s is not allowed for this endpoint", r.Method))
	}
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

		// Enforce API rate limiting based on the token.
		if config.APIRateLimit.Enabled {
			limiter := getClientByToken(apiKey.Token)
			if !limiter.Allow() {
				// Use a standard 429 response without a JSON body for simplicity.
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}

		user, err := getUserByID(r.Context(), apiKey.UserID)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to retrieve user for API key.")
			return
		}
		if user == nil {
			respondWithError(w, http.StatusUnauthorized, "User for API key not found.")
			return
		}

		// Add the full user object to the request context.
		r = setUserInContext(r, user)
		next.ServeHTTP(w, r)
	}
}

// handleAPIGetLink handles requests to retrieve a link's details via the API.
func handleAPIGetLink(w http.ResponseWriter, r *http.Request) {
	// Read parameters from the URL query string instead of a JSON body.
	key := r.URL.Query().Get("key")
	domain := r.URL.Query().Get("domain")

	if key == "" {
		respondWithError(w, http.StatusBadRequest, "The 'key' query parameter is required")
		return
	}

	if domain == "" {
		domain = config.PrimaryDomain
	}

	user := getUserFromContext(r)
	if user == nil {
		// This should not happen if apiAuth middleware is working correctly.
		respondWithError(w, http.StatusInternalServerError, "Could not identify user from request context.")
		return
	}

	// Get the full details of the link.
	link, err := getLinkDetails(r.Context(), key, domain)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve link.")
		return
	}
	if link == nil {
		respondWithError(w, http.StatusNotFound, "Link not found.")
		return
	}

	// Ownership check: The API key in the request must match the creator of the link.
	if !link.UserID.Valid || link.UserID.Int64 != user.ID {
		respondWithError(w, http.StatusForbidden, "This API key does not have permission to view this link.")
		return
	}

	// For "text" links, decompress data if necessary.
	var data string
	if link.LinkType == "text" && link.IsCompressed {
		decompressed, err := decompress(link.Data)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to decompress link data.")
			return
		}
		data = decompressed
	} else {
		data = string(link.Data)
	}

	// Respond with the link details.
	response := apiGetLinkResponse{
		Key:          link.Key,
		Domain:       link.Domain,
		LinkType:     link.LinkType,
		Data:         data,
		HasPassword:  link.PasswordHash.Valid,
		TimesAllowed: link.TimesAllowed,
		TimesUsed:    link.TimesUsed,
		ExpiresAt:    link.ExpiresAt,
		CreatedAt:    link.CreatedAt,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// handleAPICreateLink handles requests to create a new link via the API.
func handleAPICreateLink(w http.ResponseWriter, r *http.Request) {
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
	user := getUserFromContext(r)
	if user == nil {
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
	link.UserID.Int64 = user.ID
	link.UserID.Valid = true

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

	var keyLength int
	// Create the link in the database.
	if link.Key == "" {
		// No custom key provided, generate a random one.
		// Use a sensible default length for API-generated keys.
		keyLength = config.LinkLen2
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
		keyLength = 0
		err = createLinkInDB(r.Context(), *link)
	}

	if err != nil {
		if errors.Is(err, errKeyCollision) {
			// keyLength is 0 for custom keys, non-zero for random keys.
			if keyLength == 0 {
				respondWithError(w, http.StatusConflict, "The requested custom_key is already in use by an active link.")
			} else {
				respondWithError(w, http.StatusConflict, "Could not generate a unique link. Please try again.")
			}
			return
		}
		// For all other errors, use the generic server error message.
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to create link in database: "+err.Error())
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

// handleAPIDeleteLink handles requests to delete a link via the API.
func handleAPIDeleteLink(w http.ResponseWriter, r *http.Request) {
	var req apiDeleteLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	if req.Key == "" {
		respondWithError(w, http.StatusBadRequest, "The 'key' field is.Required")
		return
	}

	domain := req.Domain
	if domain == "" {
		domain = config.PrimaryDomain
	}

	user := getUserFromContext(r)
	if user == nil {
		// This should not happen if apiAuth middleware is working correctly.
		respondWithError(w, http.StatusInternalServerError, "Could not identify user from request context.")
		return
	}

	// Check if the link exists before trying to delete it. This allows us to
	// also delete any associated uploaded files.
	link, err := getLinkDetails(r.Context(), req.Key, domain)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to check for link existence.")
		return
	}
	if link == nil {
		// The link doesn't exist. Since DELETE is idempotent, this is a success.
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Ownership check: The API key in the request must match the creator of the link.
	if !link.UserID.Valid || link.UserID.Int64 != user.ID {
		respondWithError(w, http.StatusForbidden, "This API key does not have permission to delete this link.")
		return
	}

	// If it's a file link, delete the associated file from disk.
	if link.LinkType == "file" {
		deleteUploadedFile(link.Key)
	}

	// Delete the link from the database.
	if err := deleteLink(r.Context(), req.Key, domain); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to delete link.")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleAPIUpdateLink handles requests to update a link via the API.
func handleAPIUpdateLink(w http.ResponseWriter, r *http.Request) {
	var req apiUpdateLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	if req.Key == "" {
		respondWithError(w, http.StatusBadRequest, "The 'key' field is required")
		return
	}

	domain := req.Domain
	if domain == "" {
		domain = config.PrimaryDomain
	}

	user := getUserFromContext(r)
	if user == nil {
		respondWithError(w, http.StatusInternalServerError, "Could not identify user from request context.")
		return
	}

	// Get the full details of the link to be updated.
	link, err := getLinkDetails(r.Context(), req.Key, domain)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve link for update.")
		return
	}
	if link == nil {
		respondWithError(w, http.StatusNotFound, "Link not found.")
		return
	}

	// Ownership check: The API key in the request must match the creator of the link.
	if !link.UserID.Valid || link.UserID.Int64 != user.ID {
		respondWithError(w, http.StatusForbidden, "This API key does not have permission to update this link.")
		return
	}

	// Apply updates from the request.
	if req.ExpiresIn != "" {
		duration, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid 'expires_in' format. Use Go duration format (e.g., '1h', '30m').")
			return
		}
		link.ExpiresAt = time.Now().Add(duration)
	}

	if req.MaxUses != nil { // Check if the field was provided
		if *req.MaxUses < 0 {
			respondWithError(w, http.StatusBadRequest, "Invalid 'max_uses' value, must be non-negative.")
			return
		}
		link.TimesAllowed = *req.MaxUses
	}

	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to hash password.")
			return
		}
		link.PasswordHash.String = string(hashedPassword)
		link.PasswordHash.Valid = true
	}

	// Persist the changes to the database using the existing update function.
	if err := updateLink(r.Context(), *link); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to update link.")
		return
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	// Respond with the updated link details.
	response := apiCreateLinkResponse{
		ShortURL:  fmt.Sprintf("%s://%s/%s", scheme, link.Domain, link.Key),
		ExpiresAt: link.ExpiresAt,
	}

	respondWithJSON(w, http.StatusOK, response)
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

// handleRegisterPage handles user registration for a specific domain.
func handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	addHeaders(w, r)
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		// If no domain is specified in the query, fall back to the host header.
		// This maintains compatibility with old links or bookmarks.
		domain = r.Host
	}

	// Check if the domain is valid and if registration is enabled.
	subdomainCfg := getSubdomainConfig(domain)
	if _, ok := config.Subdomains[domain]; !ok {
		logErrors(w, r, "Domain not found.", http.StatusNotFound, "Registration attempted for non-existent domain: "+domain)
		return
	}

	if subdomainCfg.RegistrationEnabled == nil || !*subdomainCfg.RegistrationEnabled {
		logErrors(w, r, "User registration is not enabled for this domain.", http.StatusForbidden, "Registration attempted on domain with disabled registration: "+domain)
		return
	}

	switch r.Method {
	case http.MethodGet:
		registerTmpl, ok := templateMap["register"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load register template")
			return
		}

		captchaActive := false
		if subdomainCfg.EnableForRegistration != nil {
			captchaActive = *subdomainCfg.EnableForRegistration
		}
		captchaActive = captchaActive && config.HCaptcha.SiteKey != ""

		type registerPageVars struct {
			CssSRIHash      string
			Error           string
			CSRFToken       string
			Domain          string
			CaptchaActive   bool
			HCaptchaSiteKey string
		}

		pageVars := registerPageVars{
			CssSRIHash:      cssSRIHash,
			Domain:          domain,
			CSRFToken:       getOrSetCSRFToken(w, r),
			Error:           r.URL.Query().Get("error"),
			CaptchaActive:   captchaActive,
			HCaptchaSiteKey: config.HCaptcha.SiteKey,
		}

		if err := registerTmpl.Execute(w, pageVars); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute register template: "+err.Error())
		}
		logOK(r, http.StatusOK)

	case http.MethodPost:
		// Wrap the POST logic in the CSRF protection middleware.
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Registration form parse error: "+err.Error())
				return
			}

			enableForRegistration := false
			if subdomainCfg.EnableForRegistration != nil {
				enableForRegistration = *subdomainCfg.EnableForRegistration
			}

			if enableForRegistration {
				hCaptchaResponse := r.FormValue("h-captcha-response")
				if !verifyCaptcha(hCaptchaResponse, r.RemoteAddr) {
					http.Redirect(w, r, fmt.Sprintf("/register?domain=%s&error=CAPTCHA verification failed. Please try again.", url.QueryEscape(domain)), http.StatusSeeOther)
					return
				}
			}

			username := r.FormValue("username")
			password := r.FormValue("password")
			confirmPassword := r.FormValue("confirm_password")

			// Validation
			if username == "" || password == "" {
				http.Redirect(w, r, fmt.Sprintf("/register?domain=%s&error=Username and password are required.", url.QueryEscape(domain)), http.StatusSeeOther)
				return
			}

			if strings.EqualFold(username, "admin") {
				http.Redirect(w, r, fmt.Sprintf("/register?domain=%s&error=That username is reserved.", url.QueryEscape(domain)), http.StatusSeeOther)
				return
			}

			if password != confirmPassword {
				http.Redirect(w, r, fmt.Sprintf("/register?domain=%s&error=Passwords do not match.", url.QueryEscape(domain)), http.StatusSeeOther)
				return
			}

			// Hash password
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to hash password during registration: "+err.Error())
				return
			}

			// Create user
			newUser := &User{
				Username: username,
				Password: string(hashedPassword),
				Role:     "user", // Default role for new registrations
				Domain:   domain,
			}

			// Use createUserInDomain to ensure the user is created within the correct domain context.
			if err := createUserInDomain(r.Context(), newUser); err != nil {
				if strings.Contains(err.Error(), "violates unique constraint") {
					http.Redirect(w, r, fmt.Sprintf("/register?domain=%s&error=Username already exists.", url.QueryEscape(domain)), http.StatusSeeOther)
				} else {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to create user: "+err.Error())
				}
				return
			}

			// Redirect to login page on success
			http.Redirect(w, r, "/login?domain="+url.QueryEscape(domain), http.StatusSeeOther)
		})
		csrfProtect(handler)(w, r)

	default:
		addHeaders(w, r)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLoginPage serves the login page for GET requests and handles login form submissions for POST requests.
func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		handleLogin(w, r)
		return
	}

	// If the user is already logged in, redirect them to the admin dashboard.
	cookie, err := r.Cookie("session_token")
	if err == nil {
		session, _ := getSessionByToken(r.Context(), cookie.Value)
		if session != nil {
			user, err := getUserByID(r.Context(), session.UserID)
			if err == nil && user != nil {
				if user.Role == "super_admin" {
					http.Redirect(w, r, "/admin/", http.StatusSeeOther)
				} else {
					http.Redirect(w, r, "/user/security", http.StatusSeeOther)
				}
				return
			}
		}
	}

	csrfToken := getOrSetCSRFToken(w, r)

	// Handle GET request to display the login page.
	addHeaders(w, r)
	loginTmpl, ok := templateMap["login"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load login template")
		return
	}

	subdomainCfg := getSubdomainConfig(r.Host)
	captchaActive := false
	if subdomainCfg.EnableForLogin != nil {
		captchaActive = *subdomainCfg.EnableForLogin
	}
	captchaActive = captchaActive && config.HCaptcha.SiteKey != ""

	pageVars := loginPageVars{
		CssSRIHash:      cssSRIHash,
		Error:           r.URL.Query().Get("error"),
		CSRFToken:       csrfToken,
		CaptchaActive:   captchaActive,
		HCaptchaSiteKey: config.HCaptcha.SiteKey,
	}

	if err := loginTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute login template: "+err.Error())
	}
	logOK(r, http.StatusOK)
}

// handleLogin handles the user login form submission.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Login form parse error: "+err.Error())
		return
	}

	subdomainCfg := getSubdomainConfig(r.Host)
	enableForLogin := false
	if subdomainCfg.EnableForLogin != nil {
		enableForLogin = *subdomainCfg.EnableForLogin
	}

	if enableForLogin {
		hCaptchaResponse := r.FormValue("h-captcha-response")
		if !verifyCaptcha(hCaptchaResponse, r.RemoteAddr) {
			http.Redirect(w, r, "/login?error=CAPTCHA+verification+failed.+Please+try+again.", http.StatusSeeOther)
			return
		}
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := getUserByUsername(r.Context(), username)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to get user: "+err.Error())
		return
	}

	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		http.Redirect(w, r, "/login?error=Invalid+username+or+password", http.StatusSeeOther)
		return
	}

	if user.TOTPEnabled {
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

	// Determine session duration based on "Remember Me" checkbox.
	rememberMe := r.FormValue("remember_me") == "true"
	var sessionDuration time.Duration

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

	session, err := createSession(r.Context(), user.ID, sessionDuration)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to create session: "+err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    session.Token,
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	if user.Role == "super_admin" {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/user/security", http.StatusSeeOther)
	}
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

	user, err := getUserByUsername(r.Context(), username)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to get user: "+err.Error())
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "2FA form parse error: "+err.Error())
			return
		}

		code := r.FormValue("totp_code")
		if !user.TOTPSecret.Valid || !totp.Validate(code, user.TOTPSecret.String) {
			// Invalid code. Re-render the page with an error.
			slogger.Warn("Failed 2FA attempt", "user", username)
			render2FAPage(w, r, "Invalid verification code.")
			return
		}

		// 2FA successful. Now we can create the full, persistent session.
		slogger.Info("User successfully passed 2FA", "user", username)

		// Determine session duration based on "Remember Me" checkbox from the *original* login form.
		// We'll assume a default duration here for simplicity, or you could pass it in the temp cookie.
		sessionDuration, err := time.ParseDuration(config.SessionTimeout)
		if err != nil {
			sessionDuration = 24 * time.Hour
		}

		session, err := createSession(r.Context(), user.ID, sessionDuration)
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

		if user.Role == "super_admin" {
			http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/user/security", http.StatusSeeOther)
		}
		return
	}

	// Handle GET request to display the 2FA page.
	render2FAPage(w, r, "")
}

// render2FAPage is a helper to render the 2FA login page.
func render2FAPage(w http.ResponseWriter, r *http.Request, errorMsg string) {
	addHeaders(w, r)
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
	// Check for quick add feature: a GET request to the root with a query string.
	if r.URL.RawQuery != "" {
		// Get the subdomain config here to pass to the quickAddHandler and rate limit middleware.
		subdomainCfg := getSubdomainConfig(r.Host)

		// This is a Quick Add request. We must apply the anonymous rate limiter.
		quickAddHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var formURL string
			var keyLength int
			var linkTimeout time.Duration
			var err error

			// Check for the new query param format vs the old raw query format.
			queryParams, parseErr := url.ParseQuery(r.URL.RawQuery)
			// We check parseErr != nil OR url param is empty to catch cases like `/?&len=2`
			if parseErr != nil || queryParams.Get("url") == "" {
				// Fallback to old behavior: raw query is the URL, use default length.
				formURL = r.URL.RawQuery
				keyLength = subdomainCfg.LinkLen1
				linkTimeout, err = time.ParseDuration(subdomainCfg.LinkLen1Timeout)
				if err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Error parsing default link timeout duration: "+err.Error())
					return
				}
			} else {
				// New behavior: use query parameters.
				formURL = queryParams.Get("url")
				lenOpt := queryParams.Get("len")
				if lenOpt == "" {
					lenOpt = "1" // Default to shortest
				}

				switch lenOpt {
				case "1":
					keyLength = subdomainCfg.LinkLen1
					linkTimeout, err = time.ParseDuration(subdomainCfg.LinkLen1Timeout)
				case "2":
					keyLength = subdomainCfg.LinkLen2
					linkTimeout, err = time.ParseDuration(subdomainCfg.LinkLen2Timeout)
				case "3":
					keyLength = subdomainCfg.LinkLen3
					linkTimeout, err = time.ParseDuration(subdomainCfg.LinkLen3Timeout)
				case "c", "custom":
					// Use LinkLen3 plus a random few characters, with the custom timeout.
					// This ensures it's always longer and has more possibilities.
					// Add a random number between 1 and 3 to the base length.
					n, randErr := rand.Int(rand.Reader, big.NewInt(3)) // n will be in [0, 3)
					if randErr != nil {
						logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate random addition for key length: "+randErr.Error())
						return
					}
					keyLength = subdomainCfg.LinkLen3 + int(n.Int64()) + 1 // +1 to make it [1, 3]
					linkTimeout, err = time.ParseDuration(subdomainCfg.CustomTimeout)
				default:
					logErrors(w, r, "Invalid 'len' parameter. Must be 1, 2, 3, or 'c'.", http.StatusBadRequest, "Invalid quick-add len parameter: "+lenOpt)
					return
				}

				if err != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Error parsing link timeout duration for quick-add: "+err.Error())
					return
				}
			}

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

			createAndRespond(w, r, link, keyLength, scheme)
		})

		// Apply the middleware to our handler.
		anonymousRateLimitMiddleware(subdomainCfg.AnonymousRateLimit, subdomainCfg.RateLimit1, subdomainCfg.RateLimit2, quickAddHandler).ServeHTTP(w, r)
		return
	}

	// If there's no query string, just serve the main page.
	subdomainCfg := getSubdomainConfig(r.Host)
	csrfToken := getOrSetCSRFToken(w, r)

	// Generate nonce for CSP
	nonce, err := generateCSPNonce()
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate security token")
		return
	}

	// Set dynamic CSP with nonce and strict-dynamic
	// We need to allow unsafe-inline for styles (as per hCaptcha reqs) and strict-dynamic for scripts
	// strict-dynamic allows the loader (with nonce) to load other scripts (like hCaptcha's internal scripts)
	csp := fmt.Sprintf(
		"default-src 'none'; script-src 'self' 'nonce-%s' 'strict-dynamic' https: http: 'unsafe-inline'; frame-src 'self' https://hcaptcha.com https://*.hcaptcha.com; style-src 'self' 'unsafe-inline' https://*.hcaptcha.com; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com; report-uri /csp-report;",
		nonce,
	)
	w.Header().Set("Content-Security-Policy", csp)

	indexTmpl, ok := templateMap["index"]
	if !ok || indexTmpl == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load index template")
		return
	}
	// Prepare the data for the index page template.
	pageVars := IndexPageVars{
		IndexJsSRIHash:     indexJsSRIHash,
		CssSRIHash:         cssSRIHash,
		LinkLen1Display:    fmt.Sprintf("%s (%d chars)", subdomainCfg.LinkLen1Display, subdomainCfg.LinkLen1),
		LinkLen2Display:    fmt.Sprintf("%s (%d chars)", subdomainCfg.LinkLen2Display, subdomainCfg.LinkLen2),
		LinkLen3Display:    fmt.Sprintf("%s (%d chars)", subdomainCfg.LinkLen3Display, subdomainCfg.LinkLen3),
		CustomDisplay:      fmt.Sprintf("%s (up to %d chars)", subdomainCfg.CustomDisplay, subdomainCfg.MaxKeyLen),
		LinkAccessMaxNr:    subdomainCfg.LinkAccessMaxNr,
		MaxURLSize:         config.MaxURLSize,
		FileUploadsEnabled: config.FileUploadsEnabled,
		MaxTextSize:        config.MaxTextSize,
		MaxFileSize:        formatFileSize(subdomainCfg.MaxRequestSize),
		CSRFToken:          csrfToken,
		Nonce:              nonce,
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

	// Add a specific check for common probing patterns, like requests for hidden files.
	// This handles requests for paths like "/.env", "/.git/config", etc.
	if strings.HasPrefix(key, ".") {
		logErrors(w, r, "Not Found", http.StatusNotFound, "Blocked common probe for hidden file: "+key)
		return
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

			// Verify CSRF token for the password submission.
			submittedToken := r.FormValue("csrf_token")
			expectedToken := getOrSetCSRFToken(w, r)
			if submittedToken != expectedToken {
				logErrors(w, r, "Forbidden", http.StatusForbidden, "CSRF token mismatch on password prompt")
				return
			}

			password := r.FormValue("password")
			// Compare the submitted password with the stored hash.
			if bcrypt.CompareHashAndPassword([]byte(lnk.PasswordHash.String), []byte(password)) != nil {
				// Password does not match. Re-render the prompt with an error.
				renderPasswordPrompt(w, r, key, "Invalid password.")
				return
			}
			// Password is correct. Create a temporary auth cookie to avoid re-prompting.
			createLinkAuthCookie(w, r, key)
			// The request can now proceed to the normal link handling below.
		} else {
			// This is a GET request. Before showing the prompt, check if they have a valid auth cookie.
			if hasValidLinkAuthCookie(r, key) {
				// Cookie is valid, proceed directly to content.
			} else {
				// No valid cookie, show the password prompt page.
				renderPasswordPrompt(w, r, key, "")
				return
			}
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
			Key:            key,
			DestinationURL: string(lnk.Data),
			Timeout:        lnk.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:   lnk.TimesAllowed,
			RemainingUses:  lnk.TimesAllowed - lnk.TimesUsed,
			AbuseReporting: config.AbuseReporting,
			CssSRIHash:     cssSRIHash,
			OGTitle:        fmt.Sprintf("Link via %s", r.Host),
			OGDescription:  string(lnk.Data),
			OGImage:        scheme + "://" + r.Host + "/logo.png",
			OGUrl:          scheme + "://" + r.Host + "/" + key,
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
			Key:               key,
			Data:              textContent,
			Timeout:           lnk.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:      lnk.TimesAllowed,
			RemainingUses:     lnk.TimesAllowed - lnk.TimesUsed,
			AbuseReporting:    config.AbuseReporting,
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
			Domain:         scheme + "://" + r.Host,
			Key:            key,
			FileName:       string(lnk.Data),
			FileSize:       formatFileSize(fileInfo.Size()),
			DownloadURL:    "/" + key + "?download=true",
			Timeout:        lnk.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:   lnk.TimesAllowed,
			RemainingUses:  lnk.TimesAllowed - lnk.TimesUsed, // Usage has not been incremented yet.
			AbuseReporting: config.AbuseReporting,
			CssSRIHash:     cssSRIHash,
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
		CSRFToken:  getOrSetCSRFToken(w, r),
		CssSRIHash: cssSRIHash,
	}

	w.WriteHeader(http.StatusUnauthorized) // Signal that authorization is required.
	if err := passwordTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute password_prompt template: "+err.Error())
	}
}

// createLinkAuthCookie creates a temporary, signed cookie to remember that the user
// has successfully authenticated for a specific link.
func createLinkAuthCookie(w http.ResponseWriter, r *http.Request, linkKey string) {
	// The message is the link key. The signature proves it's from us.
	signature := generateHMAC([]byte(linkKey))
	cookieValue := fmt.Sprintf("%s|%s", linkKey, base64.StdEncoding.EncodeToString(signature))

	http.SetCookie(w, &http.Cookie{
		Name:     "link_auth_" + linkKey, // Unique name per link
		Value:    cookieValue,
		Expires:  time.Now().Add(5 * time.Minute), // Short-lived
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Path:     "/" + linkKey,
	})
}

func createAndRespond(w http.ResponseWriter, r *http.Request, link *Link, keyLength int, scheme string, fileData ...[]byte) {
	ctx := r.Context()
	var err error
	var keyExtended bool

	// If the key is empty (not a custom key), generate a random one.
	if link.Key == "" {
		// Generate the initial random key.
		link.Key, err = generateRandomKey(keyLength)
		if err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate initial random key: "+err.Error())
			return
		}

		// Retry a few times on collision, extending the key each time.
		for i := 0; i < 5; i++ { // Limit to 5 attempts to prevent infinite loops.
			err = createLinkInDB(ctx, *link)

			// If the insert was successful, we're done.
			if err == nil {
				break
			}

			// Check if the error was a collision with an *active* link.
			if errors.Is(err, errKeyCollision) {
				keyExtended = true
				slogger.Debug("Key collision with active link, appending character and retrying...", "key", link.Key, "attempt", i+1)
				// Append one more random character and try again.
				extraChar, randErr := generateRandomKey(1)
				if randErr != nil {
					logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate extra random character for key: "+randErr.Error())
					return
				}
				link.Key += extraChar
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
				logErrors(w, r, "Could not generate a unique link. Please try again.", http.StatusConflict, "Failed to create link after multiple key collision retries.")
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
			QRCodeURL:      "/qr?url=" + url.QueryEscape(fullURL),
			Timeout:        link.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:   link.TimesAllowed,
			RemainingUses:  link.TimesAllowed, // On creation, remaining uses equals times allowed.
			KeyExtended:    keyExtended,
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
			KeyExtended:   keyExtended,
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
			KeyExtended:   keyExtended,
			CssSRIHash:    cssSRIHash,
		}
		if err := t.Execute(w, tmplArgs); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute file_created template: "+err.Error())
		}
	}
	logOK(r, http.StatusCreated)
}

// handleReportPage handles displaying the abuse report form and processing submissions.
func handleReportPage(w http.ResponseWriter, r *http.Request) {
	addHeaders(w, r)
	if !config.AbuseReporting.Enabled {
		http.NotFound(w, r)
		return
	}

	key := r.URL.Query().Get("key")
	if key == "" {
		logErrors(w, r, "No link specified for reporting.", http.StatusBadRequest, "Report page accessed without key")
		return
	}

	// We don't need the full link details, just to confirm it exists.
	link, err := getLinkFromDB(r.Context(), key, r.Host)
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Error checking link for report: "+err.Error())
		return
	}
	if link == nil {
		logErrors(w, r, "The specified link does not exist or has expired.", http.StatusNotFound, "Report submitted for non-existent link: "+key)
		return
	}

	if r.Method == http.MethodPost {
		// Process the form submission.
		if err := r.ParseForm(); err != nil {
			logErrors(w, r, "Failed to parse form.", http.StatusBadRequest, "Report form parse error: "+err.Error())
			return
		}

		// Verify CSRF token.
		submittedToken := r.FormValue("csrf_token")
		expectedToken := getOrSetCSRFToken(w, r)
		if submittedToken != expectedToken {
			logErrors(w, r, "Forbidden", http.StatusForbidden, "CSRF token mismatch on report form")
			return
		}

		subdomainCfg := getSubdomainConfig(r.Host)
		captchaEnabled := false
		if subdomainCfg.AbuseReportingCaptchaEnabled != nil {
			captchaEnabled = *subdomainCfg.AbuseReportingCaptchaEnabled
		}

		// Verify the hCaptcha response if enabled for abuse reports.
		if captchaEnabled {
			hCaptchaResponse := r.FormValue("h-captcha-response")
			if !verifyCaptcha(hCaptchaResponse, r.RemoteAddr) {
				renderReportPage(w, r, key, "CAPTCHA verification failed. Please try again.")
				return
			}
		}

		// Save the verified report to the database.
		err := saveAbuseReport(r.Context(), key, r.Host, r.FormValue("email"), r.FormValue("comments"))
		if err != nil {
			// This is a server-side error.
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to save abuse report: "+err.Error())
			return
		}
		slogger.Info("Abuse report successfully saved to database", "key", key, "domain", r.Host)

		// Show a success page.
		successTmpl, ok := templateMap["report_success"]
		if !ok {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load report_success template")
			return
		}
		pageVars := struct{ CssSRIHash string }{CssSRIHash: cssSRIHash}
		if err := successTmpl.Execute(w, pageVars); err != nil {
			logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute report_success template: "+err.Error())
		}
		return
	}

	// Handle GET request to display the form.
	renderReportPage(w, r, key, "")
}

// renderReportPage is a helper to render the abuse report form.
func renderReportPage(w http.ResponseWriter, r *http.Request, key, errorMsg string) {
	nonce, err := generateCSPNonce()
	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to generate security token")
		return
	}

	// Define the Content Security Policy, including the nonce for scripts.
	// We also need to allow unsafe-inline for styles as per hCaptcha requirements (handled in global config,
	// but we override here to ensure nonce is present for scripts).
	// Note: We inherit the style-src 'unsafe-inline' from the global config if we were just appending,
	// but here we are replacing the CSP header for this specific response.
	// So we must include all necessary directives.
	// We add 'strict-dynamic' to allow hCaptcha's api.js to load its dependencies.
	csp := fmt.Sprintf(
		"default-src 'none'; script-src 'self' 'nonce-%s' 'strict-dynamic' https: http: 'unsafe-inline'; frame-src 'self' https://hcaptcha.com https://*.hcaptcha.com; style-src 'self' 'unsafe-inline' https://*.hcaptcha.com; img-src 'self'; form-action 'self'; frame-ancestors 'none'; connect-src 'self'; report-uri /csp-report;",
		nonce,
	)
	w.Header().Set("Content-Security-Policy", csp)

	addHeaders(w, r)
	reportTmpl, ok := templateMap["report"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load report template")
		return
	}

	// Captcha is only active if the feature is enabled AND a site key is provided.
	captchaActive := config.AbuseReporting.CaptchaEnabled && config.HCaptcha.SiteKey != ""

	pageVars := struct {
		ReportedURL     string
		Key             string
		Error           string
		HCaptchaSiteKey string
		CSRFToken       string
		CaptchaActive   bool
		CssSRIHash      string
		Nonce           string
	}{
		ReportedURL:     r.Host + "/" + key,
		Key:             key,
		Error:           errorMsg,
		HCaptchaSiteKey: config.HCaptcha.SiteKey,
		CSRFToken:       getOrSetCSRFToken(w, r),
		CaptchaActive:   captchaActive,
		CssSRIHash:      cssSRIHash,
		Nonce:           nonce,
	}

	if err := reportTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to execute report template: "+err.Error())
	}
}

// verifyCaptcha sends a request to the hCaptcha API to verify a user's response.
func verifyCaptcha(response, remoteIP string) bool {
	if config.HCaptcha.SecretKey == "" {
		slogger.Info("hCaptcha secret key is not configured. CAPTCHA verification is disabled, allowing submission.")
		return true
	}

	// The remoteIP from the request includes the port. We need to split it.
	ip, _, err := net.SplitHostPort(remoteIP)
	if err != nil {
		// If we can't split it, it might be just an IP. Use it as is.
		ip = remoteIP
	}

	data := url.Values{}
	data.Set("secret", config.HCaptcha.SecretKey)
	data.Set("response", response)
	data.Set("remoteip", ip)

	resp, err := http.PostForm("https://api.hcaptcha.com/siteverify", data)
	if err != nil {
		slogger.Error("Failed to send hCaptcha verification request", "error", err)
		return false
	}
	defer resp.Body.Close()

	var result hCaptchaVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		slogger.Error("Failed to decode hCaptcha response", "error", err)
		return false
	}

	return result.Success
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
