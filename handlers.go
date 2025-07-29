package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func handleRoot(mux *http.ServeMux) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		addHeaders(w, r)
		if validRequest(r) {
			handleRequests(w, r)
		} else {
			http.Error(w, errServerError, http.StatusInternalServerError)
		}
	}
	mux.HandleFunc("/", handler)
}

// handleRequests will handle all web requests and direct the right action to the right linkLen
func handleRequests(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "invalid request")
		return
	}

	// browsers should send a path that begins with a /
	if r.URL.Path[0] != '/' {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "")
		return
	}

	if r.Method == http.MethodGet {
		handleGET(w, r)
		return
	}

	// Get the specific configuration for the requested host.
	subdomainCfg := getSubdomainConfig(r.Host)

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	// If the user tries to submit data via POST
	if r.Method == http.MethodPost {
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
		return
	}

	// If the request is not handled previously redirect to index, note that Host has been validated earlier
	logOK(r, http.StatusSeeOther)
	http.Redirect(w, r, scheme+"://"+r.Host, http.StatusSeeOther)
}

// basicAuth is a middleware that protects handlers with Basic Authentication.
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if admin credentials are configured. If not, disable the endpoint.
		if config.Admin.User == "" || config.Admin.PassHash == "" {
			http.NotFound(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()

		// Check if credentials were provided and if they match the configured user.
		if !ok || user != config.Admin.User {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Compare the provided password with the stored bcrypt hash.
		err := bcrypt.CompareHashAndPassword([]byte(config.Admin.PassHash), []byte(pass))
		if err != nil {
			// Password does not match.
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// If authentication is successful, call the next handler.
		next.ServeHTTP(w, r)
	}
}

// handleAdmin serves the admin dashboard page.
func handleAdmin(w http.ResponseWriter, r *http.Request) {
	addHeaders(w, r)
	adminTmpl, ok := templateMap["admin"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to load admin template")
		return
	}

	// Prepare the data for the admin page template.
	pageVars := adminPageVars{
		Subdomains: config.Subdomains,
		Defaults:   config.Defaults,
	}

	if err := adminTmpl.Execute(w, pageVars); err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Unable to execute admin template: "+err.Error())
	}
	logOK(r, http.StatusOK)
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

// handleGET will handle GET requests and redirect to the saved link for a key, return a saved textblob or return a file
func handleGET(w http.ResponseWriter, r *http.Request) {

	if !validRequest(r) {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Error: invalid request.")
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
			Domain:        scheme + "://" + r.Host,
			Data:          textContent,
			Timeout:       lnk.ExpiresAt.Format("Mon 2006-01-02 15:04 MST"),
			TimesAllowed:  lnk.TimesAllowed,
			RemainingUses: lnk.TimesAllowed - (lnk.TimesUsed + 1),
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
			if err == nil {
				break // Success
			}
		}
	} else {
		// This is a custom key, attempt to insert it once.
		err = createLinkInDB(ctx, *link)
	}

	if err != nil {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Failed to create link in database: "+err.Error())
		return
	}

	// Respond to the user with the success page.
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	t, ok := templateMap["showLink"]
	if !ok {
		logErrors(w, r, errServerError, http.StatusInternalServerError, "Could not find showLink template")
		return
	}

	fullURL := scheme + "://" + r.Host + "/" + link.Key
	tmplArgs := showLinkVars{Domain: scheme + "://" + r.Host, Data: fullURL, Timeout: link.ExpiresAt.Format("Mon 2006-01-02 15:04 MST")}
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
	jsDir := filepath.Join(config.BaseDir, "js")
	files, err := os.ReadDir(jsDir)
	if err != nil {
		slogger.Warn("JS directory not found, skipping JS handlers.", "path", jsDir)
		return
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".js") {
			f, err := os.ReadFile(filepath.Join(jsDir, file.Name()))
			if err == nil {
				mux.HandleFunc("/js/"+file.Name(), getSingleFileHandler(f, "application/javascript"))
			}
		}
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
		if validRequest(r) {
			w.Header().Add("Content-Type", mimeType)
			w.Header().Add("Cache-Control", "max-age=2592000, public")
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && tryGzip {
				w.Header().Add("content-encoding", "gzip")
				w.Write(cf)
				return
			}
			w.Write(f)
			return
		}
		http.Error(w, errServerError, http.StatusInternalServerError)
	}
	return
}

func getImgHandler(imageName string, mimeType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addHeaders(w, r)
		if validRequest(r) {
			w.Header().Add("Content-Type", mimeType)
			w.Header().Add("Cache-Control", "max-age=2592000, public")
			// Serve the image directly from the map using its simple filename key.
			if data, ok := ImageMap[imageName]; ok {
				w.Write(data)
			} else {
				// If the image isn't in the map, it wasn't loaded. Return a 404.
				http.NotFound(w, r)
			}
			return
		}
		http.Error(w, errServerError, http.StatusInternalServerError)
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
			http.Error(w, "Not Found", http.StatusNotFound)
		}
		mux.HandleFunc("/robots.txt", handler404)
		return
	}
	handleRobots := func(w http.ResponseWriter, r *http.Request) {
		addHeaders(w, r)
		if validRequest(r) {
			w.Header().Add("Content-Type", "text/plain; charset=utf-8")
			w.Header().Add("Cache-Control", "max-age=2592000, public")
			w.Write(f)
			return
		}
		http.Error(w, errServerError, http.StatusInternalServerError)
	}
	mux.HandleFunc("/robots.txt", handleRobots)
}
