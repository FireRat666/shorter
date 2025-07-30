package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/kr/pretty"
	yaml "gopkg.in/yaml.v2"
)

var config Config
var slogger *slog.Logger

func main() {
	var conf []byte
	var err error

	// --- Configuration Loading ---
	// This logic establishes a clear priority for loading configuration:
	// 1. A local, gitignored 'shorterdata/Config' file for development secrets.
	// 2. A public, checked-in 'shorterdata/config.yaml' file for default settings.

	localConfigPath := filepath.Join("shorterdata", "Config")
	defaultConfigPath := filepath.Join("shorterdata", "config.yaml")

	// Try to load the local override first.
	conf, err = os.ReadFile(localConfigPath)
	if err != nil {
		// If local override fails, log it and fall back to the default public config.
		log.Printf("Local config override not found at '%s'. Falling back to default config.", localConfigPath)
		conf, err = os.ReadFile(defaultConfigPath)
		if err != nil {
			log.Fatalf("Failed to read both local config (%s) and default config (%s): %v", localConfigPath, defaultConfigPath, err)
		}
		log.Printf("Successfully loaded default config from '%s'", defaultConfigPath)
	} else {
		log.Printf("Successfully loaded local config override from '%s'", localConfigPath)
	}

	// Populate the global config variable with the data from the config file
	if err = yaml.UnmarshalStrict(conf, &config); err != nil {
		log.Fatalln("Unable to parse config file:\n", err)
	}

	// --- START: Render Compatibility ---
	// On Render, the port is specified by the PORT environment variable.
	if renderPort := os.Getenv("PORT"); renderPort != "" {
		config.AddressPort = "0.0.0.0:" + renderPort
	}

	// On Render, the database URL is provided as an environment variable for security.
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		config.DatabaseURL = dbURL
	}

	// On Render, the log separator can be provided as an environment variable for security.
	if logSep := os.Getenv("LOG_SEP"); logSep != "" {
		config.LogSep = logSep
	}

	// On Render, domain names can be provided as a comma-separated environment variable.
	if domainsStr := os.Getenv("SHORTER_DOMAINS"); domainsStr != "" {
		domains := strings.Split(domainsStr, ",")
		// Trim whitespace from each domain to handle "domain1, domain2" correctly.
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}
		config.DomainNames = domains
	}

	// On Render, admin credentials should be provided as environment variables.
	if adminUser := os.Getenv("ADMIN_USER"); adminUser != "" {
		config.Admin.User = adminUser
	}
	if adminPassHash := os.Getenv("ADMIN_PASS_HASH"); adminPassHash != "" {
		config.Admin.PassHash = adminPassHash
	}

	// On Render, the primary domain can be set via an environment variable.
	if primaryDomain := os.Getenv("SHORTER_PRIMARY_DOMAIN"); primaryDomain != "" {
		config.PrimaryDomain = primaryDomain
	}

	// --- END: Render Compatibility ---

	// --- START: Finalize Configuration ---
	// If PrimaryDomain is not set via config or environment, fall back to the first domain in DomainNames.
	// This ensures there is always a primary domain if any domains are configured.
	if config.PrimaryDomain == "" && len(config.DomainNames) > 0 {
		config.PrimaryDomain = config.DomainNames[0]
		// We can't log here yet as the logger is not initialized, but this is a safe fallback.
	}
	// --- END: Finalize Configuration ---

	// If BaseDir is not specified in the config, automatically find the 'shorterdata' directory.
	if config.BaseDir == "" {
		dataPath, err := findDataDir("shorterdata")
		if err != nil {
			log.Fatalf("Unable to locate 'shorterdata' directory: %v. Please specify BaseDir in the config file or place 'shorterdata' next to the executable.", err)
		}
		config.BaseDir = dataPath
	}

	if config.Logging {
		var logWriter *os.File
		if config.Logfile != "" {
			logWriter, err = os.OpenFile(config.Logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		} else {
			logWriter, err = os.OpenFile(filepath.Join(config.BaseDir, "shorter.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		}
		if err != nil {
			log.Println("Failed to open log file, logging disabled:", err)
		} else {
			// Use a more readable JSON handler for structured logs.
			handler := slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
				Level: slog.LevelDebug, // Changed to Debug to see all check messages
			})
			slogger = slog.New(handler)
			slogger.Info("Logger initialized")

			// Create a redacted config for logging to avoid leaking secrets.
			loggedConfig := config
			if loggedConfig.DatabaseURL != "" {
				loggedConfig.DatabaseURL = "[REDACTED]"
			}
			loggedConfig.LogSep = "[REDACTED]"
			slogger.Info("Loaded config", "config", fmt.Sprintf("%# v", pretty.Formatter(loggedConfig)))
		}
	}

	// Connect to the database and create schema if it doesn't exist.
	err = setupDB(config.DatabaseURL)
	if err != nil {
		log.Fatalln("Database setup failed:", err)
	}

	// Load subdomains from the database, which will be merged with and override
	// any settings with the same domain name from the config file.
	dbSubdomains, err := loadSubdomainsFromDB(context.Background())
	if err != nil {
		// Log the error but don't fail startup. The app can run with config file subdomains.
		if slogger != nil {
			slogger.Error("Failed to load subdomains from database", "error", err)
		}
	} else if len(dbSubdomains) > 0 {
		// Ensure the Subdomains map from the config file is initialized if it's nil.
		if config.Subdomains == nil {
			config.Subdomains = make(map[string]SubdomainConfig)
		}
		// Merge the database subdomains into the config, overwriting any duplicates.
		for domain, subConfig := range dbSubdomains {
			config.Subdomains[domain] = subConfig
		}
		slogger.Info("Successfully loaded and merged subdomains from database", "db_count", len(dbSubdomains), "total_count", len(config.Subdomains))
	}

	// --- START: Consolidate Domains ---
	// Ensure all domains from DomainNames are present in the Subdomains map
	// to make it the single source of truth for valid hosts.
	if config.Subdomains == nil {
		config.Subdomains = make(map[string]SubdomainConfig)
	}
	for _, domain := range config.DomainNames {
		if _, exists := config.Subdomains[domain]; !exists {
			// Add the domain with an empty config, so it will use the defaults.
			config.Subdomains[domain] = SubdomainConfig{}
		}
	}
	// --- END: Consolidate Domains ---

	initResolver()

	initTemplates()

	initImages()

	mux := http.NewServeMux()

	if err := handleCSS(mux); err != nil {
		log.Fatalln(err)
	}
	// Calculate SRI hashes for all assets at startup.
	if err := calculateSRIHashes(); err != nil {
		// Log as a warning because the app can still run, just without SRI.
		if slogger != nil {
			slogger.Warn("Could not calculate SRI hashes, integrity will not be enforced", "error", err)
		}
	}
	handleJS(mux)                                  // defined in handlers.go
	handleImages(mux)                              // defined in handlers.go
	mux.HandleFunc("/csp-report", handleCSPReport) // defined in handlers.go
	handleAdminRoutes(mux)                         // defined in handlers.go
	handleRobots(mux)                              // defined in handlers.go
	handleRoot(mux)                                // defined in handlers.go

	// Start server
	startupMsg := fmt.Sprintf("Starting server on %s", config.AddressPort)
	if slogger != nil {
		slogger.Info(startupMsg)
	} else {
		log.Println(startupMsg)
	}
	log.Fatalln(http.ListenAndServe(config.AddressPort, mux))
}

// calculateSRIHashes reads static assets (CSS, JS), computes their SRI hashes,
// and populates the global variables. This makes the application more robust,
// as hashes don't need to be manually updated when assets change.
func calculateSRIHashes() error {
	// shorter.css
	cssBytes, err := os.ReadFile(filepath.Join(config.BaseDir, "css", "shorter.css"))
	if err != nil {
		return fmt.Errorf("failed to read shorter.css: %w", err)
	}
	cssHash := sha256.Sum256(cssBytes)
	cssSRIHash = "sha256-" + base64.StdEncoding.EncodeToString(cssHash[:])

	// admin.js
	adminJsBytes, err := os.ReadFile(filepath.Join(config.BaseDir, "js", "admin.js"))
	if err != nil {
		return fmt.Errorf("failed to read admin.js: %w", err)
	}
	adminHash := sha256.Sum256(adminJsBytes)
	adminJsSRIHash = "sha256-" + base64.StdEncoding.EncodeToString(adminHash[:])

	// showText.js
	showTextJsBytes, err := os.ReadFile(filepath.Join(config.BaseDir, "js", "showText.js"))
	if err != nil {
		return fmt.Errorf("failed to read showText.js: %w", err)
	}
	showTextHash := sha256.Sum256(showTextJsBytes)
	showTextJsSRIHash = "sha256-" + base64.StdEncoding.EncodeToString(showTextHash[:])

	if slogger != nil {
		slogger.Info("Successfully calculated SRI hashes for static assets (CSS, JS)")
	}
	return nil
}
