package main

import (
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

	// --- END: Render Compatibility ---

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

	initResolver()

	initTemplates()

	initImages()

	mux := http.NewServeMux()

	if err := handleCSS(mux); err != nil {
		log.Fatalln(err)
	}
	handleJS(mux)                                  // defined in handlers.go
	handleImages(mux)                              // defined in handlers.go
	mux.HandleFunc("/csp-report", handleCSPReport) // defined in handlers.go
	mux.HandleFunc("/admin", basicAuth(handleAdmin))
	handleRobots(mux) // defined in handlers.go
	handleRoot(mux)   // defined in handlers.go

	// Start server
	startupMsg := fmt.Sprintf("Starting server on %s", config.AddressPort)
	if slogger != nil {
		slogger.Info(startupMsg)
	} else {
		log.Println(startupMsg)
	}
	log.Fatalln(http.ListenAndServe(config.AddressPort, mux))
}
