package main

import (
	"database/sql"
	"html/template"
	"log/slog"
	"net"
	"sync"
)

// Global variables are centralized here to avoid redeclaration errors.
var (
	// slogger is the global structured logger, initialized in main.go.
	slogger *slog.Logger

	// config holds the application's configuration, loaded from config.yaml.
	config Config
	// configOnce ensures the configuration is loaded only once.
	configOnce sync.Once
	// configErr holds any error that occurred during configuration loading.
	configErr error
	// loadedConfigPath holds the path of the configuration file that was loaded.
	loadedConfigPath string

	// db is the global database connection pool, initialized in db.go.
	db *sql.DB

	// customResolver is a custom DNS resolver for malware checks.
	customResolver *net.Resolver

	// templateMap holds the parsed HTML templates.
	templateMap map[string]*template.Template

	// ImageMap holds the loaded image assets.
	ImageMap map[string][]byte

	// jsFileMap holds the content of JS files read at startup.
	jsFileMap map[string][]byte

	// SRI hashes for CSS and JS files, calculated at startup.
	cssSRIHash        string
	adminJsSRIHash    string
	showTextJsSRIHash string
)
