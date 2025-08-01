package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kr/pretty"
)

func main() {
	// 1. Load configuration from file.
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// 2. Initialize the structured logger.
	if err := initLogger(config.Logging, config.LogLevel, config.Logfile); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	slogger.Info("Logger initialized successfully")
	slogger.Info("Successfully loaded configuration", "file", loadedConfigPath)

	// Log the loaded configuration, redacting sensitive fields.
	loggedConfig := config
	if loggedConfig.DatabaseURL != "" {
		loggedConfig.DatabaseURL = "[REDACTED]"
	}
	loggedConfig.LogSep = "[REDACTED]"
	loggedConfig.Admin.PassHash = "[REDACTED]"
	slogger.Info("Loaded config", "config", fmt.Sprintf("%# v", pretty.Formatter(loggedConfig)))

	// 3. Set up the database connection.
	if err := setupDB(config.DatabaseURL); err != nil {
		slogger.Error("Failed to set up database", "error", err)
		os.Exit(1)
	}
	slogger.Info("Database connection established")

	// Clean up expired links at startup to free up keys.
	slogger.Info("Running cleanup for expired links...")
	deletedCount, err := deleteExpiredLinksFromDB(context.Background())
	if err != nil {
		// This is not a fatal error, so we just log it and continue.
		slogger.Error("Failed to delete expired links", "error", err)
	} else if deletedCount > 0 {
		slogger.Info("Successfully deleted expired links", "count", deletedCount)
	} else {
		slogger.Info("No expired links found to delete.")
	}
	// Analyze tables at startup to ensure planner statistics are fresh.
	slogger.Info("Analyzing database tables for optimal performance...")
	analyzeTables(context.Background())

	// 4. Load subdomains from DB and merge with file config.
	if err := loadSubdomainsAndMerge(context.Background()); err != nil {
		slogger.Error("Failed to load and merge subdomains from DB", "error", err)
		os.Exit(1)
	}
	slogger.Info("Subdomain configurations loaded and merged")

	// 5. Initialize templates and static assets.
	initResolver()
	// Calculate SRI hashes for all assets at startup.
	if err := calculateSRIHashes(); err != nil {
		// Log as a warning because the app can still run, just without SRI.
		slogger.Warn("Could not calculate SRI hashes, integrity will not be enforced", "error", err)
	}
	if err := initTemplates(); err != nil {
		slogger.Error("Failed to initialize templates", "error", err)
		os.Exit(1)
	}
	if err := initImages(); err != nil {
		slogger.Error("Failed to initialize images", "error", err)
		os.Exit(1)
	}
	slogger.Info("Templates and images loaded")

	// 6. Set up the HTTP request multiplexer (router).
	mux := http.NewServeMux()
	handleRoot(mux)
	mux.HandleFunc("/login", handleLoginPage)
	mux.HandleFunc("/qr", handleQRCodePage)
	handleAdminRoutes(mux)
	handleAPIRoutes(mux)
	handleRobots(mux)
	handleImages(mux)
	handleJS(mux)
	mux.HandleFunc("/csp-report", handleCSPReport)
	if err := handleCSS(mux); err != nil {
		slogger.Error("Failed to set up CSS handler", "error", err)
		os.Exit(1)
	}

	// 7. Configure and start the HTTP server.
	server := &http.Server{
		Addr:         config.AddressPort,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 8. Start the server in a goroutine so it doesn't block.
	go func() {
		slogger.Info("Starting server", "address", config.AddressPort)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			slogger.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Start the periodic cleanup job in the background.
	go startCleanupTicker()

	// Start the rate limiter cleanup job in the background.
	go cleanupClients()

	// 9. Set up a channel to listen for OS signals for graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received.
	<-quit
	slogger.Info("Shutting down server...")

	// 10. Gracefully shut down the server with a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slogger.Error("Server shutdown failed", "error", err)
		os.Exit(1)
	}

	slogger.Info("Server gracefully stopped")
}

// initLogger sets up the global slog logger based on the application config.
func initLogger(loggingEnabled bool, logLevel, logFile string) error {
	if !loggingEnabled {
		slogger = slog.New(slog.NewTextHandler(io.Discard, nil))
		return nil
	}

	var level slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("invalid log level: %s", logLevel)
	}

	var output io.Writer = os.Stdout
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file %s: %w", logFile, err)
		}
		output = file
	}

	handler := slog.NewTextHandler(output, &slog.HandlerOptions{Level: level})
	slogger = slog.New(handler)
	return nil
}

// loadSubdomainsAndMerge loads configurations from the database and merges them
// into the global config, ensuring the primary domain and DB entries are present.
func loadSubdomainsAndMerge(ctx context.Context) error {
	dbSubdomains, err := loadSubdomainsFromDB(ctx)
	if err != nil {
		return err
	}

	// Ensure the Subdomains map from the config file is initialized if it's nil.
	if config.Subdomains == nil {
		config.Subdomains = make(map[string]SubdomainConfig)
	}

	// Merge the database subdomains into the config, overwriting any file-based duplicates.
	for domain, subConfig := range dbSubdomains {
		config.Subdomains[domain] = subConfig
	}

	// Finally, ensure all domains from the main DomainNames list are present in the
	// Subdomains map, making it the single source of truth for valid hosts.
	// This also adds the primary domain with its default settings if not already present.
	for _, domain := range config.DomainNames {
		if _, exists := config.Subdomains[domain]; !exists {
			config.Subdomains[domain] = config.Defaults
		}
	}

	return nil
}

// startCleanupTicker starts a background job that periodically cleans up expired
// records from the database.
func startCleanupTicker() {
	// Default to 24 hours if the interval is not set or invalid.
	interval := 24 * time.Hour
	if config.CleanupInterval != "" {
		parsedInterval, err := time.ParseDuration(config.CleanupInterval)
		if err != nil {
			slogger.Error("Invalid CleanupInterval format, using default 24h", "interval", config.CleanupInterval, "error", err)
		} else {
			interval = parsedInterval
		}
	}

	slogger.Info("Periodic cleanup job scheduled", "interval", interval.String())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run the cleanup immediately on start, then on each tick.
	for ; ; <-ticker.C {
		runCleanup()
	}
}

// runCleanup performs the actual deletion of expired links and sessions.
func runCleanup() {
	slogger.Info("Running periodic cleanup...")

	// Clean up expired links.
	if linksDeleted, err := deleteExpiredLinksFromDB(context.Background()); err != nil {
		slogger.Error("Error during periodic link cleanup", "error", err)
	} else if linksDeleted > 0 {
		slogger.Info("Periodic cleanup deleted expired links", "count", linksDeleted)
	}

	// Clean up expired sessions.
	if sessionsDeleted, err := deleteExpiredSessionsFromDB(context.Background()); err != nil {
		slogger.Error("Error during periodic session cleanup", "error", err)
	} else if sessionsDeleted > 0 {
		slogger.Info("Periodic cleanup deleted expired sessions", "count", sessionsDeleted)
	}

	// Clean up old expiration logs to keep the table size manageable.
	if logsDeleted, err := deleteOldExpirationLogs(context.Background()); err != nil {
		slogger.Error("Error during periodic expiration log cleanup", "error", err)
	} else if logsDeleted > 0 {
		slogger.Info("Periodic cleanup deleted old expiration logs", "count", logsDeleted)
	}

	// Clean up orphaned abuse reports.
	if reportsCleaned, err := cleanupOrphanedAbuseReports(context.Background()); err != nil {
		slogger.Error("Error during orphaned abuse report cleanup", "error", err)
	} else if reportsCleaned > 0 {
		slogger.Info("Periodic cleanup deleted orphaned abuse reports", "count", reportsCleaned)
	}
}
