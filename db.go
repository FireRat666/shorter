package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver for database/sql
)

// setupDB connects to the PostgreSQL database and ensures the schema is created.
func setupDB(databaseURL string) error {
	var err error
	if databaseURL == "" {
		return fmt.Errorf("DatabaseURL is not set in the config file")
	}

	db, err = sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Check that the connection is working
	// Use a more generous timeout for initial setup, as remote connections can be slow.
	// This timeout applies to both the ping and the schema creation.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Create the links table if it doesn't already exist
	schema := `
	CREATE TABLE IF NOT EXISTS links (
		key TEXT NOT NULL,
		domain TEXT NOT NULL,
		link_type TEXT NOT NULL,
		data BYTEA NOT NULL,
		is_compressed BOOLEAN NOT NULL,
		password_hash TEXT,
		created_by TEXT, -- UserID of the creator (admin or API key user)
		times_allowed INT NOT NULL,
		times_used INT DEFAULT 0 NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
		PRIMARY KEY (key, domain)
	);`

	if _, err = db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// Add an index on the created_by column for performance on the stats page.
	// CREATE INDEX IF NOT EXISTS is idempotent and safe to run on every startup.
	schemaLinksIndex := `CREATE INDEX IF NOT EXISTS idx_links_created_by ON links (created_by);`
	if _, err = db.ExecContext(ctx, schemaLinksIndex); err != nil {
		return fmt.Errorf("failed to create index on links(created_by): %w", err)
	}

	// Add additional indexes for stats page performance.
	// These speed up the "Recent Activity" and "Top 10" sections.
	schemaLinksCreatedAt := `CREATE INDEX IF NOT EXISTS idx_links_created_at ON links (created_at);`
	if _, err = db.ExecContext(ctx, schemaLinksCreatedAt); err != nil {
		return fmt.Errorf("failed to create index on links(created_at): %w", err)
	}

	schemaLinksExpiresAt := `CREATE INDEX IF NOT EXISTS idx_links_expires_at ON links (expires_at);`
	if _, err = db.ExecContext(ctx, schemaLinksExpiresAt); err != nil {
		return fmt.Errorf("failed to create index on links(expires_at): %w", err)
	}

	schemaLinksTimesUsed := `CREATE INDEX IF NOT EXISTS idx_links_times_used ON links (times_used);`
	if _, err = db.ExecContext(ctx, schemaLinksTimesUsed); err != nil {
		return fmt.Errorf("failed to create index on links(times_used): %w", err)
	}

	// Create the subdomain_configs table if it doesn't already exist.
	// The config column uses JSONB for efficient storage and querying of JSON data.
	schemaSubdomains := `
	CREATE TABLE IF NOT EXISTS subdomain_configs (
		domain TEXT PRIMARY KEY,
		config JSONB NOT NULL
	);`

	if _, err = db.ExecContext(ctx, schemaSubdomains); err != nil {
		return fmt.Errorf("failed to create subdomain_configs schema: %w", err)
	}

	// Create the sessions table for session-based authentication.
	schemaSessions := `
	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		csrf_token TEXT NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL
	);`
	if _, err = db.ExecContext(ctx, schemaSessions); err != nil {
		return fmt.Errorf("failed to create sessions schema: %w", err)
	}

	// Create the clicks table for link analytics.
	schemaClicks := `
	CREATE TABLE IF NOT EXISTS clicks (
		id BIGSERIAL PRIMARY KEY,
		link_key TEXT NOT NULL,
		link_domain TEXT NOT NULL,
		clicked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_clicks_clicked_at ON clicks (clicked_at);`
	if _, err = db.ExecContext(ctx, schemaClicks); err != nil {
		return fmt.Errorf("failed to create clicks schema: %w", err)
	}

	// Create the api_keys table for API authentication.
	schemaAPIKeys := `
	CREATE TABLE IF NOT EXISTS api_keys (
		token TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);`
	if _, err = db.ExecContext(ctx, schemaAPIKeys); err != nil {
		return fmt.Errorf("failed to create api_keys schema: %w", err)
	}

	// Create the expirations table for link analytics.
	// This table logs when a link is deleted due to expiration.
	schemaExpirations := `
	CREATE TABLE IF NOT EXISTS expirations (
		id BIGSERIAL PRIMARY KEY,
		link_key TEXT NOT NULL,
		link_domain TEXT NOT NULL,
		expired_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_expirations_expired_at ON expirations (expired_at);`
	if _, err = db.ExecContext(ctx, schemaExpirations); err != nil {
		return fmt.Errorf("failed to create expirations schema: %w", err)
	}

	// --- Schema Migrations ---
	// This section handles simple, additive schema changes to avoid breaking existing deployments.
	if err := runSchemaMigration(ctx, "links", "password_hash", "TEXT"); err != nil {
		return err
	}
	if err := runSchemaMigration(ctx, "links", "created_by", "TEXT"); err != nil {
		return err
	}
	if err := runSchemaMigration(ctx, "sessions", "csrf_token", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}

	return nil
}

// loadSubdomainsFromDB retrieves all subdomain configurations from the database.
func loadSubdomainsFromDB(ctx context.Context) (map[string]SubdomainConfig, error) {
	query := `SELECT domain, config FROM subdomain_configs;`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query subdomain configs: %w", err)
	}
	defer rows.Close()

	subdomains := make(map[string]SubdomainConfig)
	for rows.Next() {
		var domain string
		var configJSON []byte
		var subConfig SubdomainConfig

		if err := rows.Scan(&domain, &configJSON); err != nil {
			return nil, fmt.Errorf("failed to scan subdomain config row: %w", err)
		}

		if err := json.Unmarshal(configJSON, &subConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal subdomain config for %s: %w", domain, err)
		}
		subdomains[domain] = subConfig
	}

	return subdomains, rows.Err()
}

// saveSubdomainConfigToDB saves a single subdomain's configuration to the database.
// It performs an "upsert" operation: inserting a new record or updating an existing one.
func saveSubdomainConfigToDB(ctx context.Context, domain string, subConfig SubdomainConfig) error {
	configJSON, err := json.Marshal(subConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal subdomain config to JSON: %w", err)
	}

	// Use an "upsert" query to either insert a new subdomain or update an existing one.
	// The ON CONFLICT clause handles the case where the domain (primary key) already exists.
	query := `
		INSERT INTO subdomain_configs (domain, config)
		VALUES ($1, $2)
		ON CONFLICT (domain) DO UPDATE SET config = EXCLUDED.config;`

	_, err = db.ExecContext(ctx, query, domain, configJSON)
	return err
}

// deleteSubdomainFromDB removes a subdomain's configuration from the database.
func deleteSubdomainFromDB(ctx context.Context, domain string) error {
	query := `DELETE FROM subdomain_configs WHERE domain = $1;`
	result, err := db.ExecContext(ctx, query, domain)
	if err != nil {
		return fmt.Errorf("failed to delete subdomain %s: %w", domain, err)
	}

	rowsAffected, err := result.RowsAffected()
	if slogger != nil {
		if err != nil {
			// This is less likely, but good to handle.
			slogger.Warn("Could not get rows affected after deleting subdomain", "domain", domain, "error", err)
		} else if rowsAffected == 0 {
			slogger.Warn("Attempted to delete subdomain from DB, but it was not found", "domain", domain)
		} else {
			slogger.Info("Successfully deleted subdomain from database", "domain", domain, "rows_affected", rowsAffected)
		}
	}
	return nil
}

// deleteLinksForDomain removes all dynamic links associated with a specific domain.
func deleteLinksForDomain(ctx context.Context, domain string) error {
	query := `DELETE FROM links WHERE domain = $1;`
	result, err := db.ExecContext(ctx, query, domain)
	if err != nil {
		return fmt.Errorf("failed to delete links for domain %s: %w", domain, err)
	}
	rowsAffected, err := result.RowsAffected()
	if slogger != nil {
		if err != nil {
			slogger.Warn("Could not get rows affected after deleting links for domain", "domain", domain, "error", err)
		} else {
			// It's normal for a domain to have 0 links, so this is just an Info log.
			slogger.Info("Deleted dynamic links for domain", "domain", domain, "links_deleted", rowsAffected)
		}
	}
	return nil
}

// deleteExpiredLinksFromDB removes all links that have passed their expiration date.
// This is useful to run at startup to free up keys from expired links.
// It now also logs these deletions to the expirations table for analytics.
func deleteExpiredLinksFromDB(ctx context.Context) (int64, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction for expired link cleanup: %w", err)
	}
	defer tx.Rollback()

	// First, select the links that are about to be deleted to log them.
	querySelect := `SELECT key, domain, link_type FROM links WHERE expires_at <= NOW() FOR UPDATE;`
	rows, err := tx.QueryContext(ctx, querySelect)
	if err != nil {
		return 0, fmt.Errorf("failed to select expired links for logging: %w", err)
	}
	defer rows.Close()

	var linksToDelete []Link
	for rows.Next() {
		var link Link
		if err := rows.Scan(&link.Key, &link.Domain, &link.LinkType); err != nil {
			return 0, fmt.Errorf("failed to scan expired link for logging: %w", err)
		}
		linksToDelete = append(linksToDelete, link)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if len(linksToDelete) == 0 {
		return 0, nil // Nothing to do.
	}

	// Delete any associated uploaded files before modifying the database.
	for _, link := range linksToDelete {
		if link.LinkType == "file" {
			deleteUploadedFile(link.Key)
		}
	}

	// Log the expiration events before deleting.
	if err := logExpirationEventsInTx(ctx, tx, linksToDelete); err != nil {
		return 0, fmt.Errorf("failed to log expired links: %w", err)
	}

	// Now, delete the links.
	queryDelete := `DELETE FROM links WHERE expires_at <= NOW();`
	result, err := tx.ExecContext(ctx, queryDelete)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired links after logging: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("could not get rows affected after deleting expired links: %w", err)
	}

	return rowsAffected, tx.Commit()
}

// deleteExpiredSessionsFromDB removes all sessions that have passed their expiration date.
func deleteExpiredSessionsFromDB(ctx context.Context) (int64, error) {
	query := `DELETE FROM sessions WHERE expires_at <= NOW();`
	result, err := db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		// This is less likely, but good to handle.
		return 0, fmt.Errorf("could not get rows affected after deleting expired sessions: %w", err)
	}

	return rowsAffected, nil
}

// deleteOldExpirationLogs removes expiration log entries older than a certain period (e.g., 7 days)
// to keep the analytics table from growing indefinitely.
func deleteOldExpirationLogs(ctx context.Context) (int64, error) {
	// We keep 7 days of expiration data for the stats page.
	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)
	query := `DELETE FROM expirations WHERE expired_at < $1;`
	result, err := db.ExecContext(ctx, query, sevenDaysAgo)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old expiration logs: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("could not get rows affected after deleting old expiration logs: %w", err)
	}
	return rowsAffected, nil
}

// runSchemaMigration checks if a column exists in a table and adds it if it doesn't.
// This is a helper to make schema updates robust.
func runSchemaMigration(ctx context.Context, tableName, columnName, columnType string) error {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns
			WHERE table_name = $1 AND column_name = $2
		);`
	err := db.QueryRowContext(ctx, query, tableName, columnName).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check for column %s in table %s: %w", columnName, tableName, err)
	}

	if !exists {
		slogger.Info("Schema migration: adding column", "table", tableName, "column", columnName)
		alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s;", tableName, columnName, columnType)
		if _, err := db.ExecContext(ctx, alterQuery); err != nil {
			return fmt.Errorf("failed to apply schema migration for column %s: %w", columnName, err)
		}
		slogger.Info("Schema migration applied successfully.")
	}
	return nil
}

// getLinkCountForDomain returns the total number of active links for a specific domain.
func getLinkCountForDomain(ctx context.Context, domain, searchQuery string) (int, error) {
	var count int
	args := []interface{}{domain}
	query := `SELECT COUNT(*) FROM links WHERE domain = $1 AND expires_at > NOW()`

	if searchQuery != "" {
		query += ` AND key ILIKE $2`
		args = append(args, "%"+searchQuery+"%")
	}

	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get link count for domain %s: %w", domain, err)
	}
	return count, nil
}

// getLinksForDomain retrieves a paginated list of active links for a specific domain.
func getLinksForDomain(ctx context.Context, domain, searchQuery string, limit, offset int) ([]Link, error) {
	args := []interface{}{domain}
	query := `
		SELECT key, link_type, times_used, expires_at, password_hash, created_by
		FROM links
		WHERE domain = $1 AND expires_at > NOW()`

	if searchQuery != "" {
		query += ` AND key ILIKE $2`
		args = append(args, "%"+searchQuery+"%")
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d;", len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query links for domain %s: %w", domain, err)
	}
	defer rows.Close()

	var links []Link
	for rows.Next() {
		var link Link
		link.Domain = domain // Set the domain since we're not selecting it
		if err := rows.Scan(
			&link.Key,
			&link.LinkType,
			&link.TimesUsed,
			&link.ExpiresAt,
			&link.PasswordHash,
			&link.CreatedBy,
		); err != nil {
			return nil, fmt.Errorf("failed to scan link row: %w", err)
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

// getAllActiveLinks retrieves all active links from the database.
func getAllActiveLinks(ctx context.Context) ([]Link, error) {
	query := `
		SELECT key, domain, link_type, data, is_compressed, password_hash, created_by, times_allowed, times_used, expires_at, created_at
		FROM links
		WHERE expires_at > NOW()
		ORDER BY created_at DESC;`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all active links: %w", err)
	}
	defer rows.Close()

	var links []Link
	for rows.Next() {
		var link Link
		if err := rows.Scan(
			&link.Key,
			&link.Domain,
			&link.LinkType,
			&link.Data,
			&link.IsCompressed,
			&link.PasswordHash,
			&link.CreatedBy,
			&link.TimesAllowed,
			&link.TimesUsed,
			&link.ExpiresAt,
			&link.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan link row: %w", err)
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

// deleteLink removes a dynamic link from the database by its key and domain.
func deleteLink(ctx context.Context, key, domain string) error {
	query := `DELETE FROM links WHERE key = $1 AND domain = $2;`
	_, err := db.ExecContext(ctx, query, key, domain)
	if err != nil {
		return fmt.Errorf("failed to delete link %s for domain %s: %w", key, domain, err)
	}
	return nil
}

// analyzeTables manually triggers a database analysis on key tables.
// This is useful after large data changes (like startup cleanup or stats reset)
// to ensure the query planner has up-to-date statistics.
func analyzeTables(ctx context.Context) {
	// We analyze the tables that are used for performance-critical estimates.
	if _, err := db.ExecContext(ctx, `ANALYZE links; ANALYZE clicks;`); err != nil {
		slogger.Warn("Failed to run ANALYZE on tables", "error", err)
	} else {
		slogger.Info("Successfully ran ANALYZE on database tables.")
	}
}

// getOverallStats retrieves the main, site-wide statistics for the top of the stats page.
// It uses fast PostgreSQL estimates for counts on large tables to ensure quick page loads.
func getOverallStats(ctx context.Context) (*LinkStats, error) {
	stats := &LinkStats{}
	var err error

	// Helper function to run a single COUNT query.
	countQuery := func(query string, args ...interface{}) (int, error) {
		var count int
		err := db.QueryRowContext(ctx, query, args...).Scan(&count)
		if err != nil && err != sql.ErrNoRows {
			return 0, err
		}
		return count, nil
	}

	// Total Active Links - This should be fast with the index on expires_at.
	stats.TotalActiveLinks, err = countQuery(`SELECT COUNT(*) FROM links WHERE expires_at > NOW()`)
	if err != nil {
		return nil, fmt.Errorf("failed to count total active links: %w", err)
	}

	// Total Links Created (All-Time) - Use an estimate for performance on large tables.
	err = db.QueryRowContext(ctx, `SELECT reltuples::bigint FROM pg_class WHERE relname = 'links'`).Scan(&stats.TotalLinksCreated)
	// If the estimate fails or is negative (meaning the table has not been analyzed), fall back to the accurate count.
	if err != nil || stats.TotalLinksCreated < 0 {
		if err != nil {
			slogger.Warn("Failed to get estimated row count for 'links', falling back to slow COUNT(*)", "error", err)
		} else {
			slogger.Info("Estimated row count for 'links' is negative (table not analyzed), falling back to slow COUNT(*)")
		}
		stats.TotalLinksCreated, err = countQuery(`SELECT COUNT(*) FROM links`)
		if err != nil {
			return nil, fmt.Errorf("failed to count all-time links: %w", err)
		}
	}

	// Total Clicks (All-Time) - Use an estimate for performance on the clicks table.
	err = db.QueryRowContext(ctx, `SELECT reltuples::bigint FROM pg_class WHERE relname = 'clicks'`).Scan(&stats.TotalClicks)
	// If the estimate fails or is negative (meaning the table has not been analyzed), fall back to the accurate count.
	if err != nil || stats.TotalClicks < 0 {
		if err != nil {
			slogger.Warn("Failed to get estimated row count for 'clicks', falling back to slow COUNT(*)", "error", err)
		} else {
			slogger.Info("Estimated row count for 'clicks' is negative (table not analyzed), falling back to slow COUNT(*)")
		}
		stats.TotalClicks, err = countQuery(`SELECT COUNT(*) FROM clicks`)
		if err != nil {
			return nil, fmt.Errorf("failed to count total clicks from clicks table: %w", err)
		}
	}

	return stats, nil
}

// getLinkStats retrieves a comprehensive set of statistics about link creation and usage.
func getLinkStats(ctx context.Context) (*LinkStats, error) {
	stats := &LinkStats{}
	var err error

	// Helper function to run a single COUNT query.
	countQuery := func(query string, args ...interface{}) (int, error) {
		var count int
		err := db.QueryRowContext(ctx, query, args...).Scan(&count)
		if err != nil && err != sql.ErrNoRows {
			return 0, err
		}
		return count, nil
	}

	// Time-based stats
	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)
	twentyFourHoursAgo := now.Add(-24 * time.Hour)
	sevenDaysAgo := now.Add(-7 * 24 * time.Hour)

	// Links Created
	stats.LinksCreatedLastHour, err = countQuery(`SELECT COUNT(*) FROM links WHERE created_at >= $1`, oneHourAgo)
	if err != nil {
		return nil, err
	}
	stats.LinksCreatedLast24Hours, err = countQuery(`SELECT COUNT(*) FROM links WHERE created_at >= $1`, twentyFourHoursAgo)
	if err != nil {
		return nil, err
	}
	stats.LinksCreatedLast7Days, err = countQuery(`SELECT COUNT(*) FROM links WHERE created_at >= $1`, sevenDaysAgo)
	if err != nil {
		return nil, err
	}

	// Links Expired (now from the dedicated expirations table)
	stats.LinksExpiredLastHour, err = countQuery(`SELECT COUNT(*) FROM expirations WHERE expired_at >= $1`, oneHourAgo)
	if err != nil {
		return nil, fmt.Errorf("failed to count expired links (1h): %w", err)
	}
	stats.LinksExpiredLast24Hours, err = countQuery(`SELECT COUNT(*) FROM expirations WHERE expired_at >= $1`, twentyFourHoursAgo)
	if err != nil {
		return nil, fmt.Errorf("failed to count expired links (24h): %w", err)
	}
	stats.LinksExpiredLast7Days, err = countQuery(`SELECT COUNT(*) FROM expirations WHERE expired_at >= $1`, sevenDaysAgo)
	if err != nil {
		return nil, fmt.Errorf("failed to count expired links (7d): %w", err)
	}

	// Clicks Recorded
	stats.ClicksLastHour, err = countQuery(`SELECT COUNT(*) FROM clicks WHERE clicked_at >= $1`, oneHourAgo)
	if err != nil {
		return nil, err
	}
	stats.ClicksLast24Hours, err = countQuery(`SELECT COUNT(*) FROM clicks WHERE clicked_at >= $1`, twentyFourHoursAgo)
	if err != nil {
		return nil, err
	}
	stats.ClicksLast7Days, err = countQuery(`SELECT COUNT(*) FROM clicks WHERE clicked_at >= $1`, sevenDaysAgo)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// getCreatorStats aggregates link creation counts by user.
func getCreatorStats(ctx context.Context) ([]CreatorStats, error) {
	query := `
		SELECT COALESCE(created_by, 'Anonymous') as creator, COUNT(*) as link_count
		FROM links
		WHERE expires_at > NOW() -- Count only active links
		GROUP BY creator
		ORDER BY link_count DESC;`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query creator stats: %w", err)
	}
	defer rows.Close()

	var stats []CreatorStats
	for rows.Next() {
		var stat CreatorStats
		if err := rows.Scan(&stat.UserID, &stat.LinkCount); err != nil {
			return nil, fmt.Errorf("failed to scan creator stat row: %w", err)
		}
		stats = append(stats, stat)
	}
	return stats, rows.Err()
}

// getStatsForDomain retrieves statistics for a single specified domain.
func getStatsForDomain(ctx context.Context, domain string) (*DomainStats, error) {
	stats := &DomainStats{Domain: domain}
	var err error

	// 1. Get active link count for the domain.
	queryLinks := `SELECT COUNT(*) FROM links WHERE domain = $1 AND expires_at > NOW();`
	err = db.QueryRowContext(ctx, queryLinks, domain).Scan(&stats.ActiveLinks)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query active links for domain %s: %w", domain, err)
	}

	// 2. Get total click count for the domain.
	queryClicks := `SELECT COUNT(*) FROM clicks WHERE link_domain = $1;`
	err = db.QueryRowContext(ctx, queryClicks, domain).Scan(&stats.TotalClicks)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query clicks for domain %s: %w", domain, err)
	}

	return stats, nil
}

// errKeyCollision is a sentinel error used to indicate a key collision with an *active* link.
var errKeyCollision = errors.New("active key collision")

// createLinkInDB inserts a new link record into the database.
// It uses a conditional "upsert" to reclaim keys from expired links.
func createLinkInDB(ctx context.Context, link Link) error {
	// This query attempts to insert a new link.
	// If a link with the same (key, domain) already exists, it triggers the ON CONFLICT clause.
	// The DO UPDATE part will only execute if the WHERE condition is met, meaning the
	// existing link is expired by time or has been used up.
	// If the existing link is still active, the WHERE condition is false, the UPDATE is
	// skipped, and zero rows are affected.
	query := `
		INSERT INTO links (key, domain, link_type, data, is_compressed, password_hash, created_by, times_allowed, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (key, domain) DO UPDATE
		SET
			link_type = EXCLUDED.link_type,
			data = EXCLUDED.data,
			is_compressed = EXCLUDED.is_compressed,
			password_hash = EXCLUDED.password_hash,
			created_by = EXCLUDED.created_by,
			times_allowed = EXCLUDED.times_allowed,
			times_used = 0, -- Reset usage count for the new link
			expires_at = EXCLUDED.expires_at,
			created_at = NOW()
		WHERE
			links.expires_at <= NOW() OR (links.times_allowed > 0 AND links.times_used >= links.times_allowed);`

	result, err := db.ExecContext(ctx, query, link.Key, link.Domain, link.LinkType, link.Data, link.IsCompressed, link.PasswordHash, link.CreatedBy, link.TimesAllowed, link.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to insert or update link in database: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected after link creation: %w", err)
	}

	if rowsAffected == 0 {
		// This means the key exists and is still active. We must signal a collision.
		return errKeyCollision
	}

	return nil
}

// getLinkFromDB retrieves a link from the database by its key, and if found,
// it atomically increments the `times_used` counter.
// It returns nil if the link is not found, has expired, or has been used too many times.
func getLinkFromDB(ctx context.Context, key, domain string) (*Link, error) {
	// Use a transaction to ensure the SELECT and UPDATE are atomic.
	// This prevents race conditions where two requests could try to use the last
	// available link at the same time.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	// Defer a rollback. If the transaction is successfully committed, this is a no-op.
	defer tx.Rollback()

	link := &Link{}
	// The query intentionally does NOT check for expiration here.
	// We will check for expiration in the application logic so we can perform
	// a "just-in-time" deletion of the expired link.
	querySelect := `
		SELECT key, domain, link_type, data, is_compressed, password_hash, created_by, times_allowed, times_used, expires_at, created_at
		FROM links
		WHERE key = $1 AND domain = $2
		FOR UPDATE;`

	err = tx.QueryRowContext(ctx, querySelect, key, domain).Scan(
		&link.Key,
		&link.Domain,
		&link.LinkType,
		&link.Data,
		&link.IsCompressed,
		&link.PasswordHash,
		&link.CreatedBy,
		&link.TimesAllowed,
		&link.TimesUsed,
		&link.ExpiresAt,
		&link.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No link found, not an error.
		}
		return nil, fmt.Errorf("failed to get link from database: %w", err)
	}

	// Check for expiration or overuse in the application logic.
	if time.Now().After(link.ExpiresAt) || (link.TimesAllowed > 0 && link.TimesUsed >= link.TimesAllowed) {
		// The link is expired or used up. Log the expiration event and then delete it, all in the same transaction.
		// If it's a file link, delete the associated file from disk.
		if link.LinkType == "file" {
			deleteUploadedFile(link.Key)
		}

		if err := logExpirationEventsInTx(ctx, tx, []Link{*link}); err != nil {
			slogger.Error("Failed to log just-in-time expiration event", "key", key, "domain", domain, "error", err)
			// Don't block deletion on logging failure, but the defer will rollback the transaction.
			return nil, nil
		}
		deleteQuery := `DELETE FROM links WHERE key = $1 AND domain = $2;`
		if _, err := tx.ExecContext(ctx, deleteQuery, key, domain); err != nil {
			// Log the deletion error but still return nil to the user, as the link is invalid.
			slogger.Error("Failed to perform just-in-time deletion of invalid link", "key", key, "domain", domain, "error", err)
			return nil, nil // The defer will rollback.
		} else if slogger != nil {
			slogger.Info("Performed just-in-time deletion of invalid link", "key", key, "domain", domain)
		}
		// If we get here, both logging and deletion were successful. Commit the transaction.
		if err := tx.Commit(); err != nil {
			slogger.Error("Failed to commit just-in-time deletion transaction", "key", key, "domain", domain, "error", err)
		}
		return nil, nil // Return nil as if the link was not found.
	}

	// Commit the transaction to save the changes.
	return link, tx.Commit()
}

// incrementLinkUsage increments a link's usage count and records the click for analytics.
func incrementLinkUsage(ctx context.Context, key, domain string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for usage increment: %w", err)
	}
	defer tx.Rollback()

	// Increment the usage count.
	if _, err := tx.ExecContext(ctx, `UPDATE links SET times_used = times_used + 1 WHERE key = $1 AND domain = $2;`, key, domain); err != nil {
		return fmt.Errorf("failed to update link usage: %w", err)
	}
	// Record the click event.
	if _, err := tx.ExecContext(ctx, `INSERT INTO clicks (link_key, link_domain) VALUES ($1, $2);`, key, domain); err != nil {
		return fmt.Errorf("failed to record click for analytics: %w", err)
	}
	return tx.Commit()
}

// logExpirationEventsInTx logs one or more link expirations to the expirations table for analytics.
// It requires an existing transaction to be passed in.
func logExpirationEventsInTx(ctx context.Context, tx *sql.Tx, links []Link) error {
	if len(links) == 0 {
		return nil
	}

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO expirations (link_key, link_domain) VALUES ($1, $2);`)
	if err != nil {
		return fmt.Errorf("failed to prepare expiration log statement: %w", err)
	}
	defer stmt.Close()

	for _, link := range links {
		if _, err := stmt.ExecContext(ctx, link.Key, link.Domain); err != nil {
			return fmt.Errorf("failed to execute expiration log statement for link %s: %w", link.Key, err)
		}
	}

	return nil
}

// resetAllStatistics performs a hard reset on historical analytics data.
// It truncates the clicks and expirations tables, resets all link usage counters to zero,
// and deletes all logically expired links. This is a destructive operation.
func resetAllStatistics(ctx context.Context) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for resetting statistics: %w", err)
	}
	defer tx.Rollback() // Rollback on error

	// 1. Delete all logically expired links (by time or usage).
	// This makes the total link count equal to the active link count.
	deleteQuery := `DELETE FROM links WHERE expires_at <= NOW() OR (times_allowed > 0 AND times_used >= times_allowed);`
	if _, err := tx.ExecContext(ctx, deleteQuery); err != nil {
		return fmt.Errorf("failed to delete expired links during reset: %w", err)
	}

	// 2. Reset click counts on all remaining (active) links.
	updateQuery := `UPDATE links SET times_used = 0;`
	if _, err := tx.ExecContext(ctx, updateQuery); err != nil {
		return fmt.Errorf("failed to reset link click counts during reset: %w", err)
	}

	// 3. Truncate the historical clicks and expirations tables.
	if _, err := tx.ExecContext(ctx, `TRUNCATE TABLE clicks, expirations;`); err != nil {
		return fmt.Errorf("failed to truncate analytics tables during reset: %w", err)
	}

	// If all commands succeed, commit the transaction.
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction for resetting statistics: %w", err)
	}

	// 4. After committing, manually analyze the tables to update statistics.
	analyzeTables(ctx)

	return nil
}

// --- Session Management ---

// createSession generates a new session token, stores it in the database, and returns the session.
func createSession(ctx context.Context, userID string, duration time.Duration) (*Session, error) {
	token, err := generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	csrfToken, err := generateSessionToken() // We can reuse the same secure token generator.
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSRF token: %w", err)
	}

	expiresAt := time.Now().Add(duration)

	session := &Session{
		Token:     token,
		UserID:    userID,
		CSRFToken: csrfToken,
		ExpiresAt: expiresAt,
	}

	query := `INSERT INTO sessions (token, user_id, csrf_token, expires_at) VALUES ($1, $2, $3, $4);`
	_, err = db.ExecContext(ctx, query, session.Token, session.UserID, session.CSRFToken, session.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert session into database: %w", err)
	}

	return session, nil
}

// getSessionByToken retrieves a session from the database if it exists and has not expired.
func getSessionByToken(ctx context.Context, token string) (*Session, error) {
	session := &Session{}
	query := `SELECT token, user_id, csrf_token, expires_at FROM sessions WHERE token = $1 AND expires_at > NOW();`

	err := db.QueryRowContext(ctx, query, token).Scan(&session.Token, &session.UserID, &session.CSRFToken, &session.ExpiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No session found, not a fatal error.
		}
		return nil, fmt.Errorf("failed to get session from database: %w", err)
	}
	return session, nil
}

// deleteSessionByToken removes a session from the database, effectively logging the user out.
func deleteSessionByToken(ctx context.Context, token string) error {
	query := `DELETE FROM sessions WHERE token = $1;`
	_, err := db.ExecContext(ctx, query, token)
	return err
}

// getLinkDetails retrieves a link's full details from the database by its key and domain,
// regardless of its expiration or usage status. This is for admin editing purposes.
func getLinkDetails(ctx context.Context, key, domain string) (*Link, error) {
	link := &Link{}
	query := `
		SELECT key, domain, link_type, data, is_compressed, password_hash, created_by, times_allowed, times_used, expires_at, created_at
		FROM links
		WHERE key = $1 AND domain = $2;`

	err := db.QueryRowContext(ctx, query, key, domain).Scan(
		&link.Key,
		&link.Domain,
		&link.LinkType,
		&link.Data,
		&link.IsCompressed,
		&link.PasswordHash,
		&link.CreatedBy,
		&link.TimesAllowed,
		&link.TimesUsed,
		&link.ExpiresAt,
		&link.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No link found, not an error.
		}
		return nil, fmt.Errorf("failed to get link details from database: %w", err)
	}
	return link, nil
}

// updateLink updates the details of an existing dynamic link in the database.
func updateLink(ctx context.Context, link Link) error {
	query := `
		UPDATE links SET
			data = $1,
			is_compressed = $2,
			password_hash = $3,
			times_allowed = $4,
			expires_at = $5
		WHERE key = $6 AND domain = $7;`

	_, err := db.ExecContext(ctx, query,
		link.Data,
		link.IsCompressed,
		link.PasswordHash,
		link.TimesAllowed,
		link.ExpiresAt,
		link.Key,
		link.Domain,
	)
	return err
}

// getTotalActiveLinkCount returns the total number of active links.
func getTotalActiveLinkCount(ctx context.Context) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM links WHERE expires_at > NOW();`
	err := db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get total active link count: %w", err)
	}
	return count, nil
}

// getTopLinks retrieves a paginated list of the most clicked active links.
func getTopLinks(ctx context.Context, limit, offset int) ([]Link, error) {
	query := `
		SELECT key, domain, link_type, times_used, expires_at
		FROM links
		WHERE expires_at > NOW()
		ORDER BY times_used DESC
		LIMIT $1 OFFSET $2;`

	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query top links: %w", err)
	}
	defer rows.Close()

	var links []Link
	for rows.Next() {
		var link Link
		if err := rows.Scan(
			&link.Key,
			&link.Domain,
			&link.LinkType,
			&link.TimesUsed,
			&link.ExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan top link row: %w", err)
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

// --- API Key Management ---

// createAPIKey generates a new API key for a user and stores it in the database.
func createAPIKey(ctx context.Context, userID string) (*APIKey, error) {
	token, err := generateSessionToken() // We can reuse the same secure token generator.
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key token: %w", err)
	}

	apiKey := &APIKey{
		Token:  token,
		UserID: userID,
	}

	query := `INSERT INTO api_keys (token, user_id) VALUES ($1, $2);`
	_, err = db.ExecContext(ctx, query, apiKey.Token, apiKey.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to insert API key into database: %w", err)
	}

	return apiKey, nil
}

// getAPIKeysForUser retrieves all API keys associated with a specific user.
func getAPIKeysForUser(ctx context.Context, userID string) ([]APIKey, error) {
	query := `SELECT token, user_id, created_at FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC;`
	rows, err := db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query API keys for user %s: %w", userID, err)
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var key APIKey
		if err := rows.Scan(&key.Token, &key.UserID, &key.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan API key row: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// deleteAPIKey removes a specific API key from the database.
func deleteAPIKey(ctx context.Context, token string) error {
	query := `DELETE FROM api_keys WHERE token = $1;`
	_, err := db.ExecContext(ctx, query, token)
	return err
}

// getAPIKeyByToken retrieves a user's API key from the database by the token string.
func getAPIKeyByToken(ctx context.Context, token string) (*APIKey, error) {
	apiKey := &APIKey{}
	query := `SELECT token, user_id, created_at FROM api_keys WHERE token = $1;`

	err := db.QueryRowContext(ctx, query, token).Scan(&apiKey.Token, &apiKey.UserID, &apiKey.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No key found, not a fatal error.
		}
		return nil, fmt.Errorf("failed to get API key from database: %w", err)
	}
	return apiKey, nil
}
