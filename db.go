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
		times_allowed INT NOT NULL,
		times_used INT DEFAULT 0 NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
		PRIMARY KEY (key, domain)
	);`

	if _, err = db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
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

	// --- Schema Migrations ---
	// This section handles simple, additive schema changes to avoid breaking existing deployments.

	// Migration 1: Add password_hash column to links table if it doesn't exist.
	var columnExists bool
	checkColumnQuery := `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns
			WHERE table_name = 'links' AND column_name = 'password_hash'
		);`
	err = db.QueryRowContext(ctx, checkColumnQuery).Scan(&columnExists)
	if err != nil {
		return fmt.Errorf("failed to check for password_hash column existence: %w", err)
	}

	if !columnExists {
		slogger.Info("Schema migration: adding 'password_hash' column to 'links' table...")
		alterQuery := `ALTER TABLE links ADD COLUMN password_hash TEXT;`
		if _, err = db.ExecContext(ctx, alterQuery); err != nil {
			return fmt.Errorf("failed to apply schema migration for password_hash column: %w", err)
		}
		slogger.Info("Schema migration applied successfully.")
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
func deleteExpiredLinksFromDB(ctx context.Context) (int64, error) {
	query := `DELETE FROM links WHERE expires_at <= NOW();`
	result, err := db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired links: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		// This is less likely, but good to handle.
		return 0, fmt.Errorf("could not get rows affected after deleting expired links: %w", err)
	}

	return rowsAffected, nil
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

// getLinksForDomain retrieves all active links for a specific domain, ordered by creation date.
func getLinksForDomain(ctx context.Context, domain string) ([]Link, error) {
	query := `
		SELECT key, link_type, times_used, expires_at
		FROM links
		WHERE domain = $1 AND expires_at > NOW()
		ORDER BY created_at DESC;`

	rows, err := db.QueryContext(ctx, query, domain)
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
		SELECT key, domain, link_type, data, is_compressed, times_allowed, times_used, expires_at, created_at
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

	// Total Active Links
	stats.TotalActiveLinks, err = countQuery(`SELECT COUNT(*) FROM links WHERE expires_at > NOW()`)
	if err != nil {
		return nil, fmt.Errorf("failed to count total active links: %w", err)
	}

	// Total Clicks (from the times_used column for an overall count)
	err = db.QueryRowContext(ctx, `SELECT COALESCE(SUM(times_used), 0) FROM links`).Scan(&stats.TotalClicks)
	if err != nil {
		return nil, fmt.Errorf("failed to sum total clicks: %w", err)
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
		INSERT INTO links (key, domain, link_type, data, is_compressed, password_hash, times_allowed, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (key, domain) DO UPDATE
		SET
			link_type = EXCLUDED.link_type,
			data = EXCLUDED.data,
			is_compressed = EXCLUDED.is_compressed,
			password_hash = EXCLUDED.password_hash,
			times_allowed = EXCLUDED.times_allowed,
			times_used = 0, -- Reset usage count for the new link
			expires_at = EXCLUDED.expires_at,
			created_at = NOW()
		WHERE
			links.expires_at <= NOW() OR (links.times_allowed > 0 AND links.times_used >= links.times_allowed);`

	result, err := db.ExecContext(ctx, query, link.Key, link.Domain, link.LinkType, link.Data, link.IsCompressed, link.PasswordHash, link.TimesAllowed, link.ExpiresAt)
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
		SELECT key, domain, link_type, data, is_compressed, password_hash, times_allowed, times_used, expires_at, created_at
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
		// The link is expired or used up. Delete it now within the same transaction.
		deleteQuery := `DELETE FROM links WHERE key = $1 AND domain = $2;`
		if _, err := tx.ExecContext(ctx, deleteQuery, key, domain); err != nil {
			// Log the deletion error but still return nil to the user, as the link is invalid.
			slogger.Error("Failed to perform just-in-time deletion of invalid link", "key", key, "domain", domain, "error", err)
		} else if slogger != nil {
			slogger.Info("Performed just-in-time deletion of invalid link", "key", key, "domain", domain)
		}
		// We must commit the transaction to save the deletion.
		tx.Commit()
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

// getLinkDetails retrieves a link's full details from the database by its key and domain,
// regardless of its expiration or usage status. This is for admin editing purposes.
func getLinkDetails(ctx context.Context, key, domain string) (*Link, error) {
	link := &Link{}
	query := `
		SELECT key, domain, link_type, data, is_compressed, password_hash, times_allowed, times_used, expires_at, created_at
		FROM links
		WHERE key = $1 AND domain = $2;`

	err := db.QueryRowContext(ctx, query, key, domain).Scan(
		&link.Key,
		&link.Domain,
		&link.LinkType,
		&link.Data,
		&link.IsCompressed,
		&link.PasswordHash,
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
