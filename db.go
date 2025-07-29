package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver for database/sql
)

var db *sql.DB // Global database connection pool

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
		key TEXT PRIMARY KEY,
		domain TEXT NOT NULL,
		link_type TEXT NOT NULL,
		data BYTEA NOT NULL,
		is_compressed BOOLEAN NOT NULL,
		times_allowed INT NOT NULL,
		times_used INT DEFAULT 0 NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
	);`

	_, err = db.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	return nil
}

// createLinkInDB inserts a new link record into the database.
func createLinkInDB(ctx context.Context, link Link) error {
	query := `
		INSERT INTO links (key, domain, link_type, data, is_compressed, times_allowed, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7);`

	_, err := db.ExecContext(ctx, query, link.Key, link.Domain, link.LinkType, link.Data, link.IsCompressed, link.TimesAllowed, link.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to insert link into database: %w", err)
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
	// The query checks for validity (not expired, not overused) and locks the row for updating.
	querySelect := `
		SELECT key, domain, link_type, data, is_compressed, times_allowed, times_used, expires_at, created_at
		FROM links
		WHERE key = $1 AND domain = $2 AND expires_at > NOW() AND (times_allowed = 0 OR times_used < times_allowed)
		FOR UPDATE;`

	err = tx.QueryRowContext(ctx, querySelect, key, domain).Scan(
		&link.Key,
		&link.Domain,
		&link.LinkType,
		&link.Data,
		&link.IsCompressed,
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

	// Increment the usage count for the retrieved link.
	queryUpdate := `UPDATE links SET times_used = times_used + 1 WHERE key = $1;`
	if _, err = tx.ExecContext(ctx, queryUpdate, key); err != nil {
		return nil, fmt.Errorf("failed to update link usage: %w", err)
	}

	// Commit the transaction to save the changes.
	return link, tx.Commit()
}
