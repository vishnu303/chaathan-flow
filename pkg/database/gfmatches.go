package database

import (
	"fmt"
	"strings"
)

// ─────────────────────────────────────────────────────────────
// GF Match persistence — stores which URLs matched which gf patterns
//
// NOTE: The gf_matches table is currently write-dead (no production code path
// populates it after the JS/param pipeline moved in-memory/x8). The read side
// (GetGFMatchesByScan) and ROI scoring still consult it, so it contributes zero
// signal until a writer is reintroduced. The table and schema are kept for
// backwards compatibility with existing databases.
// ─────────────────────────────────────────────────────────────

// GFMatch holds URL and gf pattern match details.
type GFMatch struct {
	URL     string
	Pattern string
	Status  string // confirmed | invalid | unverified
}

// InsertGFMatches stores gf pattern matches for a scan.
// It uses INSERT OR IGNORE to honor the existing UNIQUE(scan_id, url, pattern) constraint.
func InsertGFMatches(scanID int64, matches []GFMatch) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	if len(matches) == 0 {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO gf_matches (scan_id, url, pattern, confirmed) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, m := range matches {
		urlStr := strings.TrimSpace(m.URL)
		patternStr := strings.TrimSpace(m.Pattern)
		if urlStr == "" || patternStr == "" {
			continue
		}
		status := m.Status
		if status == "" {
			status = "unverified"
		}
		if _, err := stmt.Exec(scanID, urlStr, patternStr, status); err != nil {
			return fmt.Errorf("failed to insert gf match for %q pattern %q: %w", urlStr, patternStr, err)
		}
	}
	return tx.Commit()
}

// GFMatchResult holds a pattern match with its validation status.
type GFMatchResult struct {
	Pattern string
	Status  string // confirmed | invalid | unverified
}

// GetGFMatchesByScan returns all gf pattern matches for a scan, grouped by URL.
// The returned map keys are raw URLs; the values are slices of GFMatchResult
// containing pattern names and validation status.
func GetGFMatchesByScan(scanID int64) (map[string][]GFMatchResult, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(`SELECT url, pattern, confirmed FROM gf_matches WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]GFMatchResult)
	for rows.Next() {
		var u, pattern, status string
		if err := rows.Scan(&u, &pattern, &status); err != nil {
			continue
		}
		result[u] = append(result[u], GFMatchResult{Pattern: pattern, Status: status})
	}
	return result, rows.Err()
}

// ─────────────────────────────────────────────────────────────
// JS Secret host flagging
// ─────────────────────────────────────────────────────────────

// MarkHostsJSSecrets flags the given hosts as having exposed secrets in their
// JavaScript files. If a host_metadata row doesn't exist yet, one is created.
func MarkHostsJSSecrets(scanID int64, hosts []string) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	if len(hosts) == 0 {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, host := range hosts {
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" {
			continue
		}
		// Ensure a row exists, then update the flag
		if _, err := tx.Exec(`INSERT OR IGNORE INTO host_metadata (scan_id, host) VALUES (?, ?)`, scanID, host); err != nil {
			return fmt.Errorf("failed to insert host_metadata for %q: %w", host, err)
		}
		if _, err := tx.Exec(`UPDATE host_metadata SET has_js_secrets = TRUE, updated_at = CURRENT_TIMESTAMP WHERE scan_id = ? AND host = ?`, scanID, host); err != nil {
			return fmt.Errorf("failed to flag JS secrets for %q: %w", host, err)
		}
	}
	return tx.Commit()
}
