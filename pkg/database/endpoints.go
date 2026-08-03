package database

import (
	"database/sql"
	neturl "net/url"
	"strings"
)

// Endpoint operations

// AddEndpoints inserts a slice of endpoints in a single transaction,
// skipping duplicates (INSERT OR IGNORE). Mirrors AddSubdomains pattern.
func AddEndpoints(scanID int64, items []Endpoint) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	if len(items) == 0 {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO endpoints (scan_id, url, host, method, source) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range items {
		var host string
		if parsed, err := neturl.Parse(strings.TrimSpace(e.URL)); err == nil {
			host = strings.ToLower(parsed.Hostname())
		}
		if host == "" {
			cleaned := e.URL
			if !strings.Contains(cleaned, "://") {
				cleaned = "https://" + cleaned
			}
			if parsed, err := neturl.Parse(cleaned); err == nil {
				host = strings.ToLower(parsed.Hostname())
			}
		}

		if _, err := stmt.Exec(scanID, e.URL, host, e.Method, e.Source); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func GetEndpoints(scanID int64) ([]Endpoint, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT id, scan_id, url, host, method, source, created_at 
		 FROM endpoints WHERE scan_id = ? ORDER BY url`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var endpoints []Endpoint
	for rows.Next() {
		var e Endpoint
		var hostNull, methodNull sql.NullString
		if err := rows.Scan(&e.ID, &e.ScanID, &e.URL, &hostNull, &methodNull, &e.Source, &e.CreatedAt); err != nil {
			return nil, err
		}
		if hostNull.Valid {
			e.Host = hostNull.String
		}
		if methodNull.Valid {
			e.Method = methodNull.String
		}
		endpoints = append(endpoints, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return endpoints, nil
}
