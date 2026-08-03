package database

import (
	"database/sql"
	"strings"
)

// Subdomain operations

func AddSubdomains(scanID int64, domains []string, source string) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO subdomains (scan_id, domain, source) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if _, err := stmt.Exec(scanID, domain, source); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// PurgeUnconsolidatedSubdomains deletes any subdomains for scanID that are not present in validDomains.
func PurgeUnconsolidatedSubdomains(scanID int64, validDomains []string) (int64, error) {
	if DB == nil {
		return 0, ErrDBNotInitialized
	}
	if len(validDomains) == 0 {
		res, err := DB.Exec(`DELETE FROM subdomains WHERE scan_id = ?`, scanID)
		if err != nil {
			return 0, err
		}
		rows, _ := res.RowsAffected()
		return rows, nil
	}

	tx, err := DB.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`CREATE TEMP TABLE IF NOT EXISTS temp_valid_subs (domain TEXT PRIMARY KEY)`)
	if err != nil {
		return 0, err
	}
	_, err = tx.Exec(`DELETE FROM temp_valid_subs`)
	if err != nil {
		return 0, err
	}

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO temp_valid_subs (domain) VALUES (?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, domain := range validDomains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain != "" {
			if _, err := stmt.Exec(domain); err != nil {
				return 0, err
			}
		}
	}

	res, err := tx.Exec(`DELETE FROM subdomains WHERE scan_id = ? AND domain NOT IN (SELECT domain FROM temp_valid_subs)`, scanID)
	if err != nil {
		return 0, err
	}
	rowsAffected, _ := res.RowsAffected()

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return rowsAffected, nil
}

func UpdateSubdomainLive(scanID int64, domain string, isLive bool, ipAddress string) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	_, err := DB.Exec(
		`UPDATE subdomains SET is_live = ?, ip_address = ? WHERE scan_id = ? AND domain = ?`,
		isLive, ipAddress, scanID, domain,
	)
	return err
}

// UpdateSubdomainsLiveBulk marks the given domains as live for a scan in a single transaction.
func UpdateSubdomainsLiveBulk(scanID int64, domains []string) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	if len(domains) == 0 {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`UPDATE subdomains SET is_live = TRUE WHERE scan_id = ? AND domain = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if _, err := stmt.Exec(scanID, domain); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func GetSubdomains(scanID int64) ([]Subdomain, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT id, scan_id, domain, source, is_live, ip_address, created_at 
		 FROM subdomains WHERE scan_id = ? ORDER BY domain`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []Subdomain
	for rows.Next() {
		var s Subdomain
		var ip sql.NullString
		if err := rows.Scan(&s.ID, &s.ScanID, &s.Domain, &s.Source, &s.IsLive, &ip, &s.CreatedAt); err != nil {
			return nil, err
		}
		if ip.Valid {
			s.IPAddress = ip.String
		}
		subs = append(subs, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return subs, nil
}

func GetLiveSubdomains(scanID int64) ([]Subdomain, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT id, scan_id, domain, source, is_live, ip_address, created_at 
		 FROM subdomains WHERE scan_id = ? AND is_live = TRUE ORDER BY domain`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []Subdomain
	for rows.Next() {
		var s Subdomain
		var ip sql.NullString
		if err := rows.Scan(&s.ID, &s.ScanID, &s.Domain, &s.Source, &s.IsLive, &ip, &s.CreatedAt); err != nil {
			return nil, err
		}
		if ip.Valid {
			s.IPAddress = ip.String
		}
		subs = append(subs, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return subs, nil
}

func CountSubdomains(scanID int64) (total int, live int, err error) {
	if DB == nil {
		return 0, 0, ErrDBNotInitialized
	}
	// Single round-trip: COUNT(*) for total, conditional SUM for live hosts.
	// COALESCE handles the NULL SUM that SQLite returns when no rows match.
	err = DB.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN is_live THEN 1 ELSE 0 END), 0)
		 FROM subdomains WHERE scan_id = ?`,
		scanID,
	).Scan(&total, &live)
	return
}

// GetTotalSubdomainsCount returns the total number of unique subdomains across all scans
func GetTotalSubdomainsCount() (int, error) {
	return getCount("SELECT COUNT(*) FROM subdomains")
}
