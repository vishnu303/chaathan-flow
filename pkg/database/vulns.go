package database

import (
	"database/sql"
)

// Vulnerability operations

// AddVulnerability inserts a single vulnerability record for a scan.
func AddVulnerability(scanID int64, rec VulnRecord) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	_, err := DB.Exec(
		`INSERT OR IGNORE INTO vulnerabilities (scan_id, host, url, template_id, name, severity, description, matcher, evidence)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, rec.Host, rec.URL, rec.TemplateID, rec.Name, rec.Severity, rec.Description, rec.Matcher, rec.Evidence,
	)
	return err
}

// AddVulnerabilitiesBatch inserts multiple vulnerabilities in a single transaction.
func AddVulnerabilitiesBatch(scanID int64, items []Vulnerability) (int, error) {
	if DB == nil {
		return 0, ErrDBNotInitialized
	}
	if len(items) == 0 {
		return 0, nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO vulnerabilities (scan_id, host, url, template_id, name, severity, description, matcher, evidence)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for _, v := range items {
		if _, execErr := stmt.Exec(scanID, v.Host, v.URL, v.TemplateID, v.Name, v.Severity, v.Description, v.Matcher, v.Evidence); execErr != nil {
			continue
		}
		count++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func GetVulnerabilities(scanID int64) ([]Vulnerability, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT id, scan_id, host, url, template_id, name, severity, description, matcher, evidence, created_at 
		 FROM vulnerabilities WHERE scan_id = ? ORDER BY 
		 CASE severity 
			WHEN 'critical' THEN 1 
			WHEN 'high' THEN 2 
			WHEN 'medium' THEN 3 
			WHEN 'low' THEN 4 
			ELSE 5 
		 END`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanVulnRows(rows)
}

func GetVulnerabilitiesBySeverity(scanID int64, severity string) ([]Vulnerability, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT id, scan_id, host, url, template_id, name, severity, description, matcher, evidence, created_at 
		 FROM vulnerabilities WHERE scan_id = ? AND severity = ?`,
		scanID, severity,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanVulnRows(rows)
}

// scanVulnRows extracts Vulnerability structs from a *sql.Rows cursor.
// Shared by GetVulnerabilities and GetVulnerabilitiesBySeverity.
func scanVulnRows(rows *sql.Rows) ([]Vulnerability, error) {
	var vulns []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var url, desc, matcher, evidence sql.NullString
		if err := rows.Scan(&v.ID, &v.ScanID, &v.Host, &url, &v.TemplateID, &v.Name, &v.Severity, &desc, &matcher, &evidence, &v.CreatedAt); err != nil {
			return nil, err
		}
		if url.Valid {
			v.URL = url.String
		}
		if desc.Valid {
			v.Description = desc.String
		}
		if matcher.Valid {
			v.Matcher = matcher.String
		}
		if evidence.Valid {
			v.Evidence = evidence.String
		}
		vulns = append(vulns, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return vulns, nil
}

func CountVulnerabilities(scanID int64) (map[string]int, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT severity, COUNT(*) FROM vulnerabilities WHERE scan_id = ? GROUP BY severity`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		counts[severity] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}

// GetTotalVulnerabilitiesCount returns the total number of vulnerabilities across all scans
func GetTotalVulnerabilitiesCount() (int, error) {
	return getCount("SELECT COUNT(*) FROM vulnerabilities")
}
