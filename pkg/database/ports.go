package database

import (
	"database/sql"
)

// Port operations

// AddPorts inserts a slice of ports in a single transaction,
// skipping duplicates (INSERT OR IGNORE). Mirrors AddSubdomains pattern.
func AddPorts(scanID int64, items []Port) error {
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

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO ports (scan_id, host, port, protocol, service) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range items {
		if _, err := stmt.Exec(scanID, p.Host, p.Port, p.Protocol, p.Service); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func GetPorts(scanID int64) ([]Port, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT id, scan_id, host, port, protocol, service, created_at 
		 FROM ports WHERE scan_id = ? ORDER BY host, port`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []Port
	for rows.Next() {
		var p Port
		var service sql.NullString
		if err := rows.Scan(&p.ID, &p.ScanID, &p.Host, &p.Port, &p.Protocol, &service, &p.CreatedAt); err != nil {
			return nil, err
		}
		if service.Valid {
			p.Service = service.String
		}
		ports = append(ports, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ports, nil
}

// GetTotalPortsCount returns the total number of open ports across all scans
func GetTotalPortsCount() (int, error) {
	return getCount("SELECT COUNT(*) FROM ports")
}
