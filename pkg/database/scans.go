package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Scan operations

func CreateScan(target, scanType, resultDir, config string) (*Scan, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	result, err := DB.Exec(
		`INSERT INTO scans (target, type, result_dir, config, status) VALUES (?, ?, ?, ?, ?)`,
		target, scanType, resultDir, config, StatusRunning,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get new scan ID: %w", err)
	}
	return &Scan{
		ID:        id,
		Target:    target,
		Type:      scanType,
		Status:    StatusRunning,
		StartedAt: time.Now(),
		ResultDir: resultDir,
		Config:    config,
	}, nil
}

func UpdateScanStatus(scanID int64, status string) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	var query string
	if status == StatusCompleted || status == StatusFailed || status == StatusCancelled {
		query = `UPDATE scans SET status = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`
	} else {
		query = `UPDATE scans SET status = ? WHERE id = ?`
	}
	_, err := DB.Exec(query, status, scanID)
	return err
}

func GetScan(scanID int64) (*Scan, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	scan := &Scan{}
	var completedAt sql.NullTime
	err := DB.QueryRow(
		`SELECT id, target, type, status, started_at, completed_at, result_dir, config FROM scans WHERE id = ?`,
		scanID,
	).Scan(&scan.ID, &scan.Target, &scan.Type, &scan.Status, &scan.StartedAt, &completedAt, &scan.ResultDir, &scan.Config)
	if err != nil {
		return nil, err
	}
	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}
	return scan, nil
}

func GetRecentScans(limit int) ([]Scan, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT id, target, type, status, started_at, completed_at, result_dir, config 
		 FROM scans ORDER BY started_at DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var s Scan
		var completedAt sql.NullTime
		if err := rows.Scan(&s.ID, &s.Target, &s.Type, &s.Status, &s.StartedAt, &completedAt, &s.ResultDir, &s.Config); err != nil {
			return nil, err
		}
		if completedAt.Valid {
			s.CompletedAt = &completedAt.Time
		}
		scans = append(scans, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return scans, nil
}

func GetScansByTarget(target string) ([]Scan, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT id, target, type, status, started_at, completed_at, result_dir, config 
		 FROM scans WHERE target = ? ORDER BY started_at DESC`,
		target,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var s Scan
		var completedAt sql.NullTime
		if err := rows.Scan(&s.ID, &s.Target, &s.Type, &s.Status, &s.StartedAt, &completedAt, &s.ResultDir, &s.Config); err != nil {
			return nil, err
		}
		if completedAt.Valid {
			s.CompletedAt = &completedAt.Time
		}
		scans = append(scans, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return scans, nil
}

// Stats

type ScanStats struct {
	TotalSubdomains int            `json:"total_subdomains"`
	LiveSubdomains  int            `json:"live_subdomains"`
	TotalPorts      int            `json:"total_ports"`
	TotalURLs       int            `json:"total_urls"`
	TotalEndpoints  int            `json:"total_endpoints"`
	Vulnerabilities map[string]int `json:"vulnerabilities"`
}

func GetScanStats(scanID int64) (*ScanStats, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	stats := &ScanStats{}

	// One round-trip for all numeric counts via correlated subqueries.
	err := DB.QueryRow(
		`SELECT
			(SELECT COUNT(*)                                                FROM subdomains WHERE scan_id = ?),
			(SELECT COALESCE(SUM(CASE WHEN is_live THEN 1 ELSE 0 END), 0) FROM subdomains WHERE scan_id = ?),
			(SELECT COUNT(*) FROM ports     WHERE scan_id = ?),
			(SELECT COUNT(*) FROM urls      WHERE scan_id = ?),
			(SELECT COUNT(*) FROM endpoints WHERE scan_id = ?)`,
		scanID, scanID, scanID, scanID, scanID,
	).Scan(&stats.TotalSubdomains, &stats.LiveSubdomains, &stats.TotalPorts, &stats.TotalURLs, &stats.TotalEndpoints)
	if err != nil {
		return nil, err
	}

	// Vulnerabilities need GROUP BY — one additional round-trip.
	stats.Vulnerabilities, err = CountVulnerabilities(scanID)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// DeleteScan deletes a scan and all its related data
func DeleteScan(scanID int64) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Delete from all related tables (order matters: child rows before parent).
	// Each statement is explicit — no string interpolation into SQL.
	deletes := []string{
		"DELETE FROM gf_matches WHERE scan_id = ?",
		"DELETE FROM host_metadata WHERE scan_id = ?",
		"DELETE FROM url_metadata WHERE scan_id = ?",
		"DELETE FROM endpoints WHERE scan_id = ?",
		"DELETE FROM vulnerabilities WHERE scan_id = ?",
		"DELETE FROM urls WHERE scan_id = ?",
		"DELETE FROM ports WHERE scan_id = ?",
		"DELETE FROM subdomains WHERE scan_id = ?",
	}
	for _, stmt := range deletes {
		if _, err := tx.Exec(stmt, scanID); err != nil {
			return fmt.Errorf("failed to delete scan data: %w", err)
		}
	}

	// Delete the scan itself
	if _, err := tx.Exec("DELETE FROM scans WHERE id = ?", scanID); err != nil {
		return fmt.Errorf("failed to delete scan: %w", err)
	}

	return tx.Commit()
}

// DeleteScansByTarget deletes all scans and related data for a specific target
func DeleteScansByTarget(target string) (int, error) {
	if DB == nil {
		return 0, ErrDBNotInitialized
	}
	// Collect IDs first, then close the cursor before starting destructive writes.
	rows, err := DB.Query("SELECT id FROM scans WHERE target = ?", target)
	if err != nil {
		return 0, err
	}

	var scanIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		scanIDs = append(scanIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close() // explicitly closed before delete transactions begin

	if len(scanIDs) == 0 {
		return 0, nil
	}

	// Delete each scan
	for _, scanID := range scanIDs {
		if err := DeleteScan(scanID); err != nil {
			return 0, fmt.Errorf("failed to delete scan %d: %w", scanID, err)
		}
	}

	return len(scanIDs), nil
}

// GetAllTargets returns a list of all unique targets in the database
func GetAllTargets() ([]string, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query("SELECT DISTINCT target FROM scans ORDER BY target")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []string
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

// GetTargetStats returns statistics for a specific target across all scans
func GetTargetStats(target string) (map[string]int, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	stats := make(map[string]int)

	// Count scans
	var scanCount int
	if err := DB.QueryRow("SELECT COUNT(*) FROM scans WHERE target = ?", target).Scan(&scanCount); err != nil {
		return nil, err
	}
	stats["scans"] = scanCount

	// Collect scan IDs for this target, then close the cursor.
	rows, err := DB.Query("SELECT id FROM scans WHERE target = ?", target)
	if err != nil {
		return nil, err
	}

	var scanIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		scanIDs = append(scanIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	if len(scanIDs) == 0 {
		return stats, nil
	}

	// Build a parameterised IN clause: (?, ?, ...)
	placeholders := strings.Repeat("?,", len(scanIDs))
	placeholders = "(" + placeholders[:len(placeholders)-1] + ")"

	// Convert []int64 to []interface{} for variadic Scan.
	args := make([]interface{}, len(scanIDs))
	for i, id := range scanIDs {
		args[i] = id
	}

	countQuery := func(q string) (int, error) {
		var n int
		err := DB.QueryRow(q+placeholders, args...).Scan(&n)
		return n, err
	}

	var n int

	if n, err = countQuery("SELECT COUNT(DISTINCT domain) FROM subdomains WHERE scan_id IN "); err != nil {
		return nil, fmt.Errorf("subdomains count: %w", err)
	}
	stats["subdomains"] = n

	if n, err = countQuery("SELECT COUNT(*) FROM ports WHERE scan_id IN "); err != nil {
		return nil, fmt.Errorf("ports count: %w", err)
	}
	stats["ports"] = n

	if n, err = countQuery("SELECT COUNT(*) FROM urls WHERE scan_id IN "); err != nil {
		return nil, fmt.Errorf("urls count: %w", err)
	}
	stats["urls"] = n

	if n, err = countQuery("SELECT COUNT(*) FROM vulnerabilities WHERE scan_id IN "); err != nil {
		return nil, fmt.Errorf("vulnerabilities count: %w", err)
	}
	stats["vulnerabilities"] = n

	if n, err = countQuery("SELECT COUNT(*) FROM endpoints WHERE scan_id IN "); err != nil {
		return nil, fmt.Errorf("endpoints count: %w", err)
	}
	stats["endpoints"] = n

	return stats, nil
}

// PurgeOldScans deletes scans older than the specified number of days
func PurgeOldScans(daysOld int) (int, error) {
	if DB == nil {
		return 0, ErrDBNotInitialized
	}
	// Collect IDs first, then close the cursor before starting destructive writes.
	rows, err := DB.Query(
		"SELECT id FROM scans WHERE started_at < datetime('now', ? || ' days')",
		fmt.Sprintf("-%d", daysOld),
	)
	if err != nil {
		return 0, err
	}

	var scanIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		scanIDs = append(scanIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close() // explicitly closed before delete transactions begin

	// Delete each scan
	for _, scanID := range scanIDs {
		if err := DeleteScan(scanID); err != nil {
			return 0, err
		}
	}

	return len(scanIDs), nil
}

// GetTotalScansCount returns the total number of scans
func GetTotalScansCount() (int, error) {
	return getCount("SELECT COUNT(*) FROM scans")
}
