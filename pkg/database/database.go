package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB is the global database connection
var DB *sql.DB

// Models

type Scan struct {
	ID          int64     `json:"id"`
	Target      string    `json:"target"`
	Type        string    `json:"type"` // wildcard, company
	Status      string    `json:"status"` // running, completed, failed, cancelled
	StartedAt   time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	ResultDir   string    `json:"result_dir"`
	Config      string    `json:"config"` // JSON config used
}

type Subdomain struct {
	ID        int64     `json:"id"`
	ScanID    int64     `json:"scan_id"`
	Domain    string    `json:"domain"`
	Source    string    `json:"source"` // subfinder, assetfinder, etc.
	IsLive    bool      `json:"is_live"`
	IPAddress string    `json:"ip_address,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Port struct {
	ID        int64     `json:"id"`
	ScanID    int64     `json:"scan_id"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	Service   string    `json:"service,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type URL struct {
	ID          int64     `json:"id"`
	ScanID      int64     `json:"scan_id"`
	URL         string    `json:"url"`
	StatusCode  int       `json:"status_code,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	Title       string    `json:"title,omitempty"`
	Tech        string    `json:"tech,omitempty"` // JSON array of technologies
	Source      string    `json:"source"` // httpx, katana, waybackurls
	CreatedAt   time.Time `json:"created_at"`
}

type Vulnerability struct {
	ID          int64     `json:"id"`
	ScanID      int64     `json:"scan_id"`
	Host        string    `json:"host"`
	URL         string    `json:"url,omitempty"`
	TemplateID  string    `json:"template_id"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"` // info, low, medium, high, critical
	Description string    `json:"description,omitempty"`
	Matcher     string    `json:"matcher,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type Endpoint struct {
	ID        int64     `json:"id"`
	ScanID    int64     `json:"scan_id"`
	URL       string    `json:"url"`
	Method    string    `json:"method,omitempty"`
	Source    string    `json:"source"` // linkfinder, katana, gospider
	CreatedAt time.Time `json:"created_at"`
}

// Initialize opens or creates the database
func Initialize(dbPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create db directory: %w", err)
	}

	var err error
	DB, err = sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables
	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	return nil
}

func createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		type TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'running',
		started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME,
		result_dir TEXT,
		config TEXT
	);

	CREATE TABLE IF NOT EXISTS subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		domain TEXT NOT NULL,
		source TEXT,
		is_live BOOLEAN DEFAULT FALSE,
		ip_address TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id),
		UNIQUE(scan_id, domain)
	);

	CREATE TABLE IF NOT EXISTS ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT DEFAULT 'tcp',
		service TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id),
		UNIQUE(scan_id, host, port, protocol)
	);

	CREATE TABLE IF NOT EXISTS urls (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		url TEXT NOT NULL,
		status_code INTEGER,
		content_type TEXT,
		title TEXT,
		tech TEXT,
		source TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id),
		UNIQUE(scan_id, url)
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		host TEXT NOT NULL,
		url TEXT,
		template_id TEXT,
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		description TEXT,
		matcher TEXT,
		evidence TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id)
	);

	CREATE TABLE IF NOT EXISTS endpoints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		url TEXT NOT NULL,
		method TEXT,
		source TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id),
		UNIQUE(scan_id, url, method)
	);

	CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
	CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
	CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
	CREATE INDEX IF NOT EXISTS idx_urls_scan ON urls(scan_id);
	CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
	CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
	CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
	`

	_, err := DB.Exec(schema)
	return err
}

// Close closes the database connection
func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}

// Scan operations

func CreateScan(target, scanType, resultDir, config string) (*Scan, error) {
	result, err := DB.Exec(
		`INSERT INTO scans (target, type, result_dir, config, status) VALUES (?, ?, ?, ?, 'running')`,
		target, scanType, resultDir, config,
	)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()
	return &Scan{
		ID:        id,
		Target:    target,
		Type:      scanType,
		Status:    "running",
		StartedAt: time.Now(),
		ResultDir: resultDir,
		Config:    config,
	}, nil
}

func UpdateScanStatus(scanID int64, status string) error {
	var query string
	if status == "completed" || status == "failed" || status == "cancelled" {
		query = `UPDATE scans SET status = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`
	} else {
		query = `UPDATE scans SET status = ? WHERE id = ?`
	}
	_, err := DB.Exec(query, status, scanID)
	return err
}

func GetScan(scanID int64) (*Scan, error) {
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
	return scans, nil
}

func GetScansByTarget(target string) ([]Scan, error) {
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
	return scans, nil
}

// Subdomain operations

func AddSubdomain(scanID int64, domain, source string) error {
	_, err := DB.Exec(
		`INSERT OR IGNORE INTO subdomains (scan_id, domain, source) VALUES (?, ?, ?)`,
		scanID, domain, source,
	)
	return err
}

func AddSubdomains(scanID int64, domains []string, source string) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO subdomains (scan_id, domain, source) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, domain := range domains {
		if _, err := stmt.Exec(scanID, domain, source); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func UpdateSubdomainLive(scanID int64, domain string, isLive bool, ipAddress string) error {
	_, err := DB.Exec(
		`UPDATE subdomains SET is_live = ?, ip_address = ? WHERE scan_id = ? AND domain = ?`,
		isLive, ipAddress, scanID, domain,
	)
	return err
}

func GetSubdomains(scanID int64) ([]Subdomain, error) {
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
	return subs, nil
}

func GetLiveSubdomains(scanID int64) ([]Subdomain, error) {
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
	return subs, nil
}

func CountSubdomains(scanID int64) (total int, live int, err error) {
	err = DB.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE scan_id = ?`, scanID).Scan(&total)
	if err != nil {
		return
	}
	err = DB.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE scan_id = ? AND is_live = TRUE`, scanID).Scan(&live)
	return
}

// Port operations

func AddPort(scanID int64, host string, port int, protocol, service string) error {
	_, err := DB.Exec(
		`INSERT OR IGNORE INTO ports (scan_id, host, port, protocol, service) VALUES (?, ?, ?, ?, ?)`,
		scanID, host, port, protocol, service,
	)
	return err
}

func GetPorts(scanID int64) ([]Port, error) {
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
	return ports, nil
}

// URL operations

func AddURL(scanID int64, url string, statusCode int, contentType, title, tech, source string) error {
	_, err := DB.Exec(
		`INSERT OR IGNORE INTO urls (scan_id, url, status_code, content_type, title, tech, source) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		scanID, url, statusCode, contentType, title, tech, source,
	)
	return err
}

func GetURLs(scanID int64) ([]URL, error) {
	rows, err := DB.Query(
		`SELECT id, scan_id, url, status_code, content_type, title, tech, source, created_at 
		 FROM urls WHERE scan_id = ? ORDER BY url`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var urls []URL
	for rows.Next() {
		var u URL
		var statusCode sql.NullInt64
		var contentType, title, tech sql.NullString
		if err := rows.Scan(&u.ID, &u.ScanID, &u.URL, &statusCode, &contentType, &title, &tech, &u.Source, &u.CreatedAt); err != nil {
			return nil, err
		}
		if statusCode.Valid {
			u.StatusCode = int(statusCode.Int64)
		}
		if contentType.Valid {
			u.ContentType = contentType.String
		}
		if title.Valid {
			u.Title = title.String
		}
		if tech.Valid {
			u.Tech = tech.String
		}
		urls = append(urls, u)
	}
	return urls, nil
}

// Vulnerability operations

func AddVulnerability(scanID int64, host, url, templateID, name, severity, description, matcher, evidence string) error {
	_, err := DB.Exec(
		`INSERT INTO vulnerabilities (scan_id, host, url, template_id, name, severity, description, matcher, evidence) 
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, host, url, templateID, name, severity, description, matcher, evidence,
	)
	return err
}

func GetVulnerabilities(scanID int64) ([]Vulnerability, error) {
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
	return vulns, nil
}

func GetVulnerabilitiesBySeverity(scanID int64, severity string) ([]Vulnerability, error) {
	rows, err := DB.Query(
		`SELECT id, scan_id, host, url, template_id, name, severity, description, matcher, evidence, created_at 
		 FROM vulnerabilities WHERE scan_id = ? AND severity = ?`,
		scanID, severity,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
	return vulns, nil
}

func CountVulnerabilities(scanID int64) (map[string]int, error) {
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
	return counts, nil
}

// Endpoint operations

func AddEndpoint(scanID int64, url, method, source string) error {
	_, err := DB.Exec(
		`INSERT OR IGNORE INTO endpoints (scan_id, url, method, source) VALUES (?, ?, ?, ?)`,
		scanID, url, method, source,
	)
	return err
}

func GetEndpoints(scanID int64) ([]Endpoint, error) {
	rows, err := DB.Query(
		`SELECT id, scan_id, url, method, source, created_at 
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
		var method sql.NullString
		if err := rows.Scan(&e.ID, &e.ScanID, &e.URL, &method, &e.Source, &e.CreatedAt); err != nil {
			return nil, err
		}
		if method.Valid {
			e.Method = method.String
		}
		endpoints = append(endpoints, e)
	}
	return endpoints, nil
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
	stats := &ScanStats{}

	// Subdomains
	var err error
	stats.TotalSubdomains, stats.LiveSubdomains, err = CountSubdomains(scanID)
	if err != nil {
		return nil, err
	}

	// Ports
	if err := DB.QueryRow(`SELECT COUNT(*) FROM ports WHERE scan_id = ?`, scanID).Scan(&stats.TotalPorts); err != nil {
		return nil, err
	}

	// URLs
	if err := DB.QueryRow(`SELECT COUNT(*) FROM urls WHERE scan_id = ?`, scanID).Scan(&stats.TotalURLs); err != nil {
		return nil, err
	}

	// Endpoints
	if err := DB.QueryRow(`SELECT COUNT(*) FROM endpoints WHERE scan_id = ?`, scanID).Scan(&stats.TotalEndpoints); err != nil {
		return nil, err
	}

	// Vulnerabilities
	stats.Vulnerabilities, err = CountVulnerabilities(scanID)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// GetDefaultDBPath returns the default database path
func GetDefaultDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".chaathan", "chaathan.db")
}

// DeleteScan deletes a scan and all its related data
func DeleteScan(scanID int64) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete from all related tables
	tables := []string{"endpoints", "vulnerabilities", "urls", "ports", "subdomains"}
	for _, table := range tables {
		if _, err := tx.Exec(fmt.Sprintf("DELETE FROM %s WHERE scan_id = ?", table), scanID); err != nil {
			return fmt.Errorf("failed to delete from %s: %w", table, err)
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
	// First get all scan IDs for this target
	rows, err := DB.Query("SELECT id FROM scans WHERE target = ?", target)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var scanIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		scanIDs = append(scanIDs, id)
	}

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

// DeleteAllScansForTarget deletes all data for a target (alias for DeleteScansByTarget)
func DeleteAllScansForTarget(target string) (deleted int, err error) {
	return DeleteScansByTarget(target)
}

// GetAllTargets returns a list of all unique targets in the database
func GetAllTargets() ([]string, error) {
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
	return targets, nil
}

// GetTargetStats returns statistics for a specific target across all scans
func GetTargetStats(target string) (map[string]int, error) {
	stats := make(map[string]int)

	// Count scans
	var scanCount int
	if err := DB.QueryRow("SELECT COUNT(*) FROM scans WHERE target = ?", target).Scan(&scanCount); err != nil {
		return nil, err
	}
	stats["scans"] = scanCount

	// Get scan IDs for this target
	rows, err := DB.Query("SELECT id FROM scans WHERE target = ?", target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scanIDs []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		scanIDs = append(scanIDs, id)
	}

	if len(scanIDs) == 0 {
		return stats, nil
	}

	// Build IN clause
	inClause := "("
	for i := range scanIDs {
		if i > 0 {
			inClause += ","
		}
		inClause += fmt.Sprintf("%d", scanIDs[i])
	}
	inClause += ")"

	// Count subdomains
	var subCount int
	DB.QueryRow(fmt.Sprintf("SELECT COUNT(DISTINCT domain) FROM subdomains WHERE scan_id IN %s", inClause)).Scan(&subCount)
	stats["subdomains"] = subCount

	// Count ports
	var portCount int
	DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM ports WHERE scan_id IN %s", inClause)).Scan(&portCount)
	stats["ports"] = portCount

	// Count URLs
	var urlCount int
	DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM urls WHERE scan_id IN %s", inClause)).Scan(&urlCount)
	stats["urls"] = urlCount

	// Count vulnerabilities
	var vulnCount int
	DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM vulnerabilities WHERE scan_id IN %s", inClause)).Scan(&vulnCount)
	stats["vulnerabilities"] = vulnCount

	// Count endpoints
	var endpointCount int
	DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM endpoints WHERE scan_id IN %s", inClause)).Scan(&endpointCount)
	stats["endpoints"] = endpointCount

	return stats, nil
}

// PurgeOldScans deletes scans older than the specified number of days
func PurgeOldScans(daysOld int) (int, error) {
	// Get scans older than specified days
	rows, err := DB.Query(
		"SELECT id FROM scans WHERE started_at < datetime('now', ? || ' days')",
		fmt.Sprintf("-%d", daysOld),
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var scanIDs []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		scanIDs = append(scanIDs, id)
	}

	// Delete each scan
	for _, scanID := range scanIDs {
		if err := DeleteScan(scanID); err != nil {
			return 0, err
		}
	}

	return len(scanIDs), nil
}

// VacuumDatabase runs VACUUM to reclaim space after deletions
func VacuumDatabase() error {
	_, err := DB.Exec("VACUUM")
	return err
}
