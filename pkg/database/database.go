package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/vishnu303/chaathan/pkg/paths"
)

// DB is the global database connection
var DB *sql.DB

// Models

type Scan struct {
	ID          int64      `json:"id"`
	Target      string     `json:"target"`
	Type        string     `json:"type"`   // wildcard, company
	Status      string     `json:"status"` // running, completed, failed, cancelled
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	ResultDir   string     `json:"result_dir"`
	Config      string     `json:"config"` // JSON config used
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
	Source      string    `json:"source"`         // httpx, katana, waybackurls
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
	Source    string    `json:"source"` // golinkfinder, katana, gospider, etc.
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

	// SQLite is single-writer. Capping to one open connection prevents
	// "database is locked" errors when concurrent goroutines (parallel scan
	// steps) all issue writes at the same time. WAL handles concurrent reads fine.
	DB.SetMaxOpenConns(1)
	DB.SetMaxIdleConns(1)

	// Create tables
	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Best-effort schema migrations — won't fail init if data constraints
	// can't be met on an existing database (e.g. pre-existing duplicates).
	runMigrations()

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

	CREATE TABLE IF NOT EXISTS host_metadata (
		scan_id INTEGER NOT NULL,
		host TEXT NOT NULL,
		base_url TEXT,
		headers_json TEXT,
		has_csp BOOLEAN DEFAULT FALSE,
		has_cache_headers BOOLEAN DEFAULT FALSE,
		login_surface BOOLEAN DEFAULT FALSE,
		response_bytes INTEGER DEFAULT 0,
		ssl_expired BOOLEAN DEFAULT FALSE,
		ssl_self_signed BOOLEAN DEFAULT FALSE,
		ssl_mismatch BOOLEAN DEFAULT FALSE,
		weak_tls BOOLEAN DEFAULT FALSE,
		has_js_secrets BOOLEAN DEFAULT FALSE,
		cors_wildcard BOOLEAN DEFAULT FALSE,
		has_insecure_cookies BOOLEAN DEFAULT FALSE,
		has_session_cookie BOOLEAN DEFAULT FALSE,
		has_dangerous_methods BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (scan_id, host),
		FOREIGN KEY (scan_id) REFERENCES scans(id)
	);

	CREATE TABLE IF NOT EXISTS url_metadata (
		scan_id INTEGER NOT NULL,
		url TEXT NOT NULL,
		host TEXT,
		headers_json TEXT,
		has_csp BOOLEAN DEFAULT FALSE,
		has_cache_headers BOOLEAN DEFAULT FALSE,
		login_surface BOOLEAN DEFAULT FALSE,
		response_bytes INTEGER DEFAULT 0,
		form_count INTEGER DEFAULT 0,
		has_file_upload BOOLEAN DEFAULT FALSE,
		hidden_input_count INTEGER DEFAULT 0,
		param_count INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (scan_id, url),
		FOREIGN KEY (scan_id) REFERENCES scans(id)
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

	CREATE TABLE IF NOT EXISTS gf_matches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		url TEXT NOT NULL,
		pattern TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id),
		UNIQUE(scan_id, url, pattern)
	);

	CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
	CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
	CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
	CREATE INDEX IF NOT EXISTS idx_urls_scan ON urls(scan_id);
	CREATE INDEX IF NOT EXISTS idx_host_metadata_scan ON host_metadata(scan_id);
	CREATE INDEX IF NOT EXISTS idx_url_metadata_scan ON url_metadata(scan_id);
	CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
	CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
	CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
	CREATE INDEX IF NOT EXISTS idx_gf_matches_scan ON gf_matches(scan_id);
	CREATE INDEX IF NOT EXISTS idx_scans_target   ON scans(target);
	`

	_, err := DB.Exec(schema)
	return err
}

// runMigrations applies incremental schema improvements that are safe to skip
// on existing databases where constraints cannot be satisfied (e.g. prior
// duplicate vulnerabilities). All errors are intentionally swallowed so that
// existing installs keep working without a hard migration step.
func runMigrations() {
	// Unique compound index on vulnerabilities — prevents duplicates when a scan
	// is resumed or the same nuclei template fires on the same host+URL twice.
	// IFNULL() normalises NULL → '' so empty strings and NULLs compare equal.
	_, _ = DB.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_vulns_unique
		ON vulnerabilities(scan_id, host, IFNULL(template_id, ''), IFNULL(url, ''))`)

	// Game-changer columns — safe to fail on fresh installs where columns already exist.
	_, _ = DB.Exec(`ALTER TABLE host_metadata ADD COLUMN has_js_secrets BOOLEAN DEFAULT FALSE`)
	_, _ = DB.Exec(`ALTER TABLE url_metadata ADD COLUMN form_count INTEGER DEFAULT 0`)
	_, _ = DB.Exec(`ALTER TABLE url_metadata ADD COLUMN has_file_upload BOOLEAN DEFAULT FALSE`)
	_, _ = DB.Exec(`ALTER TABLE url_metadata ADD COLUMN hidden_input_count INTEGER DEFAULT 0`)

	// Phase 4 columns — CORS, cookie security, dangerous methods, parameter counts.
	_, _ = DB.Exec(`ALTER TABLE host_metadata ADD COLUMN cors_wildcard BOOLEAN DEFAULT FALSE`)
	_, _ = DB.Exec(`ALTER TABLE host_metadata ADD COLUMN has_insecure_cookies BOOLEAN DEFAULT FALSE`)
	_, _ = DB.Exec(`ALTER TABLE host_metadata ADD COLUMN has_session_cookie BOOLEAN DEFAULT FALSE`)
	_, _ = DB.Exec(`ALTER TABLE host_metadata ADD COLUMN has_dangerous_methods BOOLEAN DEFAULT FALSE`)
	_, _ = DB.Exec(`ALTER TABLE url_metadata ADD COLUMN arjun_param_count INTEGER DEFAULT 0`)
	_, _ = DB.Exec(`ALTER TABLE url_metadata ADD COLUMN param_count INTEGER DEFAULT 0`)
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
	if err := rows.Err(); err != nil {
		return nil, err
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return scans, nil
}

// Subdomain operations

func AddSubdomain(scanID int64, domain, source string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
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
		domain = strings.ToLower(strings.TrimSpace(domain))
		if _, err := stmt.Exec(scanID, domain, source); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func UpdateSubdomainLive(scanID int64, domain string, isLive bool, ipAddress string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
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
	if err := rows.Err(); err != nil {
		return nil, err
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return subs, nil
}

func CountSubdomains(scanID int64) (total int, live int, err error) {
	// Single round-trip: COUNT(*) for total, conditional SUM for live hosts.
	// COALESCE handles the NULL SUM that SQLite returns when no rows match.
	err = DB.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN is_live THEN 1 ELSE 0 END), 0)
		 FROM subdomains WHERE scan_id = ?`,
		scanID,
	).Scan(&total, &live)
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

// AddPorts inserts a slice of ports in a single transaction,
// skipping duplicates (INSERT OR IGNORE). Mirrors AddSubdomains pattern.
func AddPorts(scanID int64, items []Port) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

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

// URL operations

func AddURL(scanID int64, url string, statusCode int, contentType, title, tech, source string) error {
	_, err := DB.Exec(
		`INSERT INTO urls (scan_id, url, status_code, content_type, title, tech, source) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, url) DO UPDATE SET
			source = CASE
				WHEN (',' || urls.source || ',') LIKE ('%,' || ? || ',%') THEN urls.source
				ELSE urls.source || ',' || ?
			END,
			status_code = CASE WHEN ? > 0 AND urls.status_code = 0 THEN ? ELSE urls.status_code END,
			content_type = CASE WHEN ? != '' AND urls.content_type = '' THEN ? ELSE urls.content_type END,
			title = CASE WHEN ? != '' AND urls.title = '' THEN ? ELSE urls.title END,
			tech = CASE WHEN ? != '' AND urls.tech = '' THEN ? ELSE urls.tech END`,
		scanID, url, statusCode, contentType, title, tech, source,
		source, source,
		statusCode, statusCode,
		contentType, contentType,
		title, title,
		tech, tech,
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}

// Vulnerability operations

func AddVulnerability(scanID int64, host, url, templateID, name, severity, description, matcher, evidence string) error {
	_, err := DB.Exec(
		`INSERT OR IGNORE INTO vulnerabilities (scan_id, host, url, template_id, name, severity, description, matcher, evidence)
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
	return scanVulnRows(rows)
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

// Endpoint operations

func AddEndpoint(scanID int64, url, method, source string) error {
	_, err := DB.Exec(
		`INSERT OR IGNORE INTO endpoints (scan_id, url, method, source) VALUES (?, ?, ?, ?)`,
		scanID, url, method, source,
	)
	return err
}

// AddEndpoints inserts a slice of endpoints in a single transaction,
// skipping duplicates (INSERT OR IGNORE). Mirrors AddSubdomains pattern.
func AddEndpoints(scanID int64, items []Endpoint) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO endpoints (scan_id, url, method, source) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range items {
		if _, err := stmt.Exec(scanID, e.URL, e.Method, e.Source); err != nil {
			return err
		}
	}
	return tx.Commit()
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
	if err := rows.Err(); err != nil {
		return nil, err
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

// GetDefaultDBPath returns the default database path
func GetDefaultDBPath() string {
	return paths.DatabasePath()
}

// DeleteScan deletes a scan and all its related data
func DeleteScan(scanID int64) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

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

// VacuumDatabase runs VACUUM to reclaim space after deletions
func VacuumDatabase() error {
	_, err := DB.Exec("VACUUM")
	return err
}

// --- Aggregate Count Functions (for status dashboard) ---

func getCount(query string) (int, error) {
	if DB == nil {
		return 0, nil
	}
	var count int
	err := DB.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetTotalScansCount returns the total number of scans
func GetTotalScansCount() (int, error) {
	return getCount("SELECT COUNT(*) FROM scans")
}

// GetTotalSubdomainsCount returns the total number of unique subdomains across all scans
func GetTotalSubdomainsCount() (int, error) {
	return getCount("SELECT COUNT(*) FROM subdomains")
}

// GetTotalVulnerabilitiesCount returns the total number of vulnerabilities across all scans
func GetTotalVulnerabilitiesCount() (int, error) {
	return getCount("SELECT COUNT(*) FROM vulnerabilities")
}

// GetTotalPortsCount returns the total number of open ports across all scans
func GetTotalPortsCount() (int, error) {
	return getCount("SELECT COUNT(*) FROM ports")
}

// ─────────────────────────────────────────────────────────────
// GF Match persistence — stores which URLs matched which gf patterns
//
// NOTE: The gf_matches table is currently write-dead (no production code path
// populates it after the JS/param pipeline moved in-memory/x8). The read side
// (GetGFMatchesByScan) and ROI scoring still consult it, so it contributes zero
// signal until a writer is reintroduced. The table and schema are kept for
// backwards compatibility with existing databases.
// ─────────────────────────────────────────────────────────────

// GetGFMatchesByScan returns all gf pattern matches for a scan, grouped by URL.
// The returned map keys are raw URLs; the values are slices of pattern names
// (e.g. "sqli", "xss", "rce").
func GetGFMatchesByScan(scanID int64) (map[string][]string, error) {
	rows, err := DB.Query(`SELECT url, pattern FROM gf_matches WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]string)
	for rows.Next() {
		var u, pattern string
		if err := rows.Scan(&u, &pattern); err != nil {
			continue
		}
		result[u] = append(result[u], pattern)
	}
	return result, rows.Err()
}

// ─────────────────────────────────────────────────────────────
// JS Secret host flagging
// ─────────────────────────────────────────────────────────────

// MarkHostsJSSecrets flags the given hosts as having exposed secrets in their
// JavaScript files. If a host_metadata row doesn't exist yet, one is created.
func MarkHostsJSSecrets(scanID int64, hosts []string) error {
	if len(hosts) == 0 {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

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
