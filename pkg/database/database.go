package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vishnu303/chaathan/pkg/paths"
)

// DB is the global database connection
var DB *sql.DB

// ErrDBNotInitialized is returned when a database operation is attempted but the database has not been initialized.
var ErrDBNotInitialized = fmt.Errorf("database not initialized")

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
	Host        string    `json:"host"`
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
	Host      string    `json:"host"`
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
	// modernc.org/sqlite registers the "sqlite" driver. Pragmas are applied
	// via separate exec statements below (the mattn-style query-string
	// "_journal_mode=..." syntax is not supported by modernc).
	DB, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// SQLite is single-writer. Capping to one open connection prevents
	// "database is locked" errors when concurrent goroutines (parallel scan
	// steps) all issue writes at the same time. WAL handles concurrent reads fine.
	DB.SetMaxOpenConns(1)
	DB.SetMaxIdleConns(1)

	// Apply WAL + busy_timeout pragmas (CGO-free driver does not parse them
	// from the DSN query string).
	if _, err := DB.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
		return fmt.Errorf("failed to apply sqlite pragmas: %w", err)
	}

	// Create tables
	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Best-effort database file permissions Chmod to 0600
	_ = os.Chmod(dbPath, 0600)

	return nil
}

// Foreign-key constraints are declared for documentation but NOT enforced (PRAGMA foreign_keys is off by default in SQLite and not enabled here). DeleteScan performs explicit child-first deletes. Do not rely on FK enforcement for orphan prevention.
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
		host TEXT,
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
		host TEXT,
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
		confirmed TEXT NOT NULL DEFAULT 'unverified',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id),
		UNIQUE(scan_id, url, pattern)
	);

	CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
	CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
	CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
	CREATE INDEX IF NOT EXISTS idx_urls_scan ON urls(scan_id);
	CREATE INDEX IF NOT EXISTS idx_urls_host ON urls(host);
	CREATE INDEX IF NOT EXISTS idx_host_metadata_scan ON host_metadata(scan_id);
	CREATE INDEX IF NOT EXISTS idx_url_metadata_scan ON url_metadata(scan_id);
	CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
	CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_vulns_unique ON vulnerabilities(scan_id, host, IFNULL(template_id, ''), IFNULL(url, ''));
	CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
	CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(host);
	CREATE INDEX IF NOT EXISTS idx_gf_matches_scan ON gf_matches(scan_id);
	CREATE INDEX IF NOT EXISTS idx_scans_target   ON scans(target);
	`

	_, err := DB.Exec(schema)
	if err != nil {
		return err
	}
	return migrateSchema()
}

// migrateSchema applies incremental schema changes for existing databases.
func migrateSchema() error {
	// Add confirmed column to gf_matches (added in JS Deep Analysis upgrade).
	// ALTER TABLE ADD COLUMN is idempotent-safe: ignore "duplicate column" errors.
	_, err := DB.Exec(`ALTER TABLE gf_matches ADD COLUMN confirmed TEXT NOT NULL DEFAULT 'unverified'`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

// Close closes the database connection
func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}

// GetDefaultDBPath returns the default database path
func GetDefaultDBPath() string {
	return paths.DatabasePath()
}

// VacuumDatabase runs VACUUM to reclaim space after deletions
func VacuumDatabase() error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	_, err := DB.Exec("VACUUM")
	return err
}

// --- Aggregate Count Functions (for status dashboard) ---

func getCount(query string) (int, error) {
	if DB == nil {
		return 0, ErrDBNotInitialized
	}
	var count int
	err := DB.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}
