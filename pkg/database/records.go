package database

// records.go groups the record structs used by the single-row write APIs.
// Batch APIs and readers share these same shapes so the write and read
// paths never diverge.

// URLRecord holds the fields needed for URL insertion (single or batch).
type URLRecord struct {
	RawURL      string
	StatusCode  int
	ContentType string
	Title       string
	Tech        string
	Source      string
}

// VulnRecord is the write-side record for AddVulnerability. It aliases
// Vulnerability so insert and read paths share one shape.
type VulnRecord = Vulnerability
