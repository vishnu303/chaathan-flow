package database

// InsertRawURLMetadataForTest inserts raw mock metadata into database without raw DB handle access in tests.
func InsertRawURLMetadataForTest(scanID int64, url, host string) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	_, err := DB.Exec("INSERT INTO url_metadata (scan_id, url, host, headers_json) VALUES (?, ?, ?, NULL)", scanID, url, host)
	return err
}
