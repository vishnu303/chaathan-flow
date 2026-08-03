package database

import (
	"database/sql"
	neturl "net/url"
	"strings"
)

// URL operations

// AddURL inserts or upserts a single URL record for a scan.
func AddURL(scanID int64, rec URLRecord) error {
	if DB == nil {
		return ErrDBNotInitialized
	}

	var host string
	if parsed, err := neturl.Parse(strings.TrimSpace(rec.RawURL)); err == nil {
		host = strings.ToLower(parsed.Hostname())
	}
	if host == "" {
		cleaned := rec.RawURL
		if !strings.Contains(cleaned, "://") {
			cleaned = "https://" + cleaned
		}
		if parsed, err := neturl.Parse(cleaned); err == nil {
			host = strings.ToLower(parsed.Hostname())
		}
	}

	_, err := DB.Exec(
		`INSERT INTO urls (scan_id, url, host, status_code, content_type, title, tech, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, url) DO UPDATE SET
			host = CASE WHEN urls.host IS NULL OR urls.host = '' THEN excluded.host ELSE urls.host END,
			source = CASE
				WHEN (',' || urls.source || ',') LIKE ('%,' || ? || ',%') THEN urls.source
				ELSE urls.source || ',' || ?
			END,
			status_code = CASE WHEN ? > 0 AND urls.status_code = 0 THEN ? ELSE urls.status_code END,
			content_type = CASE WHEN ? != '' AND urls.content_type = '' THEN ? ELSE urls.content_type END,
			title = CASE WHEN ? != '' AND urls.title = '' THEN ? ELSE urls.title END,
			tech = CASE WHEN ? != '' AND urls.tech = '' THEN ? ELSE urls.tech END`,
		scanID, rec.RawURL, host, rec.StatusCode, rec.ContentType, rec.Title, rec.Tech, rec.Source,
		rec.Source, rec.Source,
		rec.StatusCode, rec.StatusCode,
		rec.ContentType, rec.ContentType,
		rec.Title, rec.Title,
		rec.Tech, rec.Tech,
	)
	return err
}

// AddURLsBatch inserts multiple URLs in a single transaction for performance.
// It uses the same upsert logic as AddURL but avoids per-row fsync overhead.
func AddURLsBatch(scanID int64, records []URLRecord) (int, error) {
	if DB == nil {
		return 0, ErrDBNotInitialized
	}
	if len(records) == 0 {
		return 0, nil
	}

	tx, err := DB.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(
		`INSERT INTO urls (scan_id, url, host, status_code, content_type, title, tech, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, url) DO UPDATE SET
			host = CASE WHEN urls.host IS NULL OR urls.host = '' THEN excluded.host ELSE urls.host END,
			source = CASE
				WHEN (',' || urls.source || ',') LIKE ('%,' || ? || ',%') THEN urls.source
				ELSE urls.source || ',' || ?
			END,
			status_code = CASE WHEN ? > 0 AND urls.status_code = 0 THEN ? ELSE urls.status_code END,
			content_type = CASE WHEN ? != '' AND urls.content_type = '' THEN ? ELSE urls.content_type END,
			title = CASE WHEN ? != '' AND urls.title = '' THEN ? ELSE urls.title END,
			tech = CASE WHEN ? != '' AND urls.tech = '' THEN ? ELSE urls.tech END`,
	)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for _, r := range records {
		var host string
		if parsed, parseErr := neturl.Parse(strings.TrimSpace(r.RawURL)); parseErr == nil {
			host = strings.ToLower(parsed.Hostname())
		}
		if host == "" {
			cleaned := r.RawURL
			if !strings.Contains(cleaned, "://") {
				cleaned = "https://" + cleaned
			}
			if parsed, parseErr := neturl.Parse(cleaned); parseErr == nil {
				host = strings.ToLower(parsed.Hostname())
			}
		}
		if _, execErr := stmt.Exec(
			scanID, r.RawURL, host, r.StatusCode, r.ContentType, r.Title, r.Tech, r.Source,
			r.Source, r.Source,
			r.StatusCode, r.StatusCode,
			r.ContentType, r.ContentType,
			r.Title, r.Title,
			r.Tech, r.Tech,
		); execErr != nil {
			continue
		}
		count++
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

func GetURLs(scanID int64) ([]URL, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT id, scan_id, url, host, status_code, content_type, title, tech, source, created_at 
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
		var hostNull sql.NullString
		var statusCode sql.NullInt64
		var contentType, title, tech sql.NullString
		if err := rows.Scan(&u.ID, &u.ScanID, &u.URL, &hostNull, &statusCode, &contentType, &title, &tech, &u.Source, &u.CreatedAt); err != nil {
			return nil, err
		}
		if hostNull.Valid {
			u.Host = hostNull.String
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
