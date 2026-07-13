package database

import (
	"database/sql"
	"strings"
	"time"
)

// HostMetadata stores lightweight per-host signals used by ROI ranking.
type HostMetadata struct {
	ScanID              int64     `json:"scan_id"`
	Host                string    `json:"host"`
	BaseURL             string    `json:"base_url,omitempty"`
	HeadersJSON         string    `json:"headers_json,omitempty"`
	HasCSP              bool      `json:"has_csp"`
	HasCacheHeaders     bool      `json:"has_cache_headers"`
	LoginSurface        bool      `json:"login_surface"`
	ResponseBytes       int       `json:"response_bytes"`
	SSLExpired          bool      `json:"ssl_expired"`
	SSLSelfSigned       bool      `json:"ssl_self_signed"`
	SSLMismatch         bool      `json:"ssl_mismatch"`
	WeakTLS             bool      `json:"weak_tls"`
	HasJSSecrets        bool      `json:"has_js_secrets"`
	CORSWildcard        bool      `json:"cors_wildcard"`
	HasInsecureCookies  bool      `json:"has_insecure_cookies"`
	HasSessionCookie    bool      `json:"has_session_cookie"`
	HasDangerousMethods bool      `json:"has_dangerous_methods"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// URLMetadata stores selected path-level signals used by ROI ranking.
type URLMetadata struct {
	ScanID           int64     `json:"scan_id"`
	URL              string    `json:"url"`
	Host             string    `json:"host"`
	HeadersJSON      string    `json:"headers_json,omitempty"`
	HasCSP           bool      `json:"has_csp"`
	HasCacheHeaders  bool      `json:"has_cache_headers"`
	LoginSurface     bool      `json:"login_surface"`
	ResponseBytes    int       `json:"response_bytes"`
	FormCount        int       `json:"form_count"`
	HasFileUpload    bool      `json:"has_file_upload"`
	HiddenInputCount int       `json:"hidden_input_count"`
	ParamCount       int       `json:"param_count"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func UpsertHostMetadata(scanID int64, meta HostMetadata) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	meta.Host = strings.ToLower(strings.TrimSpace(meta.Host))
	_, err := DB.Exec(
		`INSERT INTO host_metadata (
			scan_id, host, base_url, headers_json, has_csp, has_cache_headers,
			login_surface, response_bytes, ssl_expired, ssl_self_signed,
			ssl_mismatch, weak_tls, has_js_secrets,
			cors_wildcard, has_insecure_cookies, has_session_cookie, has_dangerous_methods
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, host) DO UPDATE SET
			base_url = CASE
				WHEN excluded.base_url != '' THEN excluded.base_url
				ELSE host_metadata.base_url
			END,
			headers_json = CASE
				WHEN excluded.headers_json != '' THEN excluded.headers_json
				ELSE host_metadata.headers_json
			END,
			has_csp = host_metadata.has_csp OR excluded.has_csp,
			has_cache_headers = host_metadata.has_cache_headers OR excluded.has_cache_headers,
			login_surface = host_metadata.login_surface OR excluded.login_surface,
			response_bytes = CASE
				WHEN excluded.response_bytes > host_metadata.response_bytes THEN excluded.response_bytes
				ELSE host_metadata.response_bytes
			END,
			ssl_expired = host_metadata.ssl_expired OR excluded.ssl_expired,
			ssl_self_signed = host_metadata.ssl_self_signed OR excluded.ssl_self_signed,
			ssl_mismatch = host_metadata.ssl_mismatch OR excluded.ssl_mismatch,
			weak_tls = host_metadata.weak_tls OR excluded.weak_tls,
			has_js_secrets = host_metadata.has_js_secrets OR excluded.has_js_secrets,
			cors_wildcard = host_metadata.cors_wildcard OR excluded.cors_wildcard,
			has_insecure_cookies = host_metadata.has_insecure_cookies OR excluded.has_insecure_cookies,
			has_session_cookie = host_metadata.has_session_cookie OR excluded.has_session_cookie,
			has_dangerous_methods = host_metadata.has_dangerous_methods OR excluded.has_dangerous_methods,
			updated_at = CURRENT_TIMESTAMP`,
		scanID,
		meta.Host,
		meta.BaseURL,
		meta.HeadersJSON,
		meta.HasCSP,
		meta.HasCacheHeaders,
		meta.LoginSurface,
		meta.ResponseBytes,
		meta.SSLExpired,
		meta.SSLSelfSigned,
		meta.SSLMismatch,
		meta.WeakTLS,
		meta.HasJSSecrets,
		meta.CORSWildcard,
		meta.HasInsecureCookies,
		meta.HasSessionCookie,
		meta.HasDangerousMethods,
	)
	return err
}

func UpsertURLMetadata(scanID int64, meta URLMetadata) error {
	if DB == nil {
		return ErrDBNotInitialized
	}
	meta.URL = strings.TrimSpace(meta.URL)
	meta.Host = strings.ToLower(strings.TrimSpace(meta.Host))
	_, err := DB.Exec(
		`INSERT INTO url_metadata (
			scan_id, url, host, headers_json, has_csp, has_cache_headers,
			login_surface, response_bytes, form_count, has_file_upload,
			hidden_input_count, param_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, url) DO UPDATE SET
			host = CASE
				WHEN excluded.host != '' THEN excluded.host
				ELSE url_metadata.host
			END,
			headers_json = CASE
				WHEN excluded.headers_json != '' THEN excluded.headers_json
				ELSE url_metadata.headers_json
			END,
			has_csp = url_metadata.has_csp OR excluded.has_csp,
			has_cache_headers = url_metadata.has_cache_headers OR excluded.has_cache_headers,
			login_surface = url_metadata.login_surface OR excluded.login_surface,
			response_bytes = CASE
				WHEN excluded.response_bytes > url_metadata.response_bytes THEN excluded.response_bytes
				ELSE url_metadata.response_bytes
			END,
			form_count = CASE
				WHEN excluded.form_count > url_metadata.form_count THEN excluded.form_count
				ELSE url_metadata.form_count
			END,
			has_file_upload = url_metadata.has_file_upload OR excluded.has_file_upload,
			hidden_input_count = CASE
				WHEN excluded.hidden_input_count > url_metadata.hidden_input_count THEN excluded.hidden_input_count
				ELSE url_metadata.hidden_input_count
			END,
			param_count = CASE
				WHEN excluded.param_count > url_metadata.param_count THEN excluded.param_count
				ELSE url_metadata.param_count
			END,
			updated_at = CURRENT_TIMESTAMP`,
		scanID,
		meta.URL,
		meta.Host,
		meta.HeadersJSON,
		meta.HasCSP,
		meta.HasCacheHeaders,
		meta.LoginSurface,
		meta.ResponseBytes,
		meta.FormCount,
		meta.HasFileUpload,
		meta.HiddenInputCount,
		meta.ParamCount,
	)
	return err
}

func GetHostMetadata(scanID int64) ([]HostMetadata, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT scan_id, host, base_url, headers_json, has_csp, has_cache_headers,
		        login_surface, response_bytes, ssl_expired, ssl_self_signed,
		        ssl_mismatch, weak_tls, has_js_secrets,
		        cors_wildcard, has_insecure_cookies, has_session_cookie,
		        has_dangerous_methods, created_at, updated_at
		 FROM host_metadata WHERE scan_id = ?`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metas []HostMetadata
	for rows.Next() {
		var meta HostMetadata
		var baseURLNull, headersJSONNull sql.NullString
		if err := rows.Scan(
			&meta.ScanID,
			&meta.Host,
			&baseURLNull,
			&headersJSONNull,
			&meta.HasCSP,
			&meta.HasCacheHeaders,
			&meta.LoginSurface,
			&meta.ResponseBytes,
			&meta.SSLExpired,
			&meta.SSLSelfSigned,
			&meta.SSLMismatch,
			&meta.WeakTLS,
			&meta.HasJSSecrets,
			&meta.CORSWildcard,
			&meta.HasInsecureCookies,
			&meta.HasSessionCookie,
			&meta.HasDangerousMethods,
			&meta.CreatedAt,
			&meta.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if baseURLNull.Valid {
			meta.BaseURL = baseURLNull.String
		}
		if headersJSONNull.Valid {
			meta.HeadersJSON = headersJSONNull.String
		}
		metas = append(metas, meta)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return metas, nil
}

func GetURLMetadata(scanID int64) ([]URLMetadata, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}
	rows, err := DB.Query(
		`SELECT scan_id, url, host, headers_json, has_csp, has_cache_headers,
		        login_surface, response_bytes, form_count, has_file_upload,
		        hidden_input_count, param_count, created_at, updated_at
		 FROM url_metadata WHERE scan_id = ?`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metas []URLMetadata
	for rows.Next() {
		var meta URLMetadata
		var hostNull, headersJSONNull sql.NullString
		if err := rows.Scan(
			&meta.ScanID,
			&meta.URL,
			&hostNull,
			&headersJSONNull,
			&meta.HasCSP,
			&meta.HasCacheHeaders,
			&meta.LoginSurface,
			&meta.ResponseBytes,
			&meta.FormCount,
			&meta.HasFileUpload,
			&meta.HiddenInputCount,
			&meta.ParamCount,
			&meta.CreatedAt,
			&meta.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if hostNull.Valid {
			meta.Host = hostNull.String
		}
		if headersJSONNull.Valid {
			meta.HeadersJSON = headersJSONNull.String
		}
		metas = append(metas, meta)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return metas, nil
}
