package utils_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/ingest"
	"github.com/vishnu303/chaathan/utils"
)

// setupTestDB initializes a temporary SQLite database with one scan for
// "example.com" and returns the scan ID and temp directory.
func setupTestDB(t *testing.T) (int64, string) {
	t.Helper()
	tempDir := t.TempDir()
	if err := database.Initialize(filepath.Join(tempDir, "test.db")); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			database.DB.Close()
			database.DB = nil
		}
	})

	scanObj, err := database.CreateScan("example.com", "wildcard", tempDir, "{}")
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}
	return scanObj.ID, tempDir
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		domain  string
		wantErr bool
	}{
		{"example.com", false},
		{"sub.example.com", false},
		{"sub-domain.example.co.uk", false},
		{"invalid_domain.com", true}, // contains underscore
		{"", true},
		{"example", true}, // no TLD
		{"-example.com", true},
		{"example.com/path", true},
		{"example.com?query=1", true},
		{"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.com", false},
		{string(make([]byte, 254)), true}, // too long
	}

	for _, tt := range tests {
		err := utils.ValidateDomain(tt.domain)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
		}
	}
}

func TestParseScanID(t *testing.T) {
	tests := []struct {
		arg     string
		want    int64
		wantErr bool
	}{
		{"123", 123, false},
		{"0", 0, true},
		{"-5", 0, true},
		{"abc", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		got, err := utils.ParseScanID(tt.arg)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseScanID(%q) error = %v, wantErr %v", tt.arg, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("ParseScanID(%q) = %d, want %d", tt.arg, got, tt.want)
		}
	}
}

func TestParseDays(t *testing.T) {
	tests := []struct {
		arg     string
		want    int
		wantErr bool
	}{
		{"10", 10, false},
		{"1", 1, false},
		{"0", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		got, err := utils.ParseDays(tt.arg)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseDays(%q) error = %v, wantErr %v", tt.arg, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("ParseDays(%q) = %d, want %d", tt.arg, got, tt.want)
		}
	}
}

func TestDeduplicateSlice(t *testing.T) {
	in := []string{"apple", "orange", "apple", "banana", "orange"}
	want := []string{"apple", "orange", "banana"}
	got := utils.DeduplicateSlice(in)
	if !slices.Equal(got, want) {
		t.Errorf("DeduplicateSlice(%v) = %v, want %v", in, got, want)
	}

	// Empty case
	var empty []int
	if gotEmpty := utils.DeduplicateSlice(empty); len(gotEmpty) != 0 {
		t.Errorf("DeduplicateSlice(empty) = %v, want empty", gotEmpty)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		max  int
		want string
	}{
		{"hello world", 5, "he..."},
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel"},
		{"hello", 2, "he"},
		{"こんにちは", 4, "こ..."},
	}

	for _, tt := range tests {
		got := utils.Truncate(tt.s, tt.max)
		if got != tt.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.s, tt.max, got, tt.want)
		}
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 5 / 2, "2.5 MB"},
	}

	for _, tt := range tests {
		got := utils.FormatSize(tt.bytes)
		if got != tt.want {
			t.Errorf("FormatSize(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestIsHTTPMethod(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{"GET", true},
		{"get", true},
		{"POST", true},
		{"post", true},
		{"PUT", true},
		{"DELETE", true},
		{"OPTIONS", true},
		{"HEAD", true},
		{"PATCH", true},
		{"UNKNOWN", false},
		{"", false},
	}

	for _, tt := range tests {
		got := utils.IsHTTPMethod(tt.method)
		if got != tt.want {
			t.Errorf("IsHTTPMethod(%q) = %t, want %t", tt.method, got, tt.want)
		}
	}
}

func TestParseHex4(t *testing.T) {
	tests := []struct {
		hex    string
		want   rune
		wantOk bool
	}{
		{"0026", '&', true},
		{"0061", 'a', true},
		{"3042", 'あ', true},
		{"zzzz", 0, false},
		{"123", 0, false},
		{"12345", 0, false},
	}

	for _, tt := range tests {
		got, ok := utils.ParseHex4(tt.hex)
		if ok != tt.wantOk {
			t.Errorf("ParseHex4(%q) ok = %t, wantOk %t", tt.hex, ok, tt.wantOk)
		}
		if ok && got != tt.want {
			t.Errorf("ParseHex4(%q) = %d, want %d", tt.hex, got, tt.want)
		}
	}
}

func TestUnescapeUnicodeURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"http://example.com/?a=1\\u0026b=2", "http://example.com/?a=1&b=2"},
		{"http://example.com/?a=1\\\\u0026b=2", "http://example.com/?a=1&b=2"},
		{"http://example.com/no-escape", "http://example.com/no-escape"},
		{"\\u3042", "あ"},
	}

	for _, tt := range tests {
		got := utils.UnescapeUnicodeURL(tt.in)
		if got != tt.want {
			t.Errorf("UnescapeUnicodeURL(%q) = %q, want %q", tt.in, tt.want, got)
		}
	}
}

func TestNormalizeHostValue(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://[2001:db8::1]:8080/path", "2001:db8::1"},
		{"example.com:443", "example.com"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"  EXAMPLE.COM  ", "example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		got := utils.NormalizeHostValue(tt.raw)
		if got != tt.want {
			t.Errorf("NormalizeHostValue(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestIsWeakTLSVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"TLS1.0", true},
		{"tls1.1", true},
		{"TLS10", true},
		{"tls11", true},
		{"SSL3", true},
		{"TLS1.2", false},
		{"TLS1.3", false},
		{"", false},
	}

	for _, tt := range tests {
		got := utils.IsWeakTLSVersion(tt.version)
		if got != tt.want {
			t.Errorf("IsWeakTLSVersion(%q) = %t, want %t", tt.version, got, tt.want)
		}
	}
}

func TestFileUtilities(t *testing.T) {
	tmpDir := t.TempDir()

	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")
	mergedFile := filepath.Join(tmpDir, "merged.txt")

	// Test writing to files
	err := os.WriteFile(file1, []byte("  apple  \nbanana\n\napple\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(file2, []byte("cherry\nbanana\ndate\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Test CountFileLines
	lines, err := utils.CountFileLines(file1)
	if err != nil {
		t.Fatal(err)
	}
	if lines != 3 { // apple, banana, apple (trimmed non-empty lines)
		t.Errorf("CountFileLines = %d, want 3", lines)
	}

	// Test MergeAndDeduplicate
	err = utils.MergeAndDeduplicate([]string{file1, file2}, mergedFile)
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(mergedFile)
	if err != nil {
		t.Fatal(err)
	}

	wantMerged := "apple\nbanana\ncherry\ndate\n"
	if string(content) != wantMerged {
		t.Errorf("MergeAndDeduplicate content = %q, want %q", string(content), wantMerged)
	}

	// Test FilterFileLines
	err = utils.FilterFileLines(mergedFile, func(line string) bool {
		return line != "banana" // filter out banana
	})
	if err != nil {
		t.Fatal(err)
	}

	content, err = os.ReadFile(mergedFile)
	if err != nil {
		t.Fatal(err)
	}
	wantFiltered := "apple\ncherry\ndate\n"
	if string(content) != wantFiltered {
		t.Errorf("FilterFileLines content = %q, want %q", string(content), wantFiltered)
	}

	// Test SanitizeURLFile
	urlFile := filepath.Join(tmpDir, "urls.txt")
	err = os.WriteFile(urlFile, []byte(`
https://example.com/a
http://example.com/b\u0026c=3
invalid-line
https://example.com/a
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = utils.SanitizeURLFile(urlFile, nil)
	if err != nil {
		t.Fatal(err)
	}

	content, err = os.ReadFile(urlFile)
	if err != nil {
		t.Fatal(err)
	}

	wantSanitized := "http://example.com/b&c=3\nhttps://example.com/a\n"
	if string(content) != wantSanitized {
		t.Errorf("SanitizeURLFile content = %q, want %q", string(content), wantSanitized)
	}
}

func TestParseNucleiOutput(t *testing.T) {
	scanID, tempDir := setupTestDB(t)

	nucleiJSONL := `{"template-id":"xss-injection","info":{"name":"Reflected XSS","severity":"High","description":"XSS detected"},"host":"example.com","matched-at":"https://example.com/search?q=1","extractor-name":"rxss-extractor","extracted-results":["rxss-payload"]}`
	filePath := filepath.Join(tempDir, "nuclei.jsonl")
	if err := os.WriteFile(filePath, []byte(nucleiJSONL+"\n"), 0644); err != nil {
		t.Fatalf("failed to write nuclei file: %v", err)
	}

	count, err := ingest.ParseNucleiOutput(scanID, filePath)
	if err != nil {
		t.Fatalf("ParseNucleiOutput error: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 result parsed, got %d", count)
	}

	vulns, err := database.GetVulnerabilities(scanID)
	if err != nil {
		t.Fatalf("GetVulnerabilities error: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln in database, got %d", len(vulns))
	}

	v := vulns[0]
	if v.TemplateID != "xss-injection" {
		t.Errorf("expected template ID 'xss-injection', got %q", v.TemplateID)
	}
	if v.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", v.Severity)
	}
	if !strings.Contains(v.Evidence, "Extractor: rxss-extractor") {
		t.Errorf("expected evidence to contain extractor name, got %q", v.Evidence)
	}
	if !strings.Contains(v.Evidence, "rxss-payload") {
		t.Errorf("expected evidence to contain extracted-results payload, got %q", v.Evidence)
	}
}

func TestParseHttpxOutput(t *testing.T) {
	scanID, tempDir := setupTestDB(t)

	if err := database.AddSubdomain(scanID, "example.com", "test"); err != nil {
		t.Fatalf("failed to add subdomain: %v", err)
	}

	httpxJSONL := `{"url":"https://example.com/","status_code":200,"title":"Test Title","content_type":"text/html","tech":["Nginx","Go"],"host":"example.com"}`
	filePath := filepath.Join(tempDir, "httpx.jsonl")
	if err := os.WriteFile(filePath, []byte(httpxJSONL+"\n"), 0644); err != nil {
		t.Fatalf("failed to write httpx file: %v", err)
	}

	count, err := ingest.ParseHttpxOutput(scanID, filePath)
	if err != nil {
		t.Fatalf("ParseHttpxOutput error: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 result parsed, got %d", count)
	}

	urls, err := database.GetURLs(scanID)
	if err != nil {
		t.Fatalf("GetURLs error: %v", err)
	}

	if len(urls) != 1 {
		t.Fatalf("expected 1 URL, got %d", len(urls))
	}

	if urls[0].URL != "https://example.com/" {
		t.Errorf("expected URL 'https://example.com/', got %q", urls[0].URL)
	}

	subs, err := database.GetLiveSubdomains(scanID)
	if err != nil {
		t.Fatalf("GetLiveSubdomains error: %v", err)
	}

	if len(subs) != 1 {
		t.Errorf("expected subdomain to be live, but live count is %d", len(subs))
	}
}

func TestParseDalfoxOutput_TextMode(t *testing.T) {
	scanID, tempDir := setupTestDB(t)

	dalfoxOutput := `[POC][G][VULN] http://sub.example.com/index.php?q=%3Cscript%3Ealert(1)%3C/script%3E`
	filePath := filepath.Join(tempDir, "dalfox.txt")
	if err := os.WriteFile(filePath, []byte(dalfoxOutput+"\n"), 0644); err != nil {
		t.Fatalf("failed to write dalfox file: %v", err)
	}

	count, err := ingest.ParseDalfoxOutput(scanID, filePath)
	if err != nil {
		t.Fatalf("ParseDalfoxOutput error: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 result parsed, got %d", count)
	}

	vulns, err := database.GetVulnerabilities(scanID)
	if err != nil {
		t.Fatalf("GetVulnerabilities error: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}

	v := vulns[0]
	if v.Host != "sub.example.com" {
		t.Errorf("expected host 'sub.example.com', got %q", v.Host)
	}
	if v.URL != "http://sub.example.com/index.php?q=%3Cscript%3Ealert(1)%3C/script%3E" {
		t.Errorf("expected url 'http://sub.example.com/...', got %q", v.URL)
	}
	if v.Evidence != dalfoxOutput {
		t.Errorf("expected evidence to be full line, got %q", v.Evidence)
	}
}

func TestFileExists_NonExistentError(t *testing.T) {
	tempDir := t.TempDir()
	restrictedDir := filepath.Join(tempDir, "restricted")
	if err := os.Mkdir(restrictedDir, 0000); err != nil {
		t.Skip("skipping test; cannot create mode 0000 dir on this OS")
	}

	targetFile := filepath.Join(restrictedDir, "test.txt")
	exists := utils.FileExists(targetFile)
	if exists {
		t.Errorf("expected FileExists(%q) to be false", targetFile)
	}
}

func TestUnescapeUnicodeURL_SurrogatePair(t *testing.T) {
	in := "http://example.com/?q=\\uD83D\\uDE00"
	want := "http://example.com/?q=😀"
	got := utils.UnescapeUnicodeURL(in)
	if got != want {
		t.Errorf("UnescapeUnicodeURL(%q) = %q, want %q", in, got, want)
	}
}

func TestExportVulnerabilities_CaseInsensitiveSeverity(t *testing.T) {
	scanID, tempDir := setupTestDB(t)

	err := database.AddVulnerability(
		scanID, "example.com", "https://example.com", "rce",
		"Remote Code Execution", "CrItIcAl", "rce finding", "", "",
	)
	if err != nil {
		t.Fatalf("failed to insert vulnerability: %v", err)
	}

	err = ingest.ExportVulnerabilities(scanID, tempDir)
	if err != nil {
		t.Fatalf("ExportVulnerabilities failed: %v", err)
	}

	critPath := filepath.Join(tempDir, utils.FileVulnCriticalHigh)
	content, err := os.ReadFile(critPath)
	if err != nil {
		t.Fatalf("failed to read critical high file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "Remote Code Execution") {
		t.Errorf("expected critical vuln to be exported, got content: %q", contentStr)
	}
}

func TestParseNaabuOutput(t *testing.T) {
	scanID, tempDir := setupTestDB(t)

	content := `{"host":"example.com","ip":"93.184.216.34","port":443,"protocol":"tcp"}
example.com:80
not-a-valid-line
`
	filePath := filepath.Join(tempDir, "naabu.txt")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseNaabuOutput(scanID, filePath)
	if err != nil {
		t.Fatalf("ParseNaabuOutput error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 ports parsed (JSON + host:port), got %d", count)
	}

	ports, err := database.GetPorts(scanID)
	if err != nil {
		t.Fatalf("GetPorts error: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports in database, got %d", len(ports))
	}
}

func TestParseSubdomainsFile(t *testing.T) {
	scanID, tempDir := setupTestDB(t)

	content := `# comment
example.com
sub.example.com
sub.example.com
other.org
`
	filePath := filepath.Join(tempDir, "subs.txt")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseSubdomainsFile(scanID, filePath, "test")
	if err != nil {
		t.Fatalf("ParseSubdomainsFile error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 in-scope unique subdomains, got %d", count)
	}

	subs, err := database.GetSubdomains(scanID)
	if err != nil {
		t.Fatalf("GetSubdomains error: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("expected 2 subdomains in database, got %d", len(subs))
	}

	// File must be rewritten in-place, sorted, with out-of-scope entries removed.
	content2, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	want := "example.com\nsub.example.com\n"
	if string(content2) != want {
		t.Errorf("rewritten file = %q, want %q", string(content2), want)
	}
}

func TestParseURLsFile(t *testing.T) {
	scanID, tempDir := setupTestDB(t)

	content := `https://example.com/a
https://other.org/b
# comment

`
	filePath := filepath.Join(tempDir, "urls.txt")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseURLsFile(scanID, filePath, "test")
	if err != nil {
		t.Fatalf("ParseURLsFile error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 in-scope URL, got %d", count)
	}

	urls, err := database.GetURLs(scanID)
	if err != nil {
		t.Fatalf("GetURLs error: %v", err)
	}
	if len(urls) != 1 || urls[0].URL != "https://example.com/a" {
		t.Errorf("unexpected URLs in database: %+v", urls)
	}
}

func TestParseURLsFile_NoiseIgnored(t *testing.T) {
	scanID, tempDir := setupTestDB(t)

	content := `[js] https://cdn.example.com/app.js
[+] Crawling: https://example.com/
Looking for subdomains of example.com...
https://example.com/a
https://other.org/b
relative/path.js
example.com/bare-domain
https://example.com/valid?q=1
`
	filePath := filepath.Join(tempDir, "noisy_urls.txt")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseURLsFile(scanID, filePath, "test")
	if err != nil {
		t.Fatalf("ParseURLsFile error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 in-scope URL lines (noise dropped), got %d", count)
	}

	urls, err := database.GetURLs(scanID)
	if err != nil {
		t.Fatalf("GetURLs error: %v", err)
	}
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs in database, got %d", len(urls))
	}
	for _, u := range urls {
		if u.URL == "[js] https://cdn.example.com/app.js" ||
			u.URL == "[+] Crawling: https://example.com/" ||
			u.URL == "Looking for subdomains of example.com..." ||
			u.URL == "relative/path.js" ||
			u.URL == "example.com/bare-domain" {
			t.Errorf("noise line leaked into database: %q", u.URL)
		}
	}
}

func TestIsValidHTTPURL(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"https://example.com/a", true},
		{"http://example.com", true},
		{"https://sub.example.com/path?q=1", true},
		{"  https://example.com/spaced  ", true},
		{"[js] https://cdn.example.com/app.js", false},
		{"[+] Crawling: https://example.com/", false},
		{"Looking for subdomains of example.com...", false},
		{"example.com/bare-domain", false},
		{"relative/path.js", false},
		{"ftp://example.com/file", false},
		{"https://", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := utils.IsValidHTTPURL(tt.in); got != tt.want {
			t.Errorf("IsValidHTTPURL(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestFilterOutputLines(t *testing.T) {
	output := "banner line\nhttps://example.com/a\n\n[js] https://x.com/b.js\n"
	kept := utils.FilterOutputLines(output, utils.IsValidHTTPURL)
	want := "https://example.com/a\n"
	if kept != want {
		t.Errorf("FilterOutputLines = %q, want %q", kept, want)
	}

	if got := utils.FilterOutputLines("only noise\n", utils.IsValidHTTPURL); got != "" {
		t.Errorf("expected empty result for all-noise output, got %q", got)
	}
}

func TestParseEndpointsFile(t *testing.T) {
	scanID, tempDir := setupTestDB(t)

	content := `GET https://example.com/api
https://example.com/plain
`
	filePath := filepath.Join(tempDir, "endpoints.txt")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseEndpointsFile(scanID, filePath, "test")
	if err != nil {
		t.Fatalf("ParseEndpointsFile error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 endpoints parsed, got %d", count)
	}

	endpoints, err := database.GetEndpoints(scanID)
	if err != nil {
		t.Fatalf("GetEndpoints error: %v", err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints in database, got %d", len(endpoints))
	}
	var withMethod bool
	for _, e := range endpoints {
		if e.Method == "GET" {
			withMethod = true
		}
	}
	if !withMethod {
		t.Errorf("expected at least one endpoint with method GET: %+v", endpoints)
	}
}

// --- Phase 1 regression tests for pkg/ingest/parser.go P0 fixes ---

func TestParseEndpointsFile_RelativeKept(t *testing.T) {
	// F1: golinkfinder-style relative endpoints ("/api/v1/users") must be
	// retained even when the scan has a domain target; out-of-scope absolute
	// URLs are still filtered.
	scanID, tempDir := setupTestDB(t)

	content := "/api/v1/users\nhttps://other.org/x\n"
	filePath := filepath.Join(tempDir, "endpoints.txt")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseEndpointsFile(scanID, filePath, "golinkfinder")
	if err != nil {
		t.Fatalf("ParseEndpointsFile error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 endpoint (relative kept, out-of-scope dropped), got %d", count)
	}

	endpoints, err := database.GetEndpoints(scanID)
	if err != nil {
		t.Fatalf("GetEndpoints error: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].URL != "/api/v1/users" {
		t.Errorf("expected only /api/v1/users stored, got %+v", endpoints)
	}
}

func TestParseEndpointsFile_Deduplication(t *testing.T) {
	// B2: duplicate (method, url) entries in endpoints file are deduplicated
	// before insert so returned count matches DB stored rows.
	scanID, tempDir := setupTestDB(t)

	content := "GET https://example.com/api\nGET https://example.com/api\nhttps://example.com/plain\n"
	filePath := filepath.Join(tempDir, "dup_endpoints.txt")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseEndpointsFile(scanID, filePath, "test")
	if err != nil {
		t.Fatalf("ParseEndpointsFile error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 unique endpoints parsed, got %d", count)
	}

	endpoints, err := database.GetEndpoints(scanID)
	if err != nil {
		t.Fatalf("GetEndpoints error: %v", err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints in database, got %d", len(endpoints))
	}
}

func TestParseHttpxOutput_EmptyURLSkipped(t *testing.T) {
	// F3: an httpx line with an empty url must not insert a garbage empty-URL
	// row; a valid line on the same file must still be parsed.
	scanID, tempDir := setupTestDB(t)

	content := `{"url":"","host":"example.com","status_code":200}` + "\n" +
		`{"url":"https://example.com/","host":"example.com","status_code":200}` + "\n"
	filePath := filepath.Join(tempDir, "httpx.jsonl")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseHttpxOutput(scanID, filePath)
	if err != nil {
		t.Fatalf("ParseHttpxOutput error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 parsed url (empty skipped), got %d", count)
	}

	urls, err := database.GetURLs(scanID)
	if err != nil {
		t.Fatalf("GetURLs error: %v", err)
	}
	if len(urls) != 1 || urls[0].URL != "https://example.com/" {
		t.Errorf("expected only https://example.com/ stored, got %+v", urls)
	}
}

func TestParseHttpxOutput_IPv6InputFallback(t *testing.T) {
	// F2: when result.URL yields no host and httpx falls back to result.Input,
	// a bare IPv6 input must resolve to the full address "::1" form, not be
	// mangled by a naive LastIndex(":") port-strip into "2001:db8:".
	// Uses a non-domain scan target so getTargetDomain returns "" and the
	// input-fallback path is reachable (no scope filter short-circuits it).
	tempDir := t.TempDir()
	if err := database.Initialize(filepath.Join(tempDir, "test.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			database.DB.Close()
			database.DB = nil
		}
	})
	scanObj, err := database.CreateScan("Acme Corp", "wildcard", tempDir, "{}")
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := database.AddSubdomains(scanObj.ID, []string{"2001:db8::1"}, "seed"); err != nil {
		t.Fatalf("seed subdomain: %v", err)
	}

	httpxJSONL := `{"url":"/x","input":"2001:db8::1","host":"2001:db8::1","status_code":200}`
	filePath := filepath.Join(tempDir, "httpx.jsonl")
	if err := os.WriteFile(filePath, []byte(httpxJSONL+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseHttpxOutput(scanObj.ID, filePath)
	if err != nil {
		t.Fatalf("ParseHttpxOutput error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 parsed url, got %d", count)
	}

	subs, err := database.GetLiveSubdomains(scanObj.ID)
	if err != nil {
		t.Fatalf("GetLiveSubdomains error: %v", err)
	}
	if len(subs) != 1 || subs[0].Domain != "2001:db8::1" || !subs[0].IsLive {
		t.Errorf("expected live subdomain 2001:db8::1 (not mangled), got %+v", subs)
	}
}

func TestParseDalfoxOutput_TextMode_NoURL(t *testing.T) {
	// F4: a [POC]/[V] line with no http(s):// token must not insert a
	// vulnerability with empty host+url.
	scanID, tempDir := setupTestDB(t)

	content := "[POC][G][VULN] some text without a url here\n"
	filePath := filepath.Join(tempDir, "dalfox.txt")
	if err := os.WriteFile(filePath, []byte(content+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseDalfoxOutput(scanID, filePath)
	if err != nil {
		t.Fatalf("ParseDalfoxOutput error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 findings for url-less [POC] line, got %d", count)
	}

	vulns, err := database.GetVulnerabilities(scanID)
	if err != nil {
		t.Fatalf("GetVulnerabilities error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected no vulns inserted, got %+v", vulns)
	}
}

func TestParseTlsxOutput_MixedCaseSAN(t *testing.T) {
	// F5: a SAN with uppercase labels that is in-scope must be accepted and
	// lowercased before storage; previously the case-sensitive comparison
	// dropped it silently.
	scanID, tempDir := setupTestDB(t)

	content := `{"host":"example.com","san":["Www.Example.COM"],"not_after":"","expired":false,"self_signed":false,"mismatched":false,"tls_version":"tls1.2"}` + "\n"
	filePath := filepath.Join(tempDir, "tlsx.jsonl")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	newSubs, vulns, err := ingest.ParseTlsxOutput(scanID, filePath, "example.com")
	if err != nil {
		t.Fatalf("ParseTlsxOutput error: %v", err)
	}
	if newSubs != 1 {
		t.Errorf("expected 1 SAN subdomain accepted, got %d", newSubs)
	}
	if vulns != 0 {
		t.Errorf("expected 0 cert vulns, got %d", vulns)
	}

	subs, err := database.GetSubdomains(scanID)
	if err != nil {
		t.Fatalf("GetSubdomains error: %v", err)
	}
	found := false
	for _, s := range subs {
		if s.Domain == "www.example.com" {
			found = true
		}
		if s.Domain != strings.ToLower(s.Domain) {
			t.Errorf("subdomain %q not lowercased", s.Domain)
		}
	}
	if !found {
		t.Errorf("expected www.example.com in subdomains, got %+v", subs)
	}
}

func TestParseUncoverOutput_MixedCaseHost(t *testing.T) {
	// F5: an uncover host with uppercase labels that is in-scope must be
	// accepted and lowercased; previously the case-sensitive comparison
	// dropped it silently while still storing its port under the raw host.
	scanID, tempDir := setupTestDB(t)

	content := `{"host":"SUB.Example.COM","port":443,"source":"censys","protocol":"tcp"}` + "\n"
	filePath := filepath.Join(tempDir, "uncover.jsonl")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	subs, ports, err := ingest.ParseUncoverOutput(scanID, filePath, "example.com")
	if err != nil {
		t.Fatalf("ParseUncoverOutput error: %v", err)
	}
	if subs != 1 {
		t.Errorf("expected 1 in-scope subdomain accepted, got %d", subs)
	}
	if ports != 1 {
		t.Errorf("expected 1 port, got %d", ports)
	}

	stored, err := database.GetSubdomains(scanID)
	if err != nil {
		t.Fatalf("GetSubdomains error: %v", err)
	}
	found := false
	for _, s := range stored {
		if s.Domain == "sub.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sub.example.com in subdomains, got %+v", stored)
	}
}

func TestParseSubdomainsFile_MixedCaseNormalized(t *testing.T) {
	// F6: mixed-case subdomains must be deduped case-insensitively AND
	// written to the rewritten file lowercased, matching what the DB stores.
	scanID, tempDir := setupTestDB(t)

	content := "# c\nSub.Example.COM\nEXAMPLE.COM\nsub.example.com\n"
	filePath := filepath.Join(tempDir, "subs.txt")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseSubdomainsFile(scanID, filePath, "test")
	if err != nil {
		t.Fatalf("ParseSubdomainsFile error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 unique subdomains, got %d", count)
	}

	rewritten, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	want := "example.com\nsub.example.com\n"
	if string(rewritten) != want {
		t.Errorf("rewritten file = %q, want %q", string(rewritten), want)
	}
}

// --- Phase 2/3 regression tests for pkg/ingest/parser.go ---

func TestParseNaabuOutput_InvalidPortAndHost(t *testing.T) {
	// F7: out-of-range ports and non-IP/non-domain hosts are rejected.
	scanID, tempDir := setupTestDB(t)

	content := `{"host":"example.com","port":99999}` + "\n" +
		`{"host":"example.com","port":0}` + "\n" +
		"foo:123\n" +
		"example.com:80\n" +
		"1.2.3.4:443\n"
	filePath := filepath.Join(tempDir, "naabu.txt")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseNaabuOutput(scanID, filePath)
	if err != nil {
		t.Fatalf("ParseNaabuOutput error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 valid ports (example.com:80, 1.2.3.4:443), got %d", count)
	}

	ports, err := database.GetPorts(scanID)
	if err != nil {
		t.Fatalf("GetPorts error: %v", err)
	}
	if len(ports) != 2 {
		t.Errorf("expected 2 ports in DB, got %d", len(ports))
	}
}

func TestParseNucleiOutput_EmptyMatchedAtFallback(t *testing.T) {
	// F8: two same-template findings with empty matched-at but different
	// hosts must both be stored (not collapsed by the unique index on
	// (scan_id, host, template_id, url) into a single row).
	scanID, tempDir := setupTestDB(t)

	content := `{"template-id":"tech-detect","host":"a.example.com","matched-at":"","info":{"name":"Tech","severity":"info"}}` + "\n" +
		`{"template-id":"tech-detect","host":"b.example.com","matched-at":"","info":{"name":"Tech","severity":"info"}}` + "\n"
	filePath := filepath.Join(tempDir, "nuclei.jsonl")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseNucleiOutput(scanID, filePath)
	if err != nil {
		t.Fatalf("ParseNucleiOutput error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 findings stored, got %d", count)
	}

	vulns, err := database.GetVulnerabilities(scanID)
	if err != nil {
		t.Fatalf("GetVulnerabilities error: %v", err)
	}
	if len(vulns) != 2 {
		t.Errorf("expected 2 distinct vuln rows, got %d", len(vulns))
	}
}

func TestParseFfufOutput_ScopeFilterAndCount(t *testing.T) {
	// F9: out-of-scope ffuf URLs are skipped; count reflects only rows that
	// were stored successfully.
	scanID, tempDir := setupTestDB(t)

	content := `{"results":[{"url":"https://example.com/admin","status":200},{"url":"https://other.org/x","status":404}]}`
	filePath := filepath.Join(tempDir, "ffuf.json")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseFfufOutput(scanID, filePath)
	if err != nil {
		t.Fatalf("ParseFfufOutput error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 in-scope result counted, got %d", count)
	}

	urls, err := database.GetURLs(scanID)
	if err != nil {
		t.Fatalf("GetURLs error: %v", err)
	}
	if len(urls) != 1 || urls[0].URL != "https://example.com/admin" {
		t.Errorf("expected only https://example.com/admin stored, got %+v", urls)
	}
}

func TestParseLiveURLsFile_CaseInsensitiveDedup(t *testing.T) {
	// F10: the same URL in different cases is deduped to one stored row.
	scanID, tempDir := setupTestDB(t)

	content := "https://example.com/\nHTTPS://Example.com/\n"
	filePath := filepath.Join(tempDir, "live.txt")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	count, err := ingest.ParseLiveURLsFile(scanID, filePath, "probe")
	if err != nil {
		t.Fatalf("ParseLiveURLsFile error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 URL after case-insensitive dedup, got %d", count)
	}
}

func TestParseTlsxOutput_SANBatched(t *testing.T) {
	// F11: multiple SANs across multiple tlsx lines are all stored via a
	// single batched insert; dedup is still per-file (a SAN repeated across
	// lines is counted and stored once).
	scanID, tempDir := setupTestDB(t)

	content := `{"host":"example.com","san":["a.example.com"],"tls_version":"tls1.2"}` + "\n" +
		`{"host":"www.example.com","san":["a.example.com","b.example.com"],"tls_version":"tls1.2"}` + "\n"
	filePath := filepath.Join(tempDir, "tlsx.jsonl")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	newSubs, vulns, err := ingest.ParseTlsxOutput(scanID, filePath, "example.com")
	if err != nil {
		t.Fatalf("ParseTlsxOutput error: %v", err)
	}
	if newSubs != 2 {
		t.Errorf("expected 2 unique in-scope SANs (a, b), got %d", newSubs)
	}
	if vulns != 0 {
		t.Errorf("expected 0 cert vulns, got %d", vulns)
	}

	subs, err := database.GetSubdomains(scanID)
	if err != nil {
		t.Fatalf("GetSubdomains error: %v", err)
	}
	gotA, gotB := false, false
	for _, s := range subs {
		if s.Domain == "a.example.com" {
			gotA = true
		}
		if s.Domain == "b.example.com" {
			gotB = true
		}
	}
	if !gotA || !gotB {
		t.Errorf("expected a.example.com and b.example.com stored, got %+v", subs)
	}
}

func BenchmarkUnescapeUnicodeURL(b *testing.B) {
	input := "https://example.com/api/v1/search?\\u0071=\\u0076\\u0061\\u006c\\u0075\\u0065"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = utils.UnescapeUnicodeURL(input)
	}
}
