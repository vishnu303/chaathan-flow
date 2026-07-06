package utils_test
 
import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/utils"
)

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
		hex     string
		want    rune
		wantOk  bool
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

	err = utils.SanitizeURLFile(urlFile)
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
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	if err := database.Initialize(dbPath); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer func() {
		if database.DB != nil {
			database.DB.Close()
			database.DB = nil
		}
	}()

	scanObj, err := database.CreateScan("example.com", "wildcard", tempDir, "{}")
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}

	nucleiJSONL := `{"template-id":"xss-injection","info":{"name":"Reflected XSS","severity":"High","description":"XSS detected"},"host":"example.com","matched-at":"https://example.com/search?q=1","extractor-name":"rxss-extractor","extracted-results":["rxss-payload"]}`
	filePath := filepath.Join(tempDir, "nuclei.jsonl")
	if err := os.WriteFile(filePath, []byte(nucleiJSONL+"\n"), 0644); err != nil {
		t.Fatalf("failed to write nuclei file: %v", err)
	}

	count, err := utils.ParseNucleiOutput(scanObj.ID, filePath)
	if err != nil {
		t.Fatalf("ParseNucleiOutput error: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 result parsed, got %d", count)
	}

	vulns, err := database.GetVulnerabilities(scanObj.ID)
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
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	if err := database.Initialize(dbPath); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer func() {
		if database.DB != nil {
			database.DB.Close()
			database.DB = nil
		}
	}()

	scanObj, err := database.CreateScan("example.com", "wildcard", tempDir, "{}")
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}

	if err := database.AddSubdomain(scanObj.ID, "example.com", "test"); err != nil {
		t.Fatalf("failed to add subdomain: %v", err)
	}

	httpxJSONL := `{"url":"https://example.com/","status_code":200,"title":"Test Title","content_type":"text/html","tech":["Nginx","Go"],"host":"example.com"}`
	filePath := filepath.Join(tempDir, "httpx.jsonl")
	if err := os.WriteFile(filePath, []byte(httpxJSONL+"\n"), 0644); err != nil {
		t.Fatalf("failed to write httpx file: %v", err)
	}

	count, err := utils.ParseHttpxOutput(scanObj.ID, filePath)
	if err != nil {
		t.Fatalf("ParseHttpxOutput error: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 result parsed, got %d", count)
	}

	urls, err := database.GetURLs(scanObj.ID)
	if err != nil {
		t.Fatalf("GetURLs error: %v", err)
	}

	if len(urls) != 1 {
		t.Fatalf("expected 1 URL, got %d", len(urls))
	}

	if urls[0].URL != "https://example.com/" {
		t.Errorf("expected URL 'https://example.com/', got %q", urls[0].URL)
	}

	subs, err := database.GetLiveSubdomains(scanObj.ID)
	if err != nil {
		t.Fatalf("GetLiveSubdomains error: %v", err)
	}

	if len(subs) != 1 {
		t.Errorf("expected subdomain to be live, but live count is %d", len(subs))
	}
}

func TestParseDalfoxOutput_TextMode(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	if err := database.Initialize(dbPath); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer func() {
		if database.DB != nil {
			database.DB.Close()
			database.DB = nil
		}
	}()

	scanObj, err := database.CreateScan("example.com", "wildcard", tempDir, "{}")
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}

	dalfoxOutput := `[POC][G][VULN] http://sub.example.com/index.php?q=%3Cscript%3Ealert(1)%3C/script%3E`
	filePath := filepath.Join(tempDir, "dalfox.txt")
	if err := os.WriteFile(filePath, []byte(dalfoxOutput+"\n"), 0644); err != nil {
		t.Fatalf("failed to write dalfox file: %v", err)
	}

	count, err := utils.ParseDalfoxOutput(scanObj.ID, filePath)
	if err != nil {
		t.Fatalf("ParseDalfoxOutput error: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 result parsed, got %d", count)
	}

	vulns, err := database.GetVulnerabilities(scanObj.ID)
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
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	if err := database.Initialize(dbPath); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer func() {
		if database.DB != nil {
			database.DB.Close()
			database.DB = nil
		}
	}()

	scanObj, err := database.CreateScan("example.com", "wildcard", tempDir, "{}")
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}

	err = database.AddVulnerability(
		scanObj.ID, "example.com", "https://example.com", "rce",
		"Remote Code Execution", "CrItIcAl", "rce finding", "", "",
	)
	if err != nil {
		t.Fatalf("failed to insert vulnerability: %v", err)
	}

	err = utils.ExportVulnerabilities(scanObj.ID, tempDir)
	if err != nil {
		t.Fatalf("ExportVulnerabilities failed: %v", err)
	}

	critPath := filepath.Join(tempDir, utils.ExportFilenames[6])
	content, err := os.ReadFile(critPath)
	if err != nil {
		t.Fatalf("failed to read critical high file: %v", err)
	}

	contentStr := string(content)
	if !strings.Contains(contentStr, "Remote Code Execution") {
		t.Errorf("expected critical vuln to be exported, got content: %q", contentStr)
	}
}

func BenchmarkUnescapeUnicodeURL(b *testing.B) {
	input := "https://example.com/api/v1/search?\\u0071=\\u0076\\u0061\\u006c\\u0075\\u0065"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = utils.UnescapeUnicodeURL(input)
	}
}
