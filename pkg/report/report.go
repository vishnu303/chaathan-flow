package report

import (
	"encoding/json"
	"fmt"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// ReportFormat represents the output format
type ReportFormat string

const (
	FormatMarkdown ReportFormat = "markdown"
	FormatJSON     ReportFormat = "json"
	FormatHTML     ReportFormat = "html"
	FormatText     ReportFormat = "text"
)

// Report represents a scan report
type Report struct {
	Scan            *database.Scan           `json:"scan"`
	Stats           *database.ScanStats      `json:"stats"`
	Subdomains      []database.Subdomain     `json:"subdomains"`
	LiveSubdomains  []database.Subdomain     `json:"live_subdomains"`
	Ports           []database.Port          `json:"ports"`
	URLs            []database.URL           `json:"urls"`
	Vulnerabilities []database.Vulnerability `json:"vulnerabilities"`
	Endpoints       []database.Endpoint      `json:"endpoints"`
	GeneratedAt     time.Time                `json:"generated_at"`
}

// Generate creates a report for the given scan ID
func Generate(scanID int64) (*Report, error) {
	scan, err := database.GetScan(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan: %w", err)
	}

	stats, err := database.GetScanStats(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan stats: %w", err)
	}

	subdomains, err := database.GetSubdomains(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subdomains: %w", err)
	}

	liveSubdomains, err := database.GetLiveSubdomains(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get live subdomains: %w", err)
	}

	ports, err := database.GetPorts(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ports: %w", err)
	}

	urls, err := database.GetURLs(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get urls: %w", err)
	}

	vulns, err := database.GetVulnerabilities(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities: %w", err)
	}

	endpoints, err := database.GetEndpoints(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoints: %w", err)
	}

	return &Report{
		Scan:            scan,
		Stats:           stats,
		Subdomains:      subdomains,
		LiveSubdomains:  liveSubdomains,
		Ports:           ports,
		URLs:            urls,
		Vulnerabilities: vulns,
		Endpoints:       endpoints,
		GeneratedAt:     time.Now(),
	}, nil
}

// Export exports the report to the specified format
func (r *Report) Export(format ReportFormat, outputPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	var content string
	var err error

	switch format {
	case FormatJSON:
		content, err = r.toJSON()
	case FormatMarkdown:
		content, err = r.toMarkdown()
	case FormatHTML:
		content, err = r.toHTML()
	case FormatText:
		content, err = r.toText()
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, []byte(content), 0644)
}

func (r *Report) toJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal to JSON: %w", err)
	}
	return string(data), nil
}

func (r *Report) toMarkdown() (string, error) {
	tmpl := `# Chaathan Scan Report

## Scan Information

| Field | Value |
|-------|-------|
| **Target** | {{.Scan.Target}} |
| **Scan ID** | {{.Scan.ID}} |
| **Type** | {{.Scan.Type}} |
| **Status** | {{.Scan.Status}} |
| **Started** | {{.Scan.StartedAt.Format "2006-01-02 15:04:05"}} |
{{if .Scan.CompletedAt}}| **Completed** | {{.Scan.CompletedAt.Format "2006-01-02 15:04:05"}} |{{end}}
| **Results Directory** | {{.Scan.ResultDir}} |

---

## Summary

| Metric | Count |
|--------|-------|
| **Total Subdomains** | {{.Stats.TotalSubdomains}} |
| **Live Subdomains** | {{.Stats.LiveSubdomains}} |
| **Open Ports** | {{.Stats.TotalPorts}} |
| **URLs Discovered** | {{.Stats.TotalURLs}} |
| **Endpoints Found** | {{.Stats.TotalEndpoints}} |

### Vulnerabilities by Severity

| Severity | Count |
|----------|-------|
{{range $sev, $count := .Stats.Vulnerabilities}}| **{{$sev | ToUpper}}** | {{$count}} |
{{end}}

---

## Vulnerabilities

{{if .Vulnerabilities}}
{{range .Vulnerabilities}}
### {{.Severity | ToUpper}}: {{.Name}}

- **Host:** {{.Host}}
{{if .URL}}- **URL:** {{.URL}}{{end}}
{{if .TemplateID}}- **Template:** {{.TemplateID}}{{end}}
{{if .Description}}- **Description:** {{.Description}}{{end}}
{{if .Evidence}}
**Evidence:**
` + "```" + `
{{.Evidence}}
` + "```" + `
{{end}}

---
{{end}}
{{else}}
No vulnerabilities found.
{{end}}

## Live Subdomains ({{len .LiveSubdomains}})

{{if .LiveSubdomains}}
| Domain | IP Address | Source |
|--------|------------|--------|
{{range .LiveSubdomains}}| {{.Domain}} | {{.IPAddress}} | {{.Source}} |
{{end}}
{{else}}
No live subdomains found.
{{end}}

---

## Open Ports ({{len .Ports}})

{{if .Ports}}
| Host | Port | Protocol | Service |
|------|------|----------|---------|
{{range .Ports}}| {{.Host}} | {{.Port}} | {{.Protocol}} | {{.Service}} |
{{end}}
{{else}}
No open ports found.
{{end}}

---

## URLs ({{len .URLs}})

{{if .URLs}}
| URL | Status | Title |
|-----|--------|-------|
{{range .URLs}}| {{.URL}} | {{.StatusCode}} | {{.Title}} |
{{end}}
{{else}}
No URLs discovered.
{{end}}

---

## Endpoints ({{len .Endpoints}})

{{if .Endpoints}}
| Endpoint | Method | Source |
|----------|--------|--------|
{{range .Endpoints}}| {{.URL}} | {{.Method}} | {{.Source}} |
{{end}}
{{else}}
No endpoints found.
{{end}}

---

*Report generated by Chaathan on {{.GeneratedAt.Format "2006-01-02 15:04:05"}}*
`

	funcMap := template.FuncMap{
		"ToUpper": strings.ToUpper,
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf strings.Builder
	if err := t.Execute(&buf, r); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

func (r *Report) toHTML() (string, error) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chaathan Scan Report - {{.Scan.Target}}</title>
    <style>
        :root {
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --critical: #f85149;
            --high: #f0883e;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1, h2, h3 { color: #fff; margin-bottom: 1rem; }
        h1 { font-size: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }
        h2 { font-size: 1.5rem; margin-top: 2rem; }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            margin: 1rem 0;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
        }
        .stat-value { font-size: 2rem; font-weight: bold; color: var(--info); }
        .stat-label { color: var(--text-muted); font-size: 0.875rem; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { 
            padding: 0.75rem; 
            text-align: left; 
            border-bottom: 1px solid var(--border); 
        }
        th { background: var(--card-bg); color: #fff; }
        tr:hover { background: rgba(56, 139, 253, 0.1); }
        .severity { 
            padding: 0.25rem 0.5rem; 
            border-radius: 4px; 
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.75rem;
        }
        .severity-critical { background: var(--critical); color: #fff; }
        .severity-high { background: var(--high); color: #fff; }
        .severity-medium { background: var(--medium); color: #000; }
        .severity-low { background: var(--low); color: #000; }
        .severity-info { background: var(--info); color: #fff; }
        .vuln-card {
            border-left: 4px solid var(--border);
            padding-left: 1rem;
            margin: 1rem 0;
        }
        .vuln-card.critical { border-color: var(--critical); }
        .vuln-card.high { border-color: var(--high); }
        .vuln-card.medium { border-color: var(--medium); }
        .vuln-card.low { border-color: var(--low); }
        .evidence { 
            background: #000; 
            padding: 1rem; 
            border-radius: 4px; 
            overflow-x: auto;
            font-family: monospace;
            font-size: 0.875rem;
        }
        .footer { 
            margin-top: 2rem; 
            padding-top: 1rem; 
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Chaathan Scan Report</h1>
        
        <div class="card">
            <h3>Scan Information</h3>
            <table>
                <tr><td><strong>Target</strong></td><td>{{.Scan.Target}}</td></tr>
                <tr><td><strong>Scan ID</strong></td><td>{{.Scan.ID}}</td></tr>
                <tr><td><strong>Type</strong></td><td>{{.Scan.Type}}</td></tr>
                <tr><td><strong>Status</strong></td><td>{{.Scan.Status}}</td></tr>
                <tr><td><strong>Started</strong></td><td>{{.Scan.StartedAt.Format "2006-01-02 15:04:05"}}</td></tr>
            </table>
        </div>

        <h2>Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{.Stats.TotalSubdomains}}</div>
                <div class="stat-label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Stats.LiveSubdomains}}</div>
                <div class="stat-label">Live</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Stats.TotalPorts}}</div>
                <div class="stat-label">Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Stats.TotalURLs}}</div>
                <div class="stat-label">URLs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Stats.TotalEndpoints}}</div>
                <div class="stat-label">Endpoints</div>
            </div>
        </div>

        {{if .Vulnerabilities}}
        <h2>Vulnerabilities ({{len .Vulnerabilities}})</h2>
        {{range .Vulnerabilities}}
        <div class="vuln-card {{.Severity}}">
            <h3><span class="severity severity-{{.Severity}}">{{.Severity}}</span> {{.Name}}</h3>
            <p><strong>Host:</strong> {{.Host}}</p>
            {{if .URL}}<p><strong>URL:</strong> {{.URL}}</p>{{end}}
            {{if .TemplateID}}<p><strong>Template:</strong> {{.TemplateID}}</p>{{end}}
            {{if .Description}}<p>{{.Description}}</p>{{end}}
            {{if .Evidence}}<div class="evidence">{{.Evidence}}</div>{{end}}
        </div>
        {{end}}
        {{end}}

        <h2>Live Subdomains ({{len .LiveSubdomains}})</h2>
        <table>
            <thead><tr><th>Domain</th><th>IP Address</th><th>Source</th></tr></thead>
            <tbody>
            {{range .LiveSubdomains}}
            <tr><td>{{.Domain}}</td><td>{{.IPAddress}}</td><td>{{.Source}}</td></tr>
            {{end}}
            </tbody>
        </table>

        <h2>Open Ports ({{len .Ports}})</h2>
        <table>
            <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th></tr></thead>
            <tbody>
            {{range .Ports}}
            <tr><td>{{.Host}}</td><td>{{.Port}}</td><td>{{.Protocol}}</td><td>{{.Service}}</td></tr>
            {{end}}
            </tbody>
        </table>

        <div class="footer">
            <p>Report generated by Chaathan on {{.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
        </div>
    </div>
</body>
</html>`

	t, err := template.New("html-report").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML template: %w", err)
	}

	var buf strings.Builder
	if err := t.Execute(&buf, r); err != nil {
		return "", fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return buf.String(), nil
}

func (r *Report) toText() (string, error) {
	var sb strings.Builder

	sb.WriteString("=" + strings.Repeat("=", 60) + "\n")
	sb.WriteString("CHAATHAN SCAN REPORT\n")
	sb.WriteString("=" + strings.Repeat("=", 60) + "\n\n")

	sb.WriteString(fmt.Sprintf("Target: %s\n", r.Scan.Target))
	sb.WriteString(fmt.Sprintf("Scan ID: %d\n", r.Scan.ID))
	sb.WriteString(fmt.Sprintf("Status: %s\n", r.Scan.Status))
	sb.WriteString(fmt.Sprintf("Started: %s\n\n", r.Scan.StartedAt.Format("2006-01-02 15:04:05")))

	sb.WriteString("-" + strings.Repeat("-", 40) + "\n")
	sb.WriteString("SUMMARY\n")
	sb.WriteString("-" + strings.Repeat("-", 40) + "\n")
	sb.WriteString(fmt.Sprintf("Subdomains: %d (Live: %d)\n", r.Stats.TotalSubdomains, r.Stats.LiveSubdomains))
	sb.WriteString(fmt.Sprintf("Open Ports: %d\n", r.Stats.TotalPorts))
	sb.WriteString(fmt.Sprintf("URLs: %d\n", r.Stats.TotalURLs))
	sb.WriteString(fmt.Sprintf("Endpoints: %d\n", r.Stats.TotalEndpoints))

	sb.WriteString("\nVulnerabilities:\n")
	for sev, count := range r.Stats.Vulnerabilities {
		sb.WriteString(fmt.Sprintf("  %s: %d\n", strings.ToUpper(sev), count))
	}

	if len(r.Vulnerabilities) > 0 {
		sb.WriteString("\n" + "-" + strings.Repeat("-", 40) + "\n")
		sb.WriteString("VULNERABILITIES\n")
		sb.WriteString("-" + strings.Repeat("-", 40) + "\n")
		for _, v := range r.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("\n[%s] %s\n", strings.ToUpper(v.Severity), v.Name))
			sb.WriteString(fmt.Sprintf("  Host: %s\n", v.Host))
			if v.URL != "" {
				sb.WriteString(fmt.Sprintf("  URL: %s\n", v.URL))
			}
			if v.TemplateID != "" {
				sb.WriteString(fmt.Sprintf("  Template: %s\n", v.TemplateID))
			}
		}
	}

	sb.WriteString("\n" + "-" + strings.Repeat("-", 40) + "\n")
	sb.WriteString("LIVE SUBDOMAINS\n")
	sb.WriteString("-" + strings.Repeat("-", 40) + "\n")
	for _, s := range r.LiveSubdomains {
		sb.WriteString(fmt.Sprintf("%s (%s)\n", s.Domain, s.IPAddress))
	}

	sb.WriteString("\n\nGenerated: " + r.GeneratedAt.Format("2006-01-02 15:04:05") + "\n")

	return sb.String(), nil
}

// QuickSummary returns a brief text summary
func (r *Report) QuickSummary() string {
	var criticalCount, highCount int
	for sev, count := range r.Stats.Vulnerabilities {
		switch strings.ToLower(sev) {
		case "critical":
			criticalCount = count
		case "high":
			highCount = count
		}
	}

	return fmt.Sprintf(
		"Target: %s | Subdomains: %d (Live: %d) | Ports: %d | Vulns: %d critical, %d high",
		r.Scan.Target,
		r.Stats.TotalSubdomains,
		r.Stats.LiveSubdomains,
		r.Stats.TotalPorts,
		criticalCount,
		highCount,
	)
}
