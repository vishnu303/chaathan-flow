package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/vishnu303/chaathan/pkg/config"
)

var telegramEscaper = strings.NewReplacer(
	"_", "\\_",
	"*", "\\*",
	"[", "\\[",
	"]", "\\]",
	"`", "\\`",
	"~", "\\~",
	">", "\\>",
	"#", "\\#",
	"+", "\\+",
	"-", "\\-",
	"=", "\\=",
	"|", "\\|",
	"{", "\\{",
	"}", "\\}",
	".", "\\.",
	"!", "\\!",
	"(", "\\(",
	")", "\\)",
)

// GetOrderedStatsKeys returns the stats keys ordered by preference for display.
func GetOrderedStatsKeys(stats map[string]int) []string {
	preferred := []string{"subdomains", "live", "urls", "endpoints", "ports", "vulnerabilities"}
	var keys []string
	seen := make(map[string]bool)
	for _, k := range preferred {
		if _, ok := stats[k]; ok {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	for k := range stats {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	return keys
}

// Severity levels for comparison
var severityLevels = map[string]int{
	"info":     1,
	"low":      2,
	"medium":   3,
	"high":     4,
	"critical": 5,
}

// Finding represents a security finding to notify about
type Finding struct {
	Target      string    `json:"target"`
	Type        string    `json:"type"` // vulnerability, subdomain, port, etc.
	Name        string    `json:"name"`
	Severity    string    `json:"severity"`
	Description string    `json:"description,omitempty"`
	URL         string    `json:"url,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	TemplateID  string    `json:"template_id,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// ScanComplete represents a completed scan notification
type ScanComplete struct {
	Target     string         `json:"target"`
	ScanID     int64          `json:"scan_id"`
	Duration   time.Duration  `json:"duration"`
	Stats      map[string]int `json:"stats"`
	ReportPath string         `json:"report_path,omitempty"`
}

// StepComplete represents a completed workflow step notification
type StepComplete struct {
	Target          string        `json:"target"`
	ScanID          int64         `json:"scan_id"`
	ScanType        string        `json:"scan_type,omitempty"`
	StepName        string        `json:"step_name"`
	StepDescription string        `json:"step_description,omitempty"`
	StepNumber      int           `json:"step_number"`
	TotalSteps      int           `json:"total_steps"`
	Duration        time.Duration `json:"duration"`
	FindingsCount   int           `json:"findings_count,omitempty"`
	Timestamp       time.Time     `json:"timestamp"`
}

// Notifier handles sending notifications
type Notifier struct {
	cfg    *config.NotificationConfig
	client *http.Client
	// LogFunc, when non-nil, receives structured log lines for every
	// notification attempt (sent, succeeded, failed). The workflow layer
	// wires this to logger.FileDebug so entries appear in --log files
	// without pkg/notify depending on pkg/logger.
	LogFunc func(format string, args ...any)
}

// New creates a new Notifier
func New(cfg *config.NotificationConfig) *Notifier {
	return &Notifier{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// logf writes to LogFunc if set.
func (n *Notifier) logf(format string, args ...any) {
	if n.LogFunc != nil {
		n.LogFunc(format, args...)
	}
}

// ShouldNotify checks if a finding meets the minimum severity threshold
func (n *Notifier) ShouldNotify(severity string) bool {
	if !n.cfg.Enabled {
		return false
	}

	minLevel, ok := severityLevels[strings.ToLower(n.cfg.MinSeverity)]
	if !ok {
		minLevel = severityLevels["high"]
	}

	findingLevel, ok := severityLevels[strings.ToLower(severity)]
	if !ok {
		return false
	}

	return findingLevel >= minLevel
}

// SendFinding sends a notification about a finding
func (n *Notifier) SendFinding(finding Finding) error {
	if finding.Timestamp.IsZero() {
		finding.Timestamp = time.Now()
	}
	if !n.ShouldNotify(finding.Severity) {
		n.logf("notify_finding SKIPPED [%s] %s (below min_severity %s)", finding.Severity, finding.Name, n.cfg.MinSeverity)
		return nil
	}

	n.logf("notify_finding SENDING [%s] %s target=%s type=%s", finding.Severity, finding.Name, finding.Target, finding.Type)

	var errors []string

	// Discord
	if n.cfg.DiscordWebhook != "" {
		if err := n.sendDiscord(finding); err != nil {
			n.logf("notify_finding FAILED discord: %v", err)
			errors = append(errors, fmt.Sprintf("discord: %v", err))
		} else {
			n.logf("notify_finding OK discord")
		}
	}

	// Slack
	if n.cfg.SlackWebhook != "" {
		if err := n.sendSlack(finding); err != nil {
			n.logf("notify_finding FAILED slack: %v", err)
			errors = append(errors, fmt.Sprintf("slack: %v", err))
		} else {
			n.logf("notify_finding OK slack")
		}
	}

	// Telegram
	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
		if err := n.sendTelegram(finding); err != nil {
			n.logf("notify_finding FAILED telegram: %v", err)
			errors = append(errors, fmt.Sprintf("telegram: %v", err))
		} else {
			n.logf("notify_finding OK telegram")
		}
	}

	// Generic webhook
	if n.cfg.WebhookURL != "" {
		if err := n.sendWebhook(finding); err != nil {
			n.logf("notify_finding FAILED webhook: %v", err)
			errors = append(errors, fmt.Sprintf("webhook: %v", err))
		} else {
			n.logf("notify_finding OK webhook")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("notification errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// SendScanComplete sends a notification when a scan completes
func (n *Notifier) SendScanComplete(scan ScanComplete) error {
	if !n.cfg.Enabled {
		n.logf("notify_scan_complete SKIPPED target=%s (notifications disabled)", scan.Target)
		return nil
	}

	n.logf("notify_scan_complete SENDING target=%s scan_id=%d duration=%s", scan.Target, scan.ScanID, scan.Duration)

	var errors []string

	if n.cfg.DiscordWebhook != "" {
		if err := n.sendDiscordScanComplete(scan); err != nil {
			n.logf("notify_scan_complete FAILED discord: %v", err)
			errors = append(errors, fmt.Sprintf("discord: %v", err))
		} else {
			n.logf("notify_scan_complete OK discord")
		}
	}

	if n.cfg.SlackWebhook != "" {
		if err := n.sendSlackScanComplete(scan); err != nil {
			n.logf("notify_scan_complete FAILED slack: %v", err)
			errors = append(errors, fmt.Sprintf("slack: %v", err))
		} else {
			n.logf("notify_scan_complete OK slack")
		}
	}

	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
		if err := n.sendTelegramScanComplete(scan); err != nil {
			n.logf("notify_scan_complete FAILED telegram: %v", err)
			errors = append(errors, fmt.Sprintf("telegram: %v", err))
		} else {
			n.logf("notify_scan_complete OK telegram")
		}
	}

	if n.cfg.WebhookURL != "" {
		if err := n.sendWebhookScanComplete(scan); err != nil {
			n.logf("notify_scan_complete FAILED webhook: %v", err)
			errors = append(errors, fmt.Sprintf("webhook: %v", err))
		} else {
			n.logf("notify_scan_complete OK webhook")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("notification errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// SendStepComplete sends a notification when a workflow step completes
func (n *Notifier) SendStepComplete(step StepComplete) error {
	if step.Timestamp.IsZero() {
		step.Timestamp = time.Now()
	}
	if !n.cfg.Enabled || !n.cfg.StepComplete {
		n.logf("notify_step_complete SKIPPED step=%s (%d/%d) target=%s (notifications/step_complete disabled)", step.StepName, step.StepNumber, step.TotalSteps, step.Target)
		return nil
	}

	n.logf("notify_step_complete SENDING step=%s (%d/%d) target=%s", step.StepName, step.StepNumber, step.TotalSteps, step.Target)

	var errors []string

	if n.cfg.DiscordWebhook != "" {
		if err := n.sendDiscordStepComplete(step); err != nil {
			n.logf("notify_step_complete FAILED discord: %v", err)
			errors = append(errors, fmt.Sprintf("discord: %v", err))
		} else {
			n.logf("notify_step_complete OK discord")
		}
	}

	if n.cfg.SlackWebhook != "" {
		if err := n.sendSlackStepComplete(step); err != nil {
			n.logf("notify_step_complete FAILED slack: %v", err)
			errors = append(errors, fmt.Sprintf("slack: %v", err))
		} else {
			n.logf("notify_step_complete OK slack")
		}
	}

	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
		if err := n.sendTelegramStepComplete(step); err != nil {
			n.logf("notify_step_complete FAILED telegram: %v", err)
			errors = append(errors, fmt.Sprintf("telegram: %v", err))
		} else {
			n.logf("notify_step_complete OK telegram")
		}
	}

	if n.cfg.WebhookURL != "" {
		if err := n.sendWebhookStepComplete(step); err != nil {
			n.logf("notify_step_complete FAILED webhook: %v", err)
			errors = append(errors, fmt.Sprintf("webhook: %v", err))
		} else {
			n.logf("notify_step_complete OK webhook")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("notification errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// Discord notification
func (n *Notifier) sendDiscord(finding Finding) error {
	color := getDiscordColor(finding.Severity)

	embed := map[string]any{
		"title":       fmt.Sprintf("[%s] %s", strings.ToUpper(finding.Severity), finding.Name),
		"description": finding.Description,
		"color":       color,
		"fields": []map[string]any{
			{"name": "Target", "value": finding.Target, "inline": true},
			{"name": "Type", "value": finding.Type, "inline": true},
		},
		"timestamp": finding.Timestamp.Format(time.RFC3339),
		"footer": map[string]string{
			"text": "Chaathan Security Scanner",
		},
	}

	if finding.URL != "" {
		embed["url"] = finding.URL
		embed["fields"] = append(embed["fields"].([]map[string]any),
			map[string]any{"name": "URL", "value": finding.URL, "inline": false})
	}

	if finding.TemplateID != "" {
		embed["fields"] = append(embed["fields"].([]map[string]any),
			map[string]any{"name": "Template", "value": finding.TemplateID, "inline": true})
	}

	payload := map[string]any{
		"embeds": []map[string]any{embed},
	}

	return n.postJSON(n.cfg.DiscordWebhook, payload)
}

func (n *Notifier) sendDiscordScanComplete(scan ScanComplete) error {
	fields := []map[string]any{
		{"name": "Target", "value": scan.Target, "inline": true},
		{"name": "Duration", "value": scan.Duration.String(), "inline": true},
	}

	for _, k := range GetOrderedStatsKeys(scan.Stats) {
		fields = append(fields, map[string]any{
			"name": TitleCase(k), "value": fmt.Sprintf("%d", scan.Stats[k]), "inline": true,
		})
	}

	embed := map[string]any{
		"title":       "Scan Completed",
		"description": fmt.Sprintf("Scan #%d for `%s` has completed", scan.ScanID, scan.Target),
		"color":       0x00FF00, // Green
		"fields":      fields,
		"footer": map[string]string{
			"text": "Chaathan Security Scanner",
		},
	}

	payload := map[string]any{
		"embeds": []map[string]any{embed},
	}

	return n.postJSON(n.cfg.DiscordWebhook, payload)
}

func (n *Notifier) sendDiscordStepComplete(step StepComplete) error {
	fields := []map[string]any{
		{"name": "Target", "value": step.Target, "inline": true},
		{"name": "Step", "value": fmt.Sprintf("%d/%d", step.StepNumber, step.TotalSteps), "inline": true},
		{"name": "Duration", "value": step.Duration.String(), "inline": true},
		{"name": "Findings", "value": fmt.Sprintf("%d", step.FindingsCount), "inline": true},
	}

	if step.ScanType != "" {
		fields = append(fields, map[string]any{
			"name": "Scan Type", "value": step.ScanType, "inline": true,
		})
	}

	embed := map[string]any{
		"title":       "Step Completed",
		"description": formatStepLabel(step),
		"color":       0x0099FF,
		"fields":      fields,
		"timestamp":   step.Timestamp.Format(time.RFC3339),
		"footer": map[string]string{
			"text": "Chaathan Security Scanner",
		},
	}

	payload := map[string]any{
		"embeds": []map[string]any{embed},
	}

	return n.postJSON(n.cfg.DiscordWebhook, payload)
}

// Slack notification
func (n *Notifier) sendSlack(finding Finding) error {
	color := getSlackColor(finding.Severity)

	attachment := map[string]any{
		"color": color,
		"title": fmt.Sprintf("[%s] %s", strings.ToUpper(finding.Severity), finding.Name),
		"text":  finding.Description,
		"fields": []map[string]any{
			{"title": "Target", "value": finding.Target, "short": true},
			{"title": "Type", "value": finding.Type, "short": true},
		},
		"footer": "Chaathan Security Scanner",
		"ts":     finding.Timestamp.Unix(),
	}

	if finding.URL != "" {
		attachment["title_link"] = finding.URL
	}

	payload := map[string]any{
		"attachments": []map[string]any{attachment},
	}

	return n.postJSON(n.cfg.SlackWebhook, payload)
}

func (n *Notifier) sendSlackScanComplete(scan ScanComplete) error {
	fields := []map[string]any{
		{"title": "Target", "value": scan.Target, "short": true},
		{"title": "Duration", "value": scan.Duration.String(), "short": true},
	}

	for _, k := range GetOrderedStatsKeys(scan.Stats) {
		fields = append(fields, map[string]any{
			"title": TitleCase(k), "value": fmt.Sprintf("%d", scan.Stats[k]), "short": true,
		})
	}

	attachment := map[string]any{
		"color":  "good",
		"title":  "Scan Completed",
		"text":   fmt.Sprintf("Scan #%d for `%s` has completed", scan.ScanID, scan.Target),
		"fields": fields,
		"footer": "Chaathan Security Scanner",
	}

	payload := map[string]any{
		"attachments": []map[string]any{attachment},
	}

	return n.postJSON(n.cfg.SlackWebhook, payload)
}

func (n *Notifier) sendSlackStepComplete(step StepComplete) error {
	fields := []map[string]any{
		{"title": "Target", "value": step.Target, "short": true},
		{"title": "Step", "value": fmt.Sprintf("%d/%d", step.StepNumber, step.TotalSteps), "short": true},
		{"title": "Duration", "value": step.Duration.String(), "short": true},
		{"title": "Findings", "value": fmt.Sprintf("%d", step.FindingsCount), "short": true},
	}

	if step.ScanType != "" {
		fields = append(fields, map[string]any{
			"title": "Scan Type", "value": step.ScanType, "short": true,
		})
	}

	attachment := map[string]any{
		"color":  "#0099FF",
		"title":  "Step Completed",
		"text":   formatStepLabel(step),
		"fields": fields,
		"footer": "Chaathan Security Scanner",
		"ts":     step.Timestamp.Unix(),
	}

	payload := map[string]any{
		"attachments": []map[string]any{attachment},
	}

	return n.postJSON(n.cfg.SlackWebhook, payload)
}

// Telegram notification
func (n *Notifier) sendTelegram(finding Finding) error {
	header := getSeverityEmoji(finding.Severity)
	sev := strings.ToUpper(finding.Severity)

	text := fmt.Sprintf(
		"%s *%s Finding*\n\n"+
			"━━━━━━━━━━━━━━━━━━━━\n"+
			"⚡ *\\[%s\\] %s*\n"+
			"━━━━━━━━━━━━━━━━━━━━\n"+
			"🎯 *Target*    %s\n"+
			"🔖 *Type*    %s",
		header, EscapeMarkdown(sev),
		sev, EscapeMarkdown(finding.Name),
		EscapeMarkdown(finding.Target),
		EscapeMarkdown(finding.Type),
	)

	if finding.Description != "" {
		text += fmt.Sprintf("\n📝 *Details*    %s", EscapeMarkdown(finding.Description))
	}

	if finding.URL != "" {
		text += fmt.Sprintf("\n🔗 *URL*    %s", EscapeMarkdown(finding.URL))
	}

	if finding.TemplateID != "" {
		text += fmt.Sprintf("\n🗂 *Template*    %s", EscapeMarkdown(finding.TemplateID))
	}

	text += "\n━━━━━━━━━━━━━━━━━━━━\n_Chaathan Scanner_"

	return n.sendTelegramMessage(text)
}

func (n *Notifier) sendTelegramScanComplete(scan ScanComplete) error {
	text := fmt.Sprintf(
		"🏁 *Scan Completed*\n\n"+
			"━━━━━━━━━━━━━━━━━━━━\n"+
			"🎯 *Target*    %s\n"+
			"🔢 *Scan ID*    %d\n"+
			"━━━━━━━━━━━━━━━━━━━━\n"+
			"📊 *Results*\n",
		EscapeMarkdown(scan.Target),
		scan.ScanID,
	)

	// Display stats in preferred order
	for _, k := range GetOrderedStatsKeys(scan.Stats) {
		text += fmt.Sprintf("%s %s    %d\n", statEmoji(k), EscapeMarkdown(TitleCase(k)), scan.Stats[k])
	}

	text += fmt.Sprintf(
		"━━━━━━━━━━━━━━━━━━━━\n"+
			"⏱ *Duration*    %s\n"+
			"_Chaathan Scanner_",
		EscapeMarkdown(FormatDuration(scan.Duration)),
	)

	return n.sendTelegramMessage(text)
}

func (n *Notifier) sendTelegramStepComplete(step StepComplete) error {
	findings := ""
	if step.FindingsCount > 0 {
		findings = fmt.Sprintf("*%d* 🚨", step.FindingsCount)
	} else {
		findings = "0"
	}

	text := fmt.Sprintf(
		"✅ *Step Completed*\n\n"+
			"━━━━━━━━━━━━━━━━━━━━\n"+
			"🎯 *Target*    %s\n"+
			"📊 *Progress*    %d / %d\n"+
			"📋 *Step*    %s\n"+
			"⏱ *Duration*    %s\n"+
			"🔍 *Findings*    %s",
		EscapeMarkdown(step.Target),
		step.StepNumber,
		step.TotalSteps,
		EscapeMarkdown(formatStepLabel(step)),
		EscapeMarkdown(FormatDuration(step.Duration)),
		findings,
	)

	if step.ScanType != "" {
		text += fmt.Sprintf("\n🏷 *Type*    %s", EscapeMarkdown(step.ScanType))
	}

	text += "\n━━━━━━━━━━━━━━━━━━━━\n_Chaathan Scanner_"

	return n.sendTelegramMessage(text)
}

func (n *Notifier) sendTelegramMessage(text string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.cfg.TelegramBotToken)

	payload := map[string]any{
		"chat_id":    n.cfg.TelegramChatID,
		"text":       text,
		"parse_mode": "MarkdownV2",
	}

	return n.postJSON(url, payload)
}

// Generic webhook
func (n *Notifier) sendWebhook(finding Finding) error {
	payload := map[string]any{
		"event":   "finding",
		"finding": finding,
	}

	return n.postJSON(n.cfg.WebhookURL, payload)
}

func (n *Notifier) sendWebhookStepComplete(step StepComplete) error {
	payload := map[string]any{
		"event": "step_complete",
		"step":  step,
	}

	return n.postJSON(n.cfg.WebhookURL, payload)
}

func (n *Notifier) sendWebhookScanComplete(scan ScanComplete) error {
	payload := map[string]any{
		"event": "scan_complete",
		"scan":  scan,
	}

	return n.postJSON(n.cfg.WebhookURL, payload)
}

// Helper functions

// postJSON sends a JSON payload with retry logic for transient failures.
// Retries up to 2 times with exponential backoff (1s, 2s) for network errors
// and 5xx server errors. Client errors (4xx) are not retried.
func (n *Notifier) postJSON(url string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	const maxRetries = 2
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt) * time.Second
			n.logf("[WARN] notification retry %d/%d after %v", attempt, maxRetries, backoff)
			time.Sleep(backoff)
		}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := n.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue // network error — retry
		}

		if resp.StatusCode < 400 {
			io.Copy(io.Discard, resp.Body) // drain body so connection can be reused
			resp.Body.Close()
			return nil // success
		}

		// Read error body for diagnostic detail (e.g. Telegram MarkdownV2 parse errors)
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if len(errBody) > 0 {
			lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, string(errBody))
		} else {
			lastErr = fmt.Errorf("received error status: %d", resp.StatusCode)
		}

		// Only retry on server errors (5xx); client errors (4xx) are permanent
		if resp.StatusCode < 500 {
			return lastErr
		}
	}

	return lastErr
}

func getDiscordColor(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 0xFF0000 // Red
	case "high":
		return 0xFF6600 // Orange
	case "medium":
		return 0xFFFF00 // Yellow
	case "low":
		return 0x00FF00 // Green
	case "info":
		return 0x0099FF // Blue
	default:
		return 0x808080 // Gray
	}
}

func getSlackColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "danger"
	case "high":
		return "#FF6600"
	case "medium":
		return "warning"
	case "low":
		return "good"
	case "info":
		return "#0099FF"
	default:
		return "#808080"
	}
}

func getSeverityEmoji(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	case "info":
		return "🔵"
	default:
		return "⚪"
	}
}

func formatStepLabel(step StepComplete) string {
	if step.StepDescription != "" {
		return step.StepDescription
	}
	return step.StepName
}

func EscapeMarkdown(s string) string {
	// Escape all Telegram MarkdownV2 special characters to prevent
	// injection from attacker-controlled finding names, template IDs, etc.
	// Backslash MUST be escaped first to avoid double-escaping the
	// backslashes we insert for the other characters.
	s = strings.ReplaceAll(s, "\\", "\\\\")
	return telegramEscaper.Replace(s)
}

// TitleCase capitalises the first rune of s (replaces deprecated strings.Title).
func TitleCase(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// FormatDuration converts a duration to a clean human-readable string.
// e.g. 19m56.166s → "19m 56s", 3723s → "1h 2m", 45s → "45s"
func FormatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh %dm", h, m)
}

// statEmoji returns an emoji for a known scan stat key.
func statEmoji(key string) string {
	switch strings.ToLower(key) {
	case "subdomains":
		return "🌐"
	case "live":
		return "💚"
	case "urls":
		return "🔗"
	case "endpoints":
		return "📌"
	case "ports":
		return "⚓"
	case "vulnerabilities", "vulns":
		return "🚨"
	default:
		return "📊"
	}
}
