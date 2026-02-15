package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/vishnu303/chaathan-flow/pkg/config"
	"net/http"
	"strings"
	"time"
)

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

// Notifier handles sending notifications
type Notifier struct {
	cfg    *config.NotificationConfig
	client *http.Client
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
	if !n.ShouldNotify(finding.Severity) {
		return nil
	}

	var errors []string

	// Discord
	if n.cfg.DiscordWebhook != "" {
		if err := n.sendDiscord(finding); err != nil {
			errors = append(errors, fmt.Sprintf("discord: %v", err))
		}
	}

	// Slack
	if n.cfg.SlackWebhook != "" {
		if err := n.sendSlack(finding); err != nil {
			errors = append(errors, fmt.Sprintf("slack: %v", err))
		}
	}

	// Telegram
	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
		if err := n.sendTelegram(finding); err != nil {
			errors = append(errors, fmt.Sprintf("telegram: %v", err))
		}
	}

	// Generic webhook
	if n.cfg.WebhookURL != "" {
		if err := n.sendWebhook(finding); err != nil {
			errors = append(errors, fmt.Sprintf("webhook: %v", err))
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
		return nil
	}

	var errors []string

	if n.cfg.DiscordWebhook != "" {
		if err := n.sendDiscordScanComplete(scan); err != nil {
			errors = append(errors, fmt.Sprintf("discord: %v", err))
		}
	}

	if n.cfg.SlackWebhook != "" {
		if err := n.sendSlackScanComplete(scan); err != nil {
			errors = append(errors, fmt.Sprintf("slack: %v", err))
		}
	}

	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
		if err := n.sendTelegramScanComplete(scan); err != nil {
			errors = append(errors, fmt.Sprintf("telegram: %v", err))
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

	embed := map[string]interface{}{
		"title":       fmt.Sprintf("[%s] %s", strings.ToUpper(finding.Severity), finding.Name),
		"description": finding.Description,
		"color":       color,
		"fields": []map[string]interface{}{
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
		embed["fields"] = append(embed["fields"].([]map[string]interface{}),
			map[string]interface{}{"name": "URL", "value": finding.URL, "inline": false})
	}

	if finding.TemplateID != "" {
		embed["fields"] = append(embed["fields"].([]map[string]interface{}),
			map[string]interface{}{"name": "Template", "value": finding.TemplateID, "inline": true})
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}

	return n.postJSON(n.cfg.DiscordWebhook, payload)
}

func (n *Notifier) sendDiscordScanComplete(scan ScanComplete) error {
	fields := []map[string]interface{}{
		{"name": "Target", "value": scan.Target, "inline": true},
		{"name": "Duration", "value": scan.Duration.String(), "inline": true},
	}

	for k, v := range scan.Stats {
		fields = append(fields, map[string]interface{}{
			"name": k, "value": fmt.Sprintf("%d", v), "inline": true,
		})
	}

	embed := map[string]interface{}{
		"title":       "Scan Completed",
		"description": fmt.Sprintf("Scan #%d for `%s` has completed", scan.ScanID, scan.Target),
		"color":       0x00FF00, // Green
		"fields":      fields,
		"footer": map[string]string{
			"text": "Chaathan Security Scanner",
		},
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}

	return n.postJSON(n.cfg.DiscordWebhook, payload)
}

// Slack notification
func (n *Notifier) sendSlack(finding Finding) error {
	color := getSlackColor(finding.Severity)

	attachment := map[string]interface{}{
		"color": color,
		"title": fmt.Sprintf("[%s] %s", strings.ToUpper(finding.Severity), finding.Name),
		"text":  finding.Description,
		"fields": []map[string]interface{}{
			{"title": "Target", "value": finding.Target, "short": true},
			{"title": "Type", "value": finding.Type, "short": true},
		},
		"footer": "Chaathan Security Scanner",
		"ts":     finding.Timestamp.Unix(),
	}

	if finding.URL != "" {
		attachment["title_link"] = finding.URL
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{attachment},
	}

	return n.postJSON(n.cfg.SlackWebhook, payload)
}

func (n *Notifier) sendSlackScanComplete(scan ScanComplete) error {
	fields := []map[string]interface{}{
		{"title": "Target", "value": scan.Target, "short": true},
		{"title": "Duration", "value": scan.Duration.String(), "short": true},
	}

	for k, v := range scan.Stats {
		fields = append(fields, map[string]interface{}{
			"title": k, "value": fmt.Sprintf("%d", v), "short": true,
		})
	}

	attachment := map[string]interface{}{
		"color":  "good",
		"title":  "Scan Completed",
		"text":   fmt.Sprintf("Scan #%d for `%s` has completed", scan.ScanID, scan.Target),
		"fields": fields,
		"footer": "Chaathan Security Scanner",
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{attachment},
	}

	return n.postJSON(n.cfg.SlackWebhook, payload)
}

// Telegram notification
func (n *Notifier) sendTelegram(finding Finding) error {
	emoji := getSeverityEmoji(finding.Severity)

	text := fmt.Sprintf(`%s *[%s] %s*

*Target:* %s
*Type:* %s`,
		emoji,
		strings.ToUpper(finding.Severity),
		escapeMarkdown(finding.Name),
		escapeMarkdown(finding.Target),
		escapeMarkdown(finding.Type),
	)

	if finding.Description != "" {
		text += fmt.Sprintf("\n*Description:* %s", escapeMarkdown(finding.Description))
	}

	if finding.URL != "" {
		text += fmt.Sprintf("\n*URL:* %s", finding.URL)
	}

	return n.sendTelegramMessage(text)
}

func (n *Notifier) sendTelegramScanComplete(scan ScanComplete) error {
	text := fmt.Sprintf(`✅ *Scan Completed*

*Target:* %s
*Scan ID:* %d
*Duration:* %s`,
		escapeMarkdown(scan.Target),
		scan.ScanID,
		scan.Duration.String(),
	)

	for k, v := range scan.Stats {
		text += fmt.Sprintf("\n*%s:* %d", k, v)
	}

	return n.sendTelegramMessage(text)
}

func (n *Notifier) sendTelegramMessage(text string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.cfg.TelegramBotToken)

	payload := map[string]interface{}{
		"chat_id":    n.cfg.TelegramChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}

	return n.postJSON(url, payload)
}

// Generic webhook
func (n *Notifier) sendWebhook(finding Finding) error {
	payload := map[string]interface{}{
		"event":   "finding",
		"finding": finding,
	}

	return n.postJSON(n.cfg.WebhookURL, payload)
}

// Helper functions

func (n *Notifier) postJSON(url string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("received error status: %d", resp.StatusCode)
	}

	return nil
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

func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"`", "\\`",
	)
	return replacer.Replace(s)
}
