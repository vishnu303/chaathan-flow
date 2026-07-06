package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/paths"
)

// Config represents the main configuration structure
type Config struct {
	// General settings
	General GeneralConfig `yaml:"general"`

	// API Keys for various services
	APIKeys APIKeysConfig `yaml:"api_keys"`

	// Tool-specific configurations
	Tools ToolsConfig `yaml:"tools"`

	// Notification settings
	Notifications NotificationConfig `yaml:"notifications"`

	// Scope settings
	Scope ScopeConfig `yaml:"scope"`

	// Rate limiting
	RateLimits RateLimitConfig `yaml:"rate_limits"`
}

type GeneralConfig struct {
	// Default execution mode: native or docker
	Mode string `yaml:"mode"`

	// Enable verbose logging
	Verbose bool `yaml:"verbose"`

	// Retry configuration
	MaxRetries    int `yaml:"max_retries"`     // number of retries for failed tools (default: 1)
	RetryDelaySec int `yaml:"retry_delay_sec"` // seconds between retries (default: 3)

	// WAF evasion: User-Agent rotation
	UARotation bool   `yaml:"ua_rotation"` // true = rotate real browser UAs on target-facing tools
	UserAgent  string `yaml:"user_agent"`  // override: use this fixed UA instead of rotation

	// WAF evasion: Proxy support
	Proxy string `yaml:"proxy"` // e.g., "socks5://127.0.0.1:9050" or "http://proxy:8080"

	// DNS resolvers file path
	ResolversFile string `yaml:"resolvers_file"`

	// Output directory for scan results
	OutputDir string `yaml:"output_dir"`

	// Database path
	DatabasePath string `yaml:"database_path"`

	// Wordlist paths
	Wordlists WordlistsConfig `yaml:"wordlists"`

	// JS Download Limit for Secret Scanning
	JSLimit int `yaml:"js_limit"`

	// Automated proxy scraping and rotation
	ProxyScraping ProxyScrapingConfig `yaml:"proxy_scraping"`
}

type WordlistsConfig struct {
	// Subdomain wordlist for brute forcing
	Subdomains string `yaml:"subdomains"`

	// Directory fuzzing wordlist
	Directories string `yaml:"directories"`

	// Common parameters wordlist
	Parameters string `yaml:"parameters"`
}

type APIKeysConfig struct {
	// GitHub token for github-subdomains and github-endpoints
	GitHub string `yaml:"github"`

	// Shodan API key
	Shodan string `yaml:"shodan"`

	// Censys API credentials (used by uncover; set censys_id+censys_secret in env or config)
	CensysID     string `yaml:"censys_id"`
	CensysSecret string `yaml:"censys_secret"`
	// Censys is a combined shorthand: set to "id:secret" for uncover -e censys support
	Censys string `yaml:"censys"`

	// Fofa API key for uncover -e fofa support
	Fofa string `yaml:"fofa"`

	// SecurityTrails API key
	SecurityTrails string `yaml:"securitytrails"`

	// VirusTotal API key (also passed to subfinder as provider key)
	VirusTotal string `yaml:"virustotal"`

	// Chaos API key (ProjectDiscovery; also passed to subfinder as provider key)
	Chaos string `yaml:"chaos"`
}

type ToolsConfig struct {
	// Subfinder specific settings
	Subfinder SubfinderConfig `yaml:"subfinder"`

	// Amass specific settings
	Amass AmassConfig `yaml:"amass"`

	// Nuclei specific settings
	Nuclei NucleiConfig `yaml:"nuclei"`

	// Httpx specific settings
	Httpx HttpxConfig `yaml:"httpx"`

	// Naabu specific settings
	Naabu NaabuConfig `yaml:"naabu"`

	// Ffuf specific settings
	Ffuf FfufConfig `yaml:"ffuf"`

	// Dalfox specific settings
	Dalfox DalfoxConfig `yaml:"dalfox"`

	// Katana specific settings
	Katana KatanaConfig `yaml:"katana"`

	// GoSpider specific settings
	GoSpider GoSpiderConfig `yaml:"gospider"`
}

type SubfinderConfig struct {
	Threads int `yaml:"threads"` // concurrent threads for passive enumeration (default: 30)
	Timeout int `yaml:"timeout"` // timeout in seconds per source (default: 30)
}

type AmassConfig struct {
	Timeout int `yaml:"timeout"` // max runtime in minutes for Amass (default: 60)
}

type NucleiConfig struct {
	Concurrency    int      `yaml:"concurrency"`     // concurrent template executions (default: 25)
	RateLimit      int      `yaml:"rate_limit"`      // max requests per second (default: 150)
	ExcludeTags    []string `yaml:"exclude_tags"`    // template tags to exclude (default: [dos, fuzz])
	Severity       []string `yaml:"severity"`        // severities to scan (default: [low, medium, high, critical])
	DisableOOB     *bool    `yaml:"disable_oob"`     // disable Interactsh OOB checks — prevents hangs (default: true)
	MaxTimeout     int      `yaml:"max_timeout_min"` // hard process timeout per Nuclei run in minutes (default: 180)
	DASTAggression string   `yaml:"dast_aggression"` // DAST fuzzing payload count: low/medium/high (default: high)
}

type DalfoxConfig struct {
	MaxURLs        int  `yaml:"max_urls"`         // cap parameterized URLs (default: 500)
	SkipThirdParty *bool `yaml:"skip_third_party"` // filter non-target domains (default: true)
}

type HttpxConfig struct {
	Threads         int      `yaml:"threads"`          // concurrent probing threads (default: 50)
	Timeout         int      `yaml:"timeout"`          // per-request timeout in seconds (default: 10)
	Ports           []string `yaml:"ports"`            // ports to probe (default: [80, 443, 8080, 8443, 8000, 8888])
	FollowRedirects bool     `yaml:"follow_redirects"` // follow HTTP redirects (default: true)
}

type NaabuConfig struct {
	Threads int    `yaml:"threads"` // concurrent scanning threads (default: 25)
	Rate    int    `yaml:"rate"`    // packets per second (default: 1000)
	Ports   string `yaml:"ports"`   // port spec: "top-1000", "80,443,8080", or range (default: top-1000)
	// Timeout represents the maximum runtime in minutes for Naabu.
	// For backwards compatibility, it is kept as "Timeout" rather than "MaxTimeout".
	Timeout int    `yaml:"timeout"` // max runtime in minutes for Naabu (default: 240)
}

type FfufConfig struct {
	Threads    int   `yaml:"threads"`     // concurrent fuzzing threads (default: 50)
	Timeout    int   `yaml:"timeout"`     // per-request timeout in seconds (default: 10)
	MatchCodes []int `yaml:"match_codes"` // HTTP status codes to report as findings (default: 200,201,204,301,...)
	MaxTimeout int   `yaml:"max_timeout_min"` // hard process timeout per ffuf run in minutes (default: 180)
}

type KatanaConfig struct {
	// Timeout represents the maximum runtime in minutes for Katana.
	// For backwards compatibility, it is kept as "Timeout" rather than "MaxTimeout".
	Timeout int `yaml:"timeout"` // max runtime in minutes for Katana (default: 300)
}

type GoSpiderConfig struct {
	// Timeout represents the maximum runtime in minutes for GoSpider.
	// For backwards compatibility, it is kept as "Timeout" rather than "MaxTimeout".
	Timeout int `yaml:"timeout"` // max runtime in minutes for GoSpider (default: 300)
}

type NotificationConfig struct {
	// Enable notifications
	Enabled bool `yaml:"enabled"`

	// Send a notification when each scan step completes
	StepComplete bool `yaml:"step_complete"`

	// Minimum severity to notify: info, low, medium, high, critical
	MinSeverity string `yaml:"min_severity"`

	// Discord webhook URL
	DiscordWebhook string `yaml:"discord_webhook"`

	// Slack webhook URL
	SlackWebhook string `yaml:"slack_webhook"`

	// Telegram bot settings
	TelegramBotToken string `yaml:"telegram_bot_token"`
	TelegramChatID   string `yaml:"telegram_chat_id"`

	// Generic webhook URL
	WebhookURL string `yaml:"webhook_url"`
}

type ScopeConfig struct {
	// In-scope domains/patterns (regex supported)
	InScope []string `yaml:"in_scope"`

	// Out-of-scope domains/patterns (regex supported)
	OutOfScope []string `yaml:"out_of_scope"`

	// Exclude IPs/CIDRs
	ExcludeIPs []string `yaml:"exclude_ips"`

	// Only scan specific ports
	AllowedPorts []int `yaml:"allowed_ports"`
}

type RateLimitConfig struct {
	// Global requests per second limit — acts as a ceiling across all tools.
	// Per-tool rates are configured in their respective tools.* sections.
	GlobalRPS int `yaml:"global_rps"`
}

// ProxyScrapingConfig controls the automated proxy scraping and rotation step.
type ProxyScrapingConfig struct {
	// Max runtime for proxy scraping in minutes (default: 10).
	// Covers both scraping from public sources and checking against the target domain.
	TimeoutMin int `yaml:"timeout_min"`

	// Number of proxies to check simultaneously (default: 256)
	MaxConcurrent int `yaml:"max_concurrent"`

	// Preferred proxy protocol order (default: ["socks5","http","socks4"])
	ProxyTypes []string `yaml:"proxy_types"`

	// Mubeng rotation method: "random" or "sequent" (default: "random")
	RotateMethod string `yaml:"rotate_method"`

	// Rotate proxy after every N requests (default: 1 = every request)
	RotateEvery int `yaml:"rotate_every"`
}


// Global config instance
var Cfg *Config

var expectedKeys = map[string]interface{}{
	"": map[string]interface{}{
		"general":       "GeneralConfig",
		"api_keys":      "APIKeysConfig",
		"tools":         "ToolsConfig",
		"notifications": "NotificationConfig",
		"scope":         "ScopeConfig",
		"rate_limits":   "RateLimitConfig",
	},
	"general": map[string]interface{}{
		"mode":            "string",
		"verbose":         "bool",
		"max_retries":     "int",
		"retry_delay_sec": "int",
		"ua_rotation":     "bool",
		"user_agent":      "string",
		"proxy":           "string",
		"resolvers_file":  "string",
		"output_dir":      "string",
		"database_path":   "string",
		"wordlists":       "WordlistsConfig",
		"js_limit":        "int",
		"proxy_scraping":  "ProxyScrapingConfig",
	},
	"general.wordlists": map[string]interface{}{
		"subdomains":  "string",
		"directories": "string",
		"parameters":  "string",
	},
	"general.proxy_scraping": map[string]interface{}{
		"timeout_min":    "int",
		"max_concurrent": "int",
		"proxy_types":    "slice",
		"rotate_method":  "string",
		"rotate_every":   "int",
	},
	"api_keys": map[string]interface{}{
		"shodan":         "string",
		"censys":         "string",
		"censys_id":      "string",
		"censys_secret":  "string",
		"fofa":           "string",
		"github":         "string",
		"securitytrails": "string",
		"virustotal":     "string",
		"chaos":          "string",
	},
	"tools": map[string]interface{}{
		"subfinder": "SubfinderConfig",
		"amass":     "AmassConfig",
		"nuclei":    "NucleiConfig",
		"httpx":     "HttpxConfig",
		"naabu":     "NaabuConfig",
		"ffuf":      "FfufConfig",
		"dalfox":    "DalfoxConfig",
		"katana":    "KatanaConfig",
		"gospider":  "GoSpiderConfig",
	},
	"tools.subfinder": map[string]interface{}{
		"threads": "int",
		"timeout": "int",
	},
	"tools.amass": map[string]interface{}{
		"timeout": "int",
	},
	"tools.nuclei": map[string]interface{}{
		"concurrency":     "int",
		"rate_limit":      "int",
		"exclude_tags":    "slice",
		"severity":        "slice",
		"disable_oob":     "bool",
		"max_timeout_min": "int",
		"dast_aggression": "string",
	},
	"tools.httpx": map[string]interface{}{
		"threads":          "int",
		"timeout":          "int",
		"ports":            "slice",
		"follow_redirects": "bool",
	},
	"tools.naabu": map[string]interface{}{
		"threads": "int",
		"rate":    "int",
		"ports":   "string",
		"timeout": "int",
	},
	"tools.ffuf": map[string]interface{}{
		"threads":         "int",
		"timeout":         "int",
		"match_codes":     "slice",
		"max_timeout_min": "int",
	},
	"tools.dalfox": map[string]interface{}{
		"max_urls":         "int",
		"skip_third_party": "bool",
	},
	"tools.katana": map[string]interface{}{
		"timeout": "int",
	},
	"tools.gospider": map[string]interface{}{
		"timeout": "int",
	},
	"notifications": map[string]interface{}{
		"enabled":            "bool",
		"step_complete":      "bool",
		"min_severity":       "string",
		"discord_webhook":    "string",
		"slack_webhook":      "string",
		"telegram_bot_token": "string",
		"telegram_chat_id":   "string",
		"webhook_url":        "string",
	},
	"scope": map[string]interface{}{
		"in_scope":      "slice",
		"out_of_scope":  "slice",
		"exclude_ips":   "slice",
		"allowed_ports": "slice",
	},
	"rate_limits": map[string]interface{}{
		"global_rps": "int",
	},
}

func validateYAMLNode(node *yaml.Node, path string) []string {
	var warnings []string
	if node.Kind == yaml.DocumentNode {
		for _, content := range node.Content {
			warnings = append(warnings, validateYAMLNode(content, path)...)
		}
		return warnings
	}

	if node.Kind == yaml.MappingNode {
		expected, exists := expectedKeys[path]
		if !exists {
			return warnings
		}
		expectedMap, ok := expected.(map[string]interface{})
		if !ok {
			return warnings
		}

		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]
			key := keyNode.Value

			_, keyValid := expectedMap[key]
			if !keyValid {
				displayPath := key
				if path != "" {
					displayPath = path + "." + key
				}
				warnings = append(warnings, fmt.Sprintf("unknown config key: %s", displayPath))
			} else {
				childPath := key
				if path != "" {
					childPath = path + "." + key
				}
				warnings = append(warnings, validateYAMLNode(valNode, childPath)...)
			}
		}
	}
	return warnings
}

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// First pass: validate YAML keys
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err == nil {
		warnings := validateYAMLNode(&root, "")
		for _, w := range warnings {
			logger.Warning("%s", w)
		}
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply defaults
	applyDefaults(cfg)

	Cfg = cfg
	return cfg, nil
}

// LoadOrCreate loads config from path or creates a default one
func LoadOrCreate(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create default config
		cfg := DefaultConfig()
		if err := Save(cfg, path); err != nil {
			return nil, fmt.Errorf("failed to create default config: %w", err)
		}
		Cfg = cfg
		return cfg, nil
	}

	return Load(path)
}

// Save saves configuration to a YAML file
func Save(cfg *Config, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	header := `# Chaathan Configuration File
# Generated automatically - customize as needed
# Documentation: https://github.com/vishnu303/chaathan

`
	content := header + string(data)

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	chaathanDir := paths.ChaathanHome()

	return &Config{
		General: GeneralConfig{
			OutputDir:    filepath.Join(chaathanDir, "scans"),
			DatabasePath: filepath.Join(chaathanDir, "chaathan.db"),
			Mode:         "native",
			Verbose:      false,
			UARotation:   true,
			Wordlists: WordlistsConfig{
				Subdomains:  filepath.Join(resolveSeclistsBase(), "Discovery", "DNS", "subdomains-top1million-5000.txt"),
				Directories: filepath.Join(resolveSeclistsBase(), "Discovery", "Web-Content", "common.txt"),
				Parameters:  filepath.Join(resolveSeclistsBase(), "Discovery", "Web-Content", "burp-parameter-names.txt"),
			},
			JSLimit: 2000,
			ProxyScraping: ProxyScrapingConfig{
				TimeoutMin:    10,
				MaxConcurrent: 256,
				ProxyTypes:    []string{"socks5", "http", "socks4"},
				RotateMethod:  "random",
				RotateEvery:   1,
			},
		},
		APIKeys: APIKeysConfig{
			GitHub: os.Getenv("GITHUB_TOKEN"),
			Shodan: os.Getenv("SHODAN_API_KEY"),
		},
		Tools: ToolsConfig{
			Subfinder: SubfinderConfig{
				Threads: 30,
				Timeout: 30,
			},
			Amass: AmassConfig{
				Timeout: 60,
			},
			Nuclei: NucleiConfig{
				Concurrency:    25,
				RateLimit:      150,
				Severity:       []string{"low", "medium", "high", "critical"},
				ExcludeTags:    []string{"dos", "fuzz"},
				DisableOOB:     newBool(true),
				MaxTimeout:     180,
				DASTAggression: "high",
			},
			Httpx: HttpxConfig{
				Threads:         50,
				Timeout:         10,
				Ports:           []string{"80", "443", "8080", "8443", "8000", "8888"},
				FollowRedirects: true,
			},
			Naabu: NaabuConfig{
				Threads: 25,
				Rate:    1000,
				Timeout: 240,
			},
			Ffuf: FfufConfig{
				Threads:    50,
				Timeout:    10,
				MatchCodes: []int{200, 201, 204, 301, 302, 307, 401, 403, 405, 500},
				MaxTimeout: 180,
			},
			Dalfox: DalfoxConfig{
				MaxURLs:        500,
				SkipThirdParty: newBool(true),
			},
			Katana: KatanaConfig{
				Timeout: 300,
			},
			GoSpider: GoSpiderConfig{
				Timeout: 300,
			},
		},
		Notifications: NotificationConfig{
			Enabled:      false,
			StepComplete: false,
			MinSeverity:  "high",
		},
		Scope: ScopeConfig{
			InScope:    []string{},
			OutOfScope: []string{},
			ExcludeIPs: []string{},
		},
		RateLimits: RateLimitConfig{
			GlobalRPS: 0, // disabled by default; set to cap all tools
		},
	}
}

func newBool(b bool) *bool {
	return &b
}

func defaultString(val *string, def string) {
	if *val == "" {
		*val = def
	}
}

func defaultInt(val *int, def int) {
	if *val == 0 {
		*val = def
	}
}

func applyDefaults(cfg *Config) {
	defaultString(&cfg.General.Mode, "native")
	defaultInt(&cfg.General.JSLimit, 2000)
	defaultInt(&cfg.General.MaxRetries, 1)
	defaultInt(&cfg.General.RetryDelaySec, 3)
	defaultInt(&cfg.Tools.Nuclei.Concurrency, 25)
	defaultInt(&cfg.Tools.Nuclei.RateLimit, 150)
	defaultInt(&cfg.Tools.Nuclei.MaxTimeout, 180)
	if cfg.Tools.Nuclei.DisableOOB == nil {
		cfg.Tools.Nuclei.DisableOOB = newBool(true)
	}
	defaultString(&cfg.Tools.Nuclei.DASTAggression, "high")
	defaultInt(&cfg.Tools.Dalfox.MaxURLs, 500)
	if cfg.Tools.Dalfox.SkipThirdParty == nil {
		cfg.Tools.Dalfox.SkipThirdParty = newBool(true)
	}
	defaultInt(&cfg.Tools.Naabu.Timeout, 240)
	defaultInt(&cfg.Tools.Ffuf.MaxTimeout, 180)
	defaultInt(&cfg.Tools.Katana.Timeout, 300)
	defaultInt(&cfg.Tools.GoSpider.Timeout, 300)
	defaultString(&cfg.Notifications.MinSeverity, "high")


	// Proxy scraping defaults
	defaultInt(&cfg.General.ProxyScraping.TimeoutMin, 10)
	defaultInt(&cfg.General.ProxyScraping.MaxConcurrent, 256)
	if len(cfg.General.ProxyScraping.ProxyTypes) == 0 {
		cfg.General.ProxyScraping.ProxyTypes = []string{"socks5", "http", "socks4"}
	}
	defaultString(&cfg.General.ProxyScraping.RotateMethod, "random")
	defaultInt(&cfg.General.ProxyScraping.RotateEvery, 1)
}

// GetDefaultConfigPath returns the default config file path
func GetDefaultConfigPath() string {
	return paths.ConfigPath()
}

// apiKeyEnvMap maps API key config names to their corresponding environment variable names.
var apiKeyEnvMap = map[string]string{
	"github":         "GITHUB_TOKEN",
	"shodan":         "SHODAN_API_KEY",
	"securitytrails": "SECURITYTRAILS_KEY",
	"virustotal":     "VT_API_KEY",
	"chaos":          "CHAOS_KEY",
}

// GetAPIKey retrieves an API key from config or environment
func (c *Config) GetAPIKey(name string) string {
	nameLower := strings.ToLower(name)
	var val string
	switch nameLower {
	case "github":
		val = c.APIKeys.GitHub
	case "shodan":
		val = c.APIKeys.Shodan
	case "securitytrails":
		val = c.APIKeys.SecurityTrails
	case "virustotal":
		val = c.APIKeys.VirusTotal
	case "chaos":
		val = c.APIKeys.Chaos
	}
	if val != "" {
		return val
	}
	if envVar, exists := apiKeyEnvMap[nameLower]; exists {
		return os.Getenv(envVar)
	}
	return ""
}

// resolveSeclistsBase returns the seclists installation base directory.
// It checks ~/.chaathan/seclists first, then Arch Linux (/usr/share/seclists),
// and finally Debian/Kali (/usr/share/wordlists/seclists).
// Returns whichever path exists, falling back to the Debian path.
func resolveSeclistsBase() string {
	localPath := filepath.Join(paths.ChaathanHome(), "seclists")
	archPath := "/usr/share/seclists"
	debianPath := "/usr/share/wordlists/seclists"

	if info, err := os.Stat(localPath); err == nil && info.IsDir() {
		return localPath
	}
	if info, err := os.Stat(archPath); err == nil && info.IsDir() {
		return archPath
	}
	return debianPath
}
