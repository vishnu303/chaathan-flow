package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
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
	// Output directory for scan results
	OutputDir string `yaml:"output_dir"`

	// Database path
	DatabasePath string `yaml:"database_path"`

	// Default execution mode: native or docker
	Mode string `yaml:"mode"`

	// Enable verbose logging
	Verbose bool `yaml:"verbose"`

	// Number of concurrent tools to run
	Concurrency int `yaml:"concurrency"`

	// DNS resolvers file path
	ResolversFile string `yaml:"resolvers_file"`

	// Wordlist paths
	Wordlists WordlistsConfig `yaml:"wordlists"`
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

	// Censys API credentials
	CensysID     string `yaml:"censys_id"`
	CensysSecret string `yaml:"censys_secret"`

	// SecurityTrails API key
	SecurityTrails string `yaml:"securitytrails"`

	// VirusTotal API key
	VirusTotal string `yaml:"virustotal"`

	// Chaos API key (ProjectDiscovery)
	Chaos string `yaml:"chaos"`

	// Hunter.io API key
	Hunter string `yaml:"hunter"`

	// PassiveTotal API credentials
	PassiveTotalUser string `yaml:"passivetotal_user"`
	PassiveTotalKey  string `yaml:"passivetotal_key"`
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
}

type SubfinderConfig struct {
	Threads   int      `yaml:"threads"`
	Timeout   int      `yaml:"timeout"`
	Sources   []string `yaml:"sources"`
	Recursive bool     `yaml:"recursive"`
}

type AmassConfig struct {
	Timeout    int  `yaml:"timeout"`
	Active     bool `yaml:"active"`
	Brute      bool `yaml:"brute"`
	MinRecurse int  `yaml:"min_recurse"`
	MaxDepth   int  `yaml:"max_depth"`
}

type NucleiConfig struct {
	Concurrency  int      `yaml:"concurrency"`
	RateLimit    int      `yaml:"rate_limit"`
	BulkSize     int      `yaml:"bulk_size"`
	Templates    []string `yaml:"templates"`
	ExcludeTags  []string `yaml:"exclude_tags"`
	Severity     []string `yaml:"severity"`
	Retries      int      `yaml:"retries"`
	Timeout      int      `yaml:"timeout"`
	HeadlessMode bool     `yaml:"headless"`
}

type HttpxConfig struct {
	Threads         int      `yaml:"threads"`
	Timeout         int      `yaml:"timeout"`
	Retries         int      `yaml:"retries"`
	Ports           []string `yaml:"ports"`
	TechDetect      bool     `yaml:"tech_detect"`
	StatusCode      bool     `yaml:"status_code"`
	Title           bool     `yaml:"title"`
	FollowRedirects bool     `yaml:"follow_redirects"`
}

type NaabuConfig struct {
	Threads  int    `yaml:"threads"`
	Rate     int    `yaml:"rate"`
	Ports    string `yaml:"ports"`     // e.g., "top-1000" or "80,443,8080"
	ScanType string `yaml:"scan_type"` // s (SYN), c (Connect)
	Retries  int    `yaml:"retries"`
}

type FfufConfig struct {
	Threads        int   `yaml:"threads"`
	Timeout        int   `yaml:"timeout"`
	MatchCodes     []int `yaml:"match_codes"`
	FilterCodes    []int `yaml:"filter_codes"`
	FilterSize     []int `yaml:"filter_size"`
	Recursion      bool  `yaml:"recursion"`
	RecursionDepth int   `yaml:"recursion_depth"`
}

type NotificationConfig struct {
	// Enable notifications
	Enabled bool `yaml:"enabled"`

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

	// Email settings
	Email EmailConfig `yaml:"email"`
}

type EmailConfig struct {
	Enabled  bool   `yaml:"enabled"`
	SMTPHost string `yaml:"smtp_host"`
	SMTPPort int    `yaml:"smtp_port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	To       string `yaml:"to"`
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
	// Global requests per second limit
	GlobalRPS int `yaml:"global_rps"`

	// Per-tool rate limits (requests per second)
	Subfinder int `yaml:"subfinder"`
	Httpx     int `yaml:"httpx"`
	Nuclei    int `yaml:"nuclei"`
	Naabu     int `yaml:"naabu"`
	Ffuf      int `yaml:"ffuf"`
	Katana    int `yaml:"katana"`
}

// Global config instance
var Cfg *Config

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
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

	// Add header comment
	header := `# Chaathan Configuration File
# Generated automatically - customize as needed
# Documentation: https://github.com/yourusername/chaathan

`
	content := header + string(data)

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	chaathanDir := filepath.Join(home, ".chaathan")

	return &Config{
		General: GeneralConfig{
			OutputDir:    filepath.Join(chaathanDir, "scans"),
			DatabasePath: filepath.Join(chaathanDir, "chaathan.db"),
			Mode:         "native",
			Verbose:      false,
			Concurrency:  5,
			Wordlists: WordlistsConfig{
				Subdomains:  "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
				Directories: "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
				Parameters:  "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",
			},
		},
		APIKeys: APIKeysConfig{
			GitHub: os.Getenv("GITHUB_TOKEN"),
			Shodan: os.Getenv("SHODAN_API_KEY"),
		},
		Tools: ToolsConfig{
			Subfinder: SubfinderConfig{
				Threads:   30,
				Timeout:   30,
				Recursive: false,
			},
			Amass: AmassConfig{
				Timeout:    60,
				Active:     true,
				Brute:      false,
				MinRecurse: 2,
			},
			Nuclei: NucleiConfig{
				Concurrency: 25,
				RateLimit:   150,
				BulkSize:    25,
				Severity:    []string{"low", "medium", "high", "critical"},
				ExcludeTags: []string{"dos", "fuzz"},
				Retries:     1,
				Timeout:     10,
			},
			Httpx: HttpxConfig{
				Threads:         50,
				Timeout:         10,
				Retries:         2,
				Ports:           []string{"80", "443", "8080", "8443", "8000", "8888"},
				TechDetect:      true,
				StatusCode:      true,
				Title:           true,
				FollowRedirects: true,
			},
			Naabu: NaabuConfig{
				Threads:  25,
				Rate:     1000,
				Ports:    "top-1000",
				ScanType: "s",
				Retries:  3,
			},
			Ffuf: FfufConfig{
				Threads:        50,
				Timeout:        10,
				MatchCodes:     []int{200, 201, 204, 301, 302, 307, 401, 403, 405, 500},
				Recursion:      false,
				RecursionDepth: 2,
			},
		},
		Notifications: NotificationConfig{
			Enabled:     false,
			MinSeverity: "high",
		},
		Scope: ScopeConfig{
			InScope:    []string{},
			OutOfScope: []string{},
			ExcludeIPs: []string{},
		},
		RateLimits: RateLimitConfig{
			GlobalRPS: 100,
			Subfinder: 50,
			Httpx:     100,
			Nuclei:    150,
			Naabu:     1000,
			Ffuf:      100,
			Katana:    50,
		},
	}
}

func applyDefaults(cfg *Config) {
	if cfg.General.Concurrency == 0 {
		cfg.General.Concurrency = 5
	}
	if cfg.General.Mode == "" {
		cfg.General.Mode = "native"
	}
	if cfg.Tools.Nuclei.Concurrency == 0 {
		cfg.Tools.Nuclei.Concurrency = 25
	}
	if cfg.Tools.Nuclei.RateLimit == 0 {
		cfg.Tools.Nuclei.RateLimit = 150
	}
	if cfg.Notifications.MinSeverity == "" {
		cfg.Notifications.MinSeverity = "high"
	}
}

// GetDefaultConfigPath returns the default config file path
func GetDefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".chaathan", "config.yaml")
}

// GetAPIKey retrieves an API key from config or environment
func (c *Config) GetAPIKey(name string) string {
	switch name {
	case "github":
		if c.APIKeys.GitHub != "" {
			return c.APIKeys.GitHub
		}
		return os.Getenv("GITHUB_TOKEN")
	case "shodan":
		if c.APIKeys.Shodan != "" {
			return c.APIKeys.Shodan
		}
		return os.Getenv("SHODAN_API_KEY")
	case "securitytrails":
		if c.APIKeys.SecurityTrails != "" {
			return c.APIKeys.SecurityTrails
		}
		return os.Getenv("SECURITYTRAILS_KEY")
	case "virustotal":
		if c.APIKeys.VirusTotal != "" {
			return c.APIKeys.VirusTotal
		}
		return os.Getenv("VT_API_KEY")
	case "chaos":
		if c.APIKeys.Chaos != "" {
			return c.APIKeys.Chaos
		}
		return os.Getenv("CHAOS_KEY")
	default:
		return ""
	}
}
