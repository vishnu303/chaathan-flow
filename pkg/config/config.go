package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

// JSAnalysisConfig controls the unified JavaScript Deep Analysis step.
type JSAnalysisConfig struct {
	JSLimit        int  `yaml:"js_limit"`            // max JS URLs to fetch & analyze (default: 5000)
	Threads        int  `yaml:"js_threads"`          // concurrent fetch workers (default: 15)
	MaxFileMB      int  `yaml:"js_max_file_mb"`      // max size per JS file in MB (default: 15)
	MapMaxMB       int  `yaml:"js_map_max_mb"`       // max size per source map in MB (default: 20)
	ValidateLimit  int  `yaml:"js_validate_limit"`   // max secrets to live-validate per scan (default: 50)
	JsluiceTimeout int  `yaml:"jsluice_timeout_sec"` // per-file AST parse timeout in seconds (default: 30)
	SkipValidation bool `yaml:"skip_validation"`     // disable live secret validation checks
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

	// Deprecated: use js_analysis.js_limit instead. Kept for backward compat;
	// if js_analysis block is absent and this is non-zero, it overrides js_analysis.js_limit.
	JSLimit int `yaml:"js_limit"`

	// JavaScript Deep Analysis configuration
	JSAnalysis JSAnalysisConfig `yaml:"js_analysis"`

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

	// Fofa API key (FOFA classic two-factor auth)
	Fofa      string `yaml:"fofa"`
	FofaEmail string `yaml:"fofa_email"`

	// Quake (360) API credentials — email + key pair for uncover -e quake
	Quake      string `yaml:"quake"`
	QuakeEmail string `yaml:"quake_email"`

	// ZoomEye API credentials — email + key pair for uncover -e zoomeye
	ZoomEye      string `yaml:"zoomeye"`
	ZoomEyeEmail string `yaml:"zoomeye_email"`

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

	// Assetfinder specific settings
	Assetfinder AssetfinderConfig `yaml:"assetfinder"`

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

	// Uncover specific settings
	Uncover UncoverConfig `yaml:"uncover"`
}

type SubfinderConfig struct {
	Threads int `yaml:"threads"` // concurrent threads for passive enumeration (default: 30)
	Timeout int `yaml:"timeout"` // timeout in seconds per source (default: 30)
}

type AssetfinderConfig struct {
	Timeout int `yaml:"timeout"` // max runtime in seconds (default: 60)
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
	MaxURLs        int   `yaml:"max_urls"`         // cap parameterized URLs (default: 500)
	SkipThirdParty *bool `yaml:"skip_third_party"` // filter non-target domains (default: true)
	MaxTimeout     int   `yaml:"max_timeout_min"`  // hard process timeout per run in minutes (default: 120)
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
	Timeout int `yaml:"timeout"` // max runtime in minutes for Naabu (default: 240)
}

type FfufConfig struct {
	Threads    int   `yaml:"threads"`         // concurrent fuzzing threads (default: 50)
	Timeout    int   `yaml:"timeout"`         // per-request timeout in seconds (default: 10)
	MatchCodes []int `yaml:"match_codes"`     // HTTP status codes to report as findings (default: 200,201,204,301,...)
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

type UncoverConfig struct {
	Timeout int `yaml:"timeout"` // max runtime in seconds (default: 120)
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

// Cfg is the process-wide configuration instance, set by Load/LoadOrCreate.
// It is the single sanctioned mutable global in the codebase: commands and
// workflows read it, but only the config package may assign it.
var Cfg *Config

// expectedKeys maps each config path ("" for root, "general",
// "tools.nuclei", ...) to the set of valid YAML keys at that level. It is
// generated from the Config struct's yaml tags, so new fields are validated
// automatically and can never drift from the schema.
var expectedKeys = buildExpectedKeys(reflect.TypeOf(Config{}))

// buildExpectedKeys walks a config struct type via reflection and collects
// the valid yaml key names for every nesting level.
func buildExpectedKeys(t reflect.Type) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	var walk func(t reflect.Type, path string)
	walk = func(t reflect.Type, path string) {
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		set, ok := out[path]
		if !ok {
			set = map[string]bool{}
			out[path] = set
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			set[tag] = true
			child := tag
			if path != "" {
				child = path + "." + tag
			}
			walk(f.Type, child)
		}
	}
	walk(t, "")
	return out
}

func validateYAMLNode(node *yaml.Node, path string) []string {
	var warnings []string
	if node.Kind == yaml.DocumentNode {
		for _, content := range node.Content {
			warnings = append(warnings, validateYAMLNode(content, path)...)
		}
		return warnings
	}

	if node.Kind != yaml.MappingNode {
		return warnings
	}

	expected, exists := expectedKeys[path]
	if !exists {
		return warnings
	}

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]
		key := keyNode.Value

		displayPath := key
		if path != "" {
			displayPath = path + "." + key
		}
		if !expected[key] {
			warnings = append(warnings, fmt.Sprintf("unknown config key: %s", displayPath))
		} else {
			warnings = append(warnings, validateYAMLNode(valNode, displayPath)...)
		}
	}
	return warnings
}

// Load loads configuration from a YAML file. The Config is pre-seeded with
// DefaultConfig() before decoding, so any keys absent from the file keep
// their documented defaults — DefaultConfig is the single source of defaults.
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

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	resolveWordlists(cfg)
	migrateJSLimit(cfg)

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
			OutputDir:     filepath.Join(chaathanDir, "scans"),
			DatabasePath:  filepath.Join(chaathanDir, "chaathan.db"),
			Mode:          "native",
			Verbose:       false,
			MaxRetries:    1,
			RetryDelaySec: 3,
			UARotation:    true,
			Wordlists: WordlistsConfig{
				Subdomains:  ResolveSecListFile("Discovery/DNS/subdomains-top1million-5000.txt"),
				Directories: ResolveSecListFile("Discovery/Web-Content/common.txt"),
				Parameters:  ResolveSecListFile("Discovery/Web-Content/burp-parameter-names.txt"),
			},
			JSLimit: 0, // deprecated; kept for backward compat
			JSAnalysis: JSAnalysisConfig{
				JSLimit:        5000,
				Threads:        15,
				MaxFileMB:      15,
				MapMaxMB:       20,
				ValidateLimit:  50,
				JsluiceTimeout: 30,
				SkipValidation: false,
			},
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
			Assetfinder: AssetfinderConfig{
				Timeout: 60,
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
				Ports:           []string{"80", "443", "8080", "8443", "8000", "8888", "3000", "9090", "4443", "5000"},
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
				MaxTimeout:     120,
			},
			Katana: KatanaConfig{
				Timeout: 300,
			},
			GoSpider: GoSpiderConfig{
				Timeout: 300,
			},
			Uncover: UncoverConfig{
				Timeout: 120,
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

// migrateJSLimit applies backward compatibility: if the deprecated top-level
// js_limit is set and the new js_analysis.js_limit is still at its default,
// the old value takes precedence so existing user configs keep working.
func migrateJSLimit(cfg *Config) {
	if cfg.General.JSLimit > 0 && cfg.General.JSAnalysis.JSLimit == 5000 {
		cfg.General.JSAnalysis.JSLimit = cfg.General.JSLimit
	}
}

func newBool(b bool) *bool {
	return &b
}

// resolveWordlists applies the dynamic fallback for wordlist paths: a
// configured path is kept only if it exists on disk; otherwise the seclists
// location is tried. Called after Load so sparse configs inherit the resolved
// defaults untouched.
func resolveWordlists(cfg *Config) {
	resolve := func(configuredPath, subpath string) string {
		if configuredPath != "" {
			if _, err := os.Stat(configuredPath); err == nil {
				return configuredPath
			}
		}
		resolved := filepath.Join(ResolveSecListsBase(), subpath)
		if _, err := os.Stat(resolved); err == nil {
			return resolved
		}
		return configuredPath
	}

	cfg.General.Wordlists.Subdomains = resolve(cfg.General.Wordlists.Subdomains, filepath.Join("Discovery", "DNS", "subdomains-top1million-5000.txt"))
	cfg.General.Wordlists.Directories = resolve(cfg.General.Wordlists.Directories, filepath.Join("Discovery", "Web-Content", "common.txt"))
	cfg.General.Wordlists.Parameters = resolve(cfg.General.Wordlists.Parameters, filepath.Join("Discovery", "Web-Content", "burp-parameter-names.txt"))
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
	"fofa":           "FOFA_KEY",
	"fofa_email":     "FOFA_EMAIL",
	"quake":          "QUAKE_KEY",
	"quake_email":    "QUAKE_EMAIL",
	"zoomeye":        "ZOOMEYE_KEY",
	"zoomeye_email":  "ZOOMEYE_EMAIL",
}

// GetAPIKey retrieves an API key from config or environment.
// Config values win; the environment fallback only applies to keys listed in
// apiKeyEnvMap.
//
// For the email-style API services (fofa, quake, zoomeye), the bare key name
// returns "<key>:<email>" when both halves are configured; callers that need
// the raw key alone may pass the "<svc>_email" key separately (mirroring the
// Censys "id:secret" shorthand).
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
	case "censys":
		val = c.APIKeys.Censys
		if val == "" && c.APIKeys.CensysID != "" && c.APIKeys.CensysSecret != "" {
			val = c.APIKeys.CensysID + ":" + c.APIKeys.CensysSecret
		}
	case "fofa":
		val = c.APIKeys.Fofa
		if val != "" && c.APIKeys.FofaEmail != "" {
			val = val + ":" + c.APIKeys.FofaEmail
		}
	case "fofa_email":
		val = c.APIKeys.FofaEmail
	case "quake":
		val = c.APIKeys.Quake
		if val != "" && c.APIKeys.QuakeEmail != "" {
			val = val + ":" + c.APIKeys.QuakeEmail
		}
	case "quake_email":
		val = c.APIKeys.QuakeEmail
	case "zoomeye":
		val = c.APIKeys.ZoomEye
		if val != "" && c.APIKeys.ZoomEyeEmail != "" {
			val = val + ":" + c.APIKeys.ZoomEyeEmail
		}
	case "zoomeye_email":
		val = c.APIKeys.ZoomEyeEmail
	}
	if val != "" {
		return val
	}
	if envVar, exists := apiKeyEnvMap[nameLower]; exists {
		return os.Getenv(envVar)
	}
	return ""
}

// ResolveSecListsBase returns the seclists installation base directory.
// It checks ~/.chaathan/seclists first, then Arch Linux (/usr/share/seclists),
// and finally Debian/Kali (/usr/share/wordlists/seclists).
// Returns whichever path exists, falling back to the Debian path.
func ResolveSecListsBase() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "" // candidates below skip empty entries
	}
	candidates := []string{
		filepath.Join(paths.ChaathanHome(), "seclists"),
		filepath.Join(paths.ChaathanHome(), "SecLists"),
		filepath.Join(home, "seclists"),
		filepath.Join(home, "SecLists"),
		"/usr/share/seclists",
		"/usr/share/SecLists",
		"/usr/share/wordlists/seclists",
		"/usr/share/wordlists/SecLists",
	}

	for _, p := range candidates {
		if p == "" {
			continue
		}
		if info, err := os.Stat(filepath.Join(p, "Discovery")); err == nil && info.IsDir() {
			return p
		}
	}
	return ""
}

// ResolveSecListFile checks if SecLists is installed on the host and returns the absolute path
// to the requested relative subpath (e.g. "Discovery/Web-Content/common.txt") if it exists.
// Returns empty string if SecLists is not found or the target file does not exist.
func ResolveSecListFile(subpath string) string {
	base := ResolveSecListsBase()
	if base == "" {
		return ""
	}
	target := filepath.Join(base, filepath.FromSlash(subpath))
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		return target
	}
	return ""
}
