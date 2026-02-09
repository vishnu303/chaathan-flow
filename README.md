# Chaathan

A powerful, modular CLI pentesting framework for comprehensive bug bounty reconnaissance and vulnerability scanning. Single binary, no dependencies, works on any Linux VPS.

```
   _____ _                 _   _                 
  / ____| |               | | | |                
 | |    | |__   __ _  __ _| |_| |__   __ _ _ __  
 | |    | '_ \ / _' |/ _' | __| '_ \ / _' | '_ \ 
 | |____| | | | (_| | (_| | |_| | | | (_| | | | |
  \_____|_| |_|\__,_|\__,_|\__|_| |_|\__,_|_| |_|
```

## Features

- **20+ Integrated Tools**: Subfinder, Amass, Nuclei, Httpx, Naabu, Katana, ffuf, LinkFinder, CeWL, and more
- **Parallel Execution**: Run multiple tools simultaneously for faster results
- **SQLite Database**: All results stored persistently for querying and analysis
- **Text File Export**: All results automatically exported to organized text files
- **Report Generation**: Export reports in Markdown, JSON, HTML, or Text format
- **Notifications**: Discord, Slack, Telegram, and webhook alerts for findings
- **Resume Capability**: Continue interrupted scans from where they left off
- **YAML Configuration**: Centralized config for API keys, rate limits, and tool settings
- **Scope Management**: Define in-scope/out-of-scope targets with regex patterns
- **Easy Cleanup**: Delete target data from database when done

## Installation

### Prerequisites

- Go 1.21+
- Git

### Install Chaathan

```bash
# Clone and build
git clone https://github.com/yourusername/chaathan.git
cd chaathan
go build -o chaathan .

# Or install directly
go install github.com/yourusername/chaathan@latest
```

### Install Dependencies

```bash
chaathan setup
```

This installs all required tools:
- **Go tools**: subfinder, amass, nuclei, httpx, naabu, katana, ffuf, gospider, waybackurls, gau, dnsx, etc.
- **Python tools**: sublist3r, linkfinder, cloud_enum, subdomainizer
- **Ruby tools**: cewl
- **Other**: massdns (compiled from source)

## Quick Start

```bash
# 1. Setup tools (first time only)
chaathan setup

# 2. Configure API keys (optional but recommended)
chaathan config set api_keys.github ghp_xxxxxxxxxxxx

# 3. Run full recon on a domain
chaathan wildcard -d example.com

# 4. View results
chaathan scans show 1
chaathan query vulns 1
chaathan query subdomains 1 --live

# 5. Generate report
chaathan report generate 1 --format html

# 6. When done with target, cleanup database
chaathan delete target example.com
```

## Commands Overview

| Command | Description |
|---------|-------------|
| `chaathan wildcard -d <domain>` | Run full recon workflow |
| `chaathan setup` | Install all dependency tools |
| `chaathan scans list` | List all past scans |
| `chaathan scans show <id>` | Show scan details |
| `chaathan query subdomains <id>` | Query subdomains |
| `chaathan query vulns <id>` | Query vulnerabilities |
| `chaathan query ports <id>` | Query open ports |
| `chaathan query urls <id>` | Query discovered URLs |
| `chaathan query endpoints <id>` | Query API endpoints |
| `chaathan report generate <id>` | Generate report |
| `chaathan export <id>` | Export results to text files |
| `chaathan delete target <domain>` | Delete target data |
| `chaathan delete list` | List all targets in DB |
| `chaathan config show` | Show configuration |
| `chaathan config set <key> <value>` | Set config value |

---

## Detailed Usage

### Wildcard Workflow

Full subdomain enumeration and vulnerability scanning:

```bash
# Basic usage
chaathan wildcard -d target.com

# With all options
chaathan wildcard -d target.com \
  --skip-amass \
  --skip-nuclei \
  --wordlist /path/to/wordlist.txt \
  --github-token ghp_xxxx \
  --verbose

# Fast scan (skip slow tools)
chaathan wildcard -d target.com --skip-amass --skip-nuclei
```

**Workflow Steps (12 total):**

| Step | Tools | Mode |
|------|-------|------|
| 1. Passive Enumeration | Subfinder, Assetfinder, Sublist3r | Parallel |
| 2. URL Discovery | Waybackurls, GAU | Parallel |
| 3. Active Enumeration | Amass | Optional |
| 4. GitHub Recon | github-subdomains | Optional |
| 5. Consolidation | Merge & deduplicate | Sequential |
| 6. DNS Resolution | DNSx | Sequential |
| 7. HTTP Probing | Httpx | Sequential |
| 8. Port Scanning | Naabu | Sequential |
| 9. Web Crawling | Katana, GoSpider | Parallel |
| 10. JS Analysis | LinkFinder | Sequential |
| 11. Wordlist Gen | CeWL | Sequential |
| 12. Dir Fuzzing | ffuf | Optional |
| 13. Vuln Scanning | Nuclei | Optional |

**Flags:**

| Flag | Description |
|------|-------------|
| `-d, --domain` | Target domain (required) |
| `--skip-amass` | Skip Amass (slow but thorough) |
| `--skip-nuclei` | Skip Nuclei vulnerability scanning |
| `-w, --wordlist` | Wordlist for directory fuzzing |
| `--github-token` | GitHub token for GitHub recon |
| `--report` | Generate report after scan (default: true) |
| `-v, --verbose` | Enable verbose output |
| `-m, --mode` | Execution mode: native or docker |

---

### Scan Management

```bash
# List all scans
chaathan scans list

# List scans for specific target
chaathan scans list -t example.com

# Show scan details with statistics
chaathan scans show 1

# Resume an interrupted scan
chaathan scans resume 1
```

**Example output:**

```
$ chaathan scans list
ID  TARGET              TYPE      STATUS     STARTED           DURATION
--  ------              ----      ------     -------           --------
3   example.com         wildcard  completed  2024-01-15 10:30  45m32s
2   test.org            wildcard  completed  2024-01-14 14:22  38m15s
1   another.io          wildcard  failed     2024-01-13 09:00  12m45s
```

---

### Query Results

Query and filter results from completed scans:

```bash
# Subdomains
chaathan query subdomains 1              # All subdomains
chaathan query subdomains 1 --live       # Only live subdomains
chaathan query subdomains 1 --grep api   # Filter by pattern
chaathan query subdomains 1 --json       # Output as JSON

# Vulnerabilities
chaathan query vulns 1                   # All vulnerabilities
chaathan query vulns 1 --severity critical  # Filter by severity
chaathan query vulns 1 --json            # Output as JSON

# Ports
chaathan query ports 1                   # All open ports
chaathan query ports 1 --json            # Output as JSON

# URLs
chaathan query urls 1                    # All URLs
chaathan query urls 1 --json             # Output as JSON

# Endpoints
chaathan query endpoints 1               # All endpoints
chaathan query endpoints 1 --json        # Output as JSON
```

**Example output:**

```
$ chaathan query vulns 1 --severity critical

[CRITICAL] CVE-2023-1234 - Remote Code Execution
  Host: api.example.com
  URL: https://api.example.com/upload
  Template: CVE-2023-1234

[CRITICAL] SQL Injection
  Host: admin.example.com
  URL: https://admin.example.com/login?id=1

=== Summary ===
  critical: 2
  high: 5
  medium: 12
```

---

### Report Generation

Generate reports in multiple formats:

```bash
# Markdown report (default)
chaathan report generate 1

# HTML report (beautiful dark theme)
chaathan report generate 1 --format html

# JSON report (for programmatic use)
chaathan report generate 1 --format json

# Text report
chaathan report generate 1 --format text

# Custom output path
chaathan report generate 1 --format html -o /path/to/report.html
```

Reports are automatically saved to:
- `~/.chaathan/reports/scan_<id>.md`
- `<result_dir>/REPORT.md`

---

### Export to Text Files

All results are automatically exported after each scan. You can also manually export:

```bash
# Export scan results to text files
chaathan export 1

# Export to custom directory
chaathan export 1 -o /path/to/output
```

**Output files created:**

| File | Description |
|------|-------------|
| `final_subdomains.txt` | All discovered subdomains |
| `live_subdomains.txt` | Only live/responsive subdomains |
| `live_subdomains_with_ip.txt` | Live subdomains with IP addresses |
| `open_ports.txt` | Open ports (host:port format) |
| `open_ports_detailed.txt` | Ports with protocol and service |
| `hosts_with_ports.txt` | Unique hosts with their open ports |
| `all_urls.txt` | All discovered URLs |
| `urls_200.txt` | Only URLs returning 200 OK |
| `urls_with_status.txt` | URLs with HTTP status codes |
| `urls_with_titles.txt` | URLs with page titles |
| `vulnerabilities.txt` | All vulnerabilities summary |
| `vulnerabilities_detailed.txt` | Full vulnerability details with evidence |
| `vulnerabilities_critical_high.txt` | Critical/High severity only |
| `vulnerable_hosts.txt` | Unique hosts with vulnerabilities |
| `endpoints.txt` | All discovered endpoints |
| `endpoints_with_methods.txt` | Endpoints with HTTP methods |
| `endpoints_interesting.txt` | API/admin/interesting endpoints |
| `SUMMARY.txt` | Overall scan summary |
| `REPORT.md` | Full Markdown report |

---

### Delete Data (Cleanup)

When you're done with a target, clean up the database to save space:

```bash
# List all targets in database
chaathan delete list

# Delete all data for a target
chaathan delete target example.com

# Also delete result files from disk
chaathan delete target example.com --files

# Delete a specific scan by ID
chaathan delete scan 5

# Delete scans older than 30 days
chaathan delete old 30
```

**Example:**

```
$ chaathan delete list

=== Targets in Database ===
example.com                               [3 scans, 1547 subs, 12 vulns]
test.org                                  [1 scans, 234 subs, 0 vulns]
another.io                                [2 scans, 892 subs, 5 vulns]

Total: 3 targets

$ chaathan delete target example.com
[*] Deleting data for: example.com
[*]   Scans: 3, Subdomains: 1547, Ports: 89, URLs: 2341, Vulns: 12
[+] Deleted 3 scan(s) for target: example.com
[*] Reclaiming disk space...
[+] Cleanup complete for: example.com
```

**Delete options:**

| Flag | Description |
|------|-------------|
| `--files` | Also delete result files from disk |
| `--vacuum` | Run VACUUM to reclaim disk space (default: true) |

---

### Configuration

Manage configuration via CLI:

```bash
# Show current config
chaathan config show

# Edit config in your default editor
chaathan config edit

# Set individual values
chaathan config set api_keys.github ghp_xxxxx
chaathan config set api_keys.shodan xxxxxxxx
chaathan config set notifications.discord_webhook https://discord.com/api/webhooks/xxx
chaathan config set notifications.enabled true
chaathan config set general.verbose true

# Show config file path
chaathan config path

# Reset to defaults
chaathan config reset
```

**Available config keys:**

| Key | Description |
|-----|-------------|
| `api_keys.github` | GitHub token for GitHub recon |
| `api_keys.shodan` | Shodan API key |
| `api_keys.securitytrails` | SecurityTrails API key |
| `api_keys.virustotal` | VirusTotal API key |
| `api_keys.chaos` | ProjectDiscovery Chaos key |
| `general.verbose` | Enable verbose logging |
| `general.mode` | Execution mode (native/docker) |
| `general.output_dir` | Output directory for scans |
| `notifications.enabled` | Enable notifications |
| `notifications.discord_webhook` | Discord webhook URL |
| `notifications.slack_webhook` | Slack webhook URL |
| `notifications.telegram_bot_token` | Telegram bot token |
| `notifications.telegram_chat_id` | Telegram chat ID |
| `notifications.min_severity` | Minimum severity to notify |

---

## Configuration File

Located at `~/.chaathan/config.yaml`:

```yaml
general:
  output_dir: ~/.chaathan/scans
  database_path: ~/.chaathan/chaathan.db
  mode: native
  verbose: false
  concurrency: 5
  wordlists:
    subdomains: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    directories: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt

api_keys:
  github: ""
  shodan: ""
  securitytrails: ""
  virustotal: ""
  chaos: ""

tools:
  subfinder:
    threads: 30
    timeout: 30
  amass:
    timeout: 60
    active: true
  nuclei:
    concurrency: 25
    rate_limit: 150
    severity:
      - low
      - medium
      - high
      - critical
    exclude_tags:
      - dos
      - fuzz
  httpx:
    threads: 50
    timeout: 10
    ports:
      - "80"
      - "443"
      - "8080"
      - "8443"
  naabu:
    threads: 25
    rate: 1000
    ports: "top-1000"
  ffuf:
    threads: 50
    timeout: 10

notifications:
  enabled: false
  min_severity: high
  discord_webhook: ""
  slack_webhook: ""
  telegram_bot_token: ""
  telegram_chat_id: ""

scope:
  in_scope: []
  out_of_scope: []
  exclude_ips: []

rate_limits:
  global_rps: 100
  nuclei: 150
  httpx: 100
  naabu: 1000
  ffuf: 100
```

---

## Notifications

Get real-time alerts for critical/high findings:

### Discord

```bash
chaathan config set notifications.discord_webhook https://discord.com/api/webhooks/xxx/yyy
chaathan config set notifications.enabled true
chaathan config set notifications.min_severity high
```

### Slack

```bash
chaathan config set notifications.slack_webhook https://hooks.slack.com/services/xxx/yyy/zzz
chaathan config set notifications.enabled true
```

### Telegram

```bash
chaathan config set notifications.telegram_bot_token 123456789:ABCdefGHIjklMNOpqrsTUVwxyz
chaathan config set notifications.telegram_chat_id -123456789
chaathan config set notifications.enabled true
```

---

## Data Storage

All data is stored in SQLite at `~/.chaathan/chaathan.db`:

| Table | Description |
|-------|-------------|
| `scans` | Scan metadata (target, status, timestamps) |
| `subdomains` | Discovered subdomains with live status and IPs |
| `ports` | Open ports per host with service info |
| `urls` | Discovered URLs with status codes and titles |
| `vulnerabilities` | Nuclei findings with severity and evidence |
| `endpoints` | API endpoints from crawling/JS analysis |

---

## Directory Structure

```
~/.chaathan/
├── config.yaml              # Configuration file
├── chaathan.db              # SQLite database
├── scans/                   # Scan results
│   └── example.com/
│       ├── subfinder.txt
│       ├── assetfinder.txt
│       ├── all_subdomains.txt
│       ├── live_subdomains.txt
│       ├── httpx_live.json
│       ├── naabu_ports.txt
│       ├── nuclei_vulns.json
│       ├── vulnerabilities.txt
│       ├── SUMMARY.txt
│       └── REPORT.md
├── reports/                 # Generated reports
│   └── scan_1.md
└── state/                   # Scan state (for resume)
    └── scan_1.json
```

---

## Project Structure

```
chaathan/
├── main.go                     # Entry point
├── go.mod                      # Go modules
├── README.md                   # This file
├── cmd/
│   ├── root.go                 # CLI setup, global flags
│   ├── wildcard.go             # Wildcard recon workflow
│   ├── company.go              # Company/org workflow
│   ├── setup.go                # Tool installation
│   ├── scans.go                # Scan management
│   ├── query.go                # Query results
│   ├── report.go               # Report generation
│   ├── export.go               # Export to text files
│   ├── delete.go               # Delete/cleanup data
│   └── config.go               # Config management
├── pkg/
│   ├── config/config.go        # YAML config handling
│   ├── database/database.go    # SQLite operations
│   ├── logger/logger.go        # Colored console output
│   ├── notify/notify.go        # Notifications (Discord/Slack/Telegram)
│   ├── report/report.go        # Report templates
│   ├── runner/runner.go        # Tool execution (native/docker)
│   ├── scan/scan.go            # Scan state management
│   ├── scope/scope.go          # Scope filtering
│   ├── tools/tools.go          # Tool wrappers
│   └── utils/
│       ├── file.go             # File utilities
│       ├── parser.go           # Tool output parsers
│       └── export.go           # Text file export
```

---

## Integrated Tools

| Category | Tools |
|----------|-------|
| **Passive Enum** | subfinder, assetfinder, sublist3r, gau, waybackurls |
| **Active Enum** | amass, github-subdomains |
| **DNS** | dnsx, massdns, shuffledns |
| **HTTP Probing** | httpx |
| **Port Scanning** | naabu |
| **Web Crawling** | katana, gospider |
| **JS Analysis** | linkfinder |
| **Fuzzing** | ffuf |
| **Wordlist Gen** | cewl |
| **Vuln Scanning** | nuclei |
| **Cloud** | cloud_enum, metabigor |

---

## Comparison with Other Tools

| Feature | Chaathan | ReconFTW | Osmedeus |
|---------|----------|----------|----------|
| Single Binary | Yes | No (Bash) | No |
| SQLite Storage | Yes | No | Yes |
| Text File Export | Yes | Yes | Yes |
| Report Generation | Yes | Basic | Yes |
| Notifications | Yes | No | Yes |
| Resume Scans | Yes | No | Yes |
| Config File | YAML | Bash vars | YAML |
| Learning Curve | Low | Medium | High |
| Easy Cleanup | Yes | Manual | Manual |

---

## Examples

### Full Recon Pipeline

```bash
# Setup (first time)
chaathan setup

# Configure GitHub token for better results
chaathan config set api_keys.github ghp_xxxxxxxxxxxx

# Run full scan
chaathan wildcard -d bugcrowd-target.com --verbose

# Check results
chaathan scans show 1
chaathan query vulns 1 --severity critical
chaathan query subdomains 1 --live

# Generate HTML report for submission
chaathan report generate 1 --format html -o report.html

# Cleanup when done
chaathan delete target bugcrowd-target.com --files
```

### Quick Scan (Skip Slow Tools)

```bash
chaathan wildcard -d target.com --skip-amass --skip-nuclei
```

### Export for Other Tools

```bash
# Get live subdomains for manual testing
chaathan query subdomains 1 --live --json > live_subs.json

# Get all URLs for Burp import
chaathan query urls 1 > urls_for_burp.txt

# Get endpoints for API testing
chaathan query endpoints 1 > api_endpoints.txt
```

### Continuous Monitoring

```bash
# Run daily scan via cron
0 0 * * * /usr/local/bin/chaathan wildcard -d target.com

# Cleanup old scans weekly
0 0 * * 0 /usr/local/bin/chaathan delete old 7
```

---

## Troubleshooting

### Tool not found

```bash
# Reinstall tools
chaathan setup

# Check if tool is in PATH
which subfinder
```

### Database locked

```bash
# Close any running scans, then:
chaathan delete old 0  # This runs VACUUM
```

### Scan interrupted

```bash
# List resumable scans
chaathan scans list

# Resume scan
chaathan scans resume <scan_id>
```

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## License

MIT License - see LICENSE file for details.

---

## Author

Created for the bug bounty community. Happy hunting!
