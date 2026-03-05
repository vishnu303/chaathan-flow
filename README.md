# Chaathan

A modular CLI pentesting framework for bug bounty reconnaissance and vulnerability scanning. Single binary, persistent database, 24+ integrated tools.

```
   _____ _                 _   _                 
  / ____| |               | | | |                
 | |    | |__   __ _  __ _| |_| |__   __ _ _ __  
 | |    | '_ \ / _' |/ _' | __| '_ \ / _' | '_ \ 
 | |____| | | | (_| | (_| | |_| | | | (_| | | | |
  \_____|_| |_|\__,_|\__,_|\__|_| |_|\__,_|_| |_|
```

## What It Does

Chaathan runs a **17-step automated recon workflow** on a target domain — subdomain discovery, DNS resolution, port scanning, web crawling, vulnerability scanning, XSS detection, subdomain takeover checks — and stores everything in a local SQLite database you can query, diff, and export.

## Install

```bash
git clone https://github.com/vishnu303/chaathan-flow.git
cd chaathan-flow

# Build
make build

# Install system-wide (optional)
make install

# Install all external tools
chaathan setup
```

**Requirements:** Go 1.21+, Git, Linux

## Quick Start

```bash
# Install tools (first time)
chaathan setup

# Run full recon
chaathan scan -d target.com

# Check what's installed
chaathan tools check

# View results
chaathan status
chaathan query vulns 1 --severity critical
chaathan query subdomains 1 --live

# Generate report
chaathan report generate 1 --format html
```

## The 17-Step Workflow

```bash
chaathan scan -d target.com
```

| Step | Tool(s) | What It Does | Skip Flag |
|------|---------|-------------|-----------|
| 1 | Subfinder, Assetfinder, Sublist3r | Passive subdomain enumeration | — |
| 2 | Waybackurls, GAU | Historical URL discovery | — |
| 3 | Amass | Active DNS brute-force | `--skip-amass` |
| 4 | github-subdomains | GitHub scraping for subdomains | needs `--github-token` |
| 5 | Uncover | Shodan/Censys/Fofa passive dorking | `--skip-uncover` |
| 6 | DNSx | Consolidation + DNS resolution | — |
| 7 | Alterx → DNSx | Smart subdomain permutation | — |
| 8 | Httpx | HTTP probing + tech detection | — |
| 9 | tlsx | TLS cert analysis + SAN extraction | `--skip-tlsx` |
| 10 | Naabu | Port scanning (all subdomains) | `--skip-naabu` |
| 11 | Katana, GoSpider | Web crawling | `--skip-crawl` |
| 12 | LinkFinder | JavaScript endpoint extraction | — |
| 13 | CeWL | Custom wordlist generation | — |
| 14 | ffuf | Directory fuzzing | needs `--wordlist` |
| 15 | Nuclei | Template-based vuln scanning | `--skip-nuclei` |
| 16 | Subjack | Subdomain takeover detection | `--skip-subjack` |
| 17 | Dalfox | XSS scanning on parameterized URLs | `--skip-dalfox` |

**Fast scan** (skip heavy tools):
```bash
chaathan scan -d target.com --skip-amass --skip-naabu --skip-nuclei
```

**Resume interrupted scan:**
```bash
chaathan scan -d target.com --resume <scan_id>
```

## Commands

| Command | What It Does |
|---------|-------------|
| `chaathan scan -d <domain>` | Run the 17-step recon workflow |
| `chaathan status` | Dashboard — recent scans, progress, stats |
| `chaathan tools list` | List all 24 tools with categories |
| `chaathan tools check` | Check which tools are installed |
| `chaathan diff <id1> <id2>` | Compare two scans — find new assets/vulns |
| `chaathan scans list` | List all past scans |
| `chaathan scans show <id>` | Show scan details and statistics |
| `chaathan query subdomains <id>` | Query discovered subdomains |
| `chaathan query vulns <id>` | Query vulnerabilities |
| `chaathan query ports <id>` | Query open ports |
| `chaathan query urls <id>` | Query discovered URLs |
| `chaathan query endpoints <id>` | Query API endpoints |
| `chaathan report generate <id>` | Generate report (md/html/json/text) |
| `chaathan export <id>` | Export results to text files |
| `chaathan delete target <domain>` | Delete all data for a target |
| `chaathan delete scan <id>` | Delete a specific scan |
| `chaathan delete old <days>` | Delete scans older than N days |
| `chaathan config show` | Show current configuration |
| `chaathan config edit` | Edit config in your editor |
| `chaathan setup` | Install all external tools |

## Query Examples

```bash
# Subdomains
chaathan query subdomains 1 --live         # only live ones
chaathan query subdomains 1 --grep api     # filter by pattern
chaathan query subdomains 1 --json         # JSON output

# Vulnerabilities
chaathan query vulns 1 --severity critical # filter by severity

# Pipe to other tools
chaathan query subdomains 1 --live > live.txt
chaathan query urls 1 > urls_for_burp.txt
```

## Scan Diffing

Compare two scans of the same target to find what changed:

```bash
chaathan diff 1 2
```

Shows new/removed subdomains, new open ports, new vulnerabilities with severity, and new URLs. Useful for continuous monitoring.

## Configuration

Config lives at `~/.chaathan/config.yaml`:

```bash
chaathan config edit       # open in editor
chaathan config show       # view current config
chaathan config set api_keys.github ghp_xxxxx
```

Key settings:

```yaml
general:
  max_retries: 1          # auto-retry failed tools
  retry_delay_sec: 3      # seconds between retries

tools:
  subfinder:
    threads: 30
    timeout: 30
  naabu:
    threads: 25
    rate: 1000
    ports: "top-1000"
  nuclei:
    concurrency: 25
    rate_limit: 150
    severity: [low, medium, high, critical]
    exclude_tags: [dos, fuzz]
  httpx:
    threads: 50
    timeout: 10
    ports: ["80", "443", "8080", "8443"]

notifications:
  enabled: false
  min_severity: high
  discord_webhook: ""
  slack_webhook: ""
  telegram_bot_token: ""
  telegram_chat_id: ""
```

## Notifications

Get alerts on Discord/Slack/Telegram when critical findings are discovered:

```bash
chaathan config set notifications.enabled true
chaathan config set notifications.discord_webhook https://discord.com/api/webhooks/xxx/yyy
chaathan config set notifications.min_severity high
```

Subdomain takeover findings trigger immediate notifications.

## Integrated Tools (24)

| Category | Tools |
|----------|-------|
| **Subdomain Discovery** | subfinder, assetfinder, sublist3r, amass, alterx |
| **DNS** | dnsx, shuffledns |
| **Web Probing** | httpx, tlsx |
| **Port Scanning** | naabu |
| **URL Discovery** | waybackurls, gau |
| **Web Crawling** | katana, gospider |
| **JS Analysis** | linkfinder |
| **Fuzzing** | ffuf |
| **Wordlists** | cewl |
| **Vuln Scanning** | nuclei, subjack, dalfox |
| **Passive Recon** | uncover, metabigor, github-subdomains |
| **Cloud** | cloud_enum |

```bash
chaathan tools check    # see what's installed
chaathan setup          # install everything
```

## Output Structure

```
~/.chaathan/
├── config.yaml
├── chaathan.db               # SQLite — all results
├── scans/
│   └── target.com/
│       ├── subfinder.txt
│       ├── all_subdomains.txt
│       ├── httpx_live.json
│       ├── naabu_ports.txt
│       ├── tlsx_certs.json
│       ├── nuclei_vulns.json
│       ├── subjack_takeovers.txt
│       ├── dalfox_xss.json
│       ├── alterx_permutations.txt
│       ├── uncover.json
│       ├── SUMMARY.txt
│       └── REPORT.md
├── reports/
│   └── scan_1.md
└── state/
    └── scan_1.json           # for resume
```

## Makefile

```bash
make build          # build binary (stripped, ~11MB)
make install        # install to /usr/local/bin
make clean          # remove build artifacts
make test           # run tests
make vet            # static analysis
make setup          # build + install tools
make tools-check    # check installed tools
make all            # build + install + setup
```

## Continuous Monitoring

```bash
# Daily scan via cron
0 0 * * * /usr/local/bin/chaathan scan -d target.com

# Weekly diff to spot changes
chaathan diff <old_scan_id> <new_scan_id>

# Cleanup old data
0 0 * * 0 /usr/local/bin/chaathan delete old 7
```

## Project Structure

```
chaathan-flow/
├── main.go
├── Makefile
├── cli/
│   ├── root.go              # CLI setup, global flags
│   ├── wildcard.go          # 17-step recon workflow
│   ├── company.go           # Company/org workflow
│   ├── setup.go             # Tool installation
│   ├── scans.go             # Scan management
│   ├── query.go             # Query results
│   ├── report.go            # Report generation
│   ├── export.go            # Text file export
│   ├── delete.go            # Data cleanup
│   ├── config.go            # Config management
│   ├── status.go            # Status dashboard
│   ├── tools_cmd.go         # Tools list/check
│   └── diff.go              # Scan comparison
├── pkg/
│   ├── config/config.go     # YAML config
│   ├── database/database.go # SQLite operations
│   ├── logger/logger.go     # Colored output
│   ├── notify/notify.go     # Discord/Slack/Telegram
│   ├── report/report.go     # Report templates
│   ├── runner/runner.go     # Tool execution + retry
│   ├── scan/scan.go         # Scan state + resume
│   ├── scope/scope.go       # Scope filtering
│   ├── tools/tools.go       # Tool wrappers (24 tools)
│   └── utils/
│       ├── file.go          # File utilities
│       ├── parser.go        # Output parsers
│       ├── export.go        # Text export
│       └── validate.go      # Input validation
```

## License

MIT

## Author

Built by [vishnu303](https://github.com/vishnu303) for the bug bounty community.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The author is not responsible for any misuse, damage, or illegal activities caused by the usage of this tool. Use it at your own risk.
