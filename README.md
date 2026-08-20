# Chaathan

[![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=for-the-badge&logo=go)](https://golang.org)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite)](https://sqlite.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux)](https://linux.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> **Chaathan** is an enterprise-grade, single-binary Go pentesting orchestration framework built for professional bug hunters and red teams. It automates high-performance multi-phase reconnaissance, stores results in a centralized SQLite database, tracks targets over time with stateful diffs, and fires real-time alerts on critical discoveries.

---

## ⚡ Core Capabilities

*   **Stateful 23-Step Wildcard Recon**: End-to-end domain discovery, HTTP probing, historical URL extraction, vulnerability auditing, and WAF fingerprinting.
*   **Stateful 3-Step Company Discovery**: Network ASN mappings, reverse-WHOIS root enumeration, and public cloud asset discovery.
*   **Relational Intelligence**: Stores all assets, open ports, vulnerabilities, URLs, and API endpoints in a high-speed local SQLite database.
*   **Intelligent ROI Ranking**: Evaluates crawled endpoints to rank test targets by vulnerability density and potential ROI.
*   **Continuous Monitoring & Diffs**: Compare scans over time to immediately isolate new subdomains, ports, or vulnerabilities.
*   **Real-time Alerts**: Native webhook support for Discord, Slack, Telegram, and generic HTTP endpoints with automated subdomain takeover detection.

---

## 🎮 Consolidated Command Center

All commands in the Chaathan ecosystem—including installation, building, testing, scanning, querying, diffing, reporting, configuration, and scheduling—are consolidated in this single section. There are no scattered commands throughout the rest of the document.

### 1. Build & Installation (Makefile)

Run these targets from the root of the cloned repository directory to compile the binary and provision external engines.

```bash
# Clone the repository
git clone https://github.com/vishnu303/chaathan.git && cd chaathan

# Orchestration targets
make all            # Installs chaathan binary and provisions all 27 tools (Recommended)
make build          # Compiles the single chaathan binary in the local directory
make install        # Installs the compiled binary globally to /usr/local/bin
make setup          # Provisions and compiles all 27 third-party tools
make test           # Executes the Go unit test suite
make vet            # Performs static analysis and code verification
make clean          # Cleans up local compilation and build artifacts
```

### 2. Reconnaissance & Scanning

| Purpose | Command |
| :--- | :--- |
| **Standard Scan** | `chaathan wildcard -d target.com` |
| **Fast Scan** *(Skip heavy DNS/vuln/port scans)* | `chaathan wildcard -d target.com --skip-amass --skip-naabu --skip-nuclei` |
| **Stealth Scan** *(Proxy + Rate limit)* | `chaathan wildcard -d target.com --proxy socks5://127.0.0.1:9050 --rate-limit 10` |
| **Auto-Proxy Scan** *(Free rotating proxies)* | `chaathan wildcard -d target.com --auto-proxy` |
| **Auto-Proxy + Stealth** | `chaathan wildcard -d target.com --auto-proxy --rate-limit 10` |
| **Stateful Resume** | `chaathan wildcard -d target.com --resume <scan_id>` |
| **Session-Authenticated Scan** | `chaathan wildcard -d target.com --cookie "PHPSESSID=abc; auth=1" -H "X-Client: Pro" --token "jwt_value"` |
| **Execution Logging** | `chaathan wildcard -d target.com --log` |
| **Company Discovery** | `chaathan company -n "Acme Corporation"` |
| **Company Discovery** *(Fast)* | `chaathan company -n "Acme Corporation" --skip-metabigor` |
| **Company Discovery** *(With Logging)* | `chaathan company -n "Acme Corporation" --log` |


### 3. Database Queries & Filtering

Extract, pivot, and visually explore relational reconnaissance datasets directly from the local SQLite database.

```bash
# Interactive TUI Query Explorer
chaathan query                              # Launch the Unified Query & Findings TUI Console
chaathan query 12                           # Launch the TUI console pre-loaded with Scan #12

# Subdomain queries
chaathan query subdomains 1 --live          # Filter for live HTTP assets only
chaathan query subdomains 1 --grep api      # Filter subdomains containing 'api'
chaathan query subdomains 1 --json          # Output in clean JSON format
chaathan query subdomains 1 --live > live.txt # Pipe live subdomains to a text file

# Vulnerabilities, Ports, & Endpoints
chaathan query vulns 1 --severity critical  # Filter vulnerabilities by severity level
chaathan query ports 1                      # List all discovered open ports
chaathan query urls 1                       # List all historical and crawled URL paths
chaathan query urls 1 > urls_for_burp.txt   # Export all discovered URLs for external proxies
chaathan query endpoints 1                  # List resolved REST/GraphQL API endpoints

# Attack Surface Analysis
chaathan query roi 1 --limit 10             # Rank high-value web targets by estimated ROI
chaathan query roi 1 --json -o roi.json     # Export high-ROI assets directly to JSON
chaathan diff 1 2                           # Isolate differences (new subdomains, open ports, vulns) between two scans
```

### 4. Telemetry & Environment Control

Manage running scans, configure system options, clean up old records, and verify tool health.

```bash
# Dashboard & Telemetry
chaathan status                             # Show interactive dashboard of active and historical runs
chaathan scans list                         # List database scan history and run metadata
chaathan scans show <id>                    # Inspect detailed runtime metrics for a specific scan
chaathan scans resume <id>                  # Resume a suspended or interrupted scan from the database
chaathan scans delete <id>                  # Delete metadata and tables for a single scan ID

# Data Cleanups
chaathan delete target target.com           # Completely purge all database entries for a target domain
chaathan delete old 30                      # Delete all database runs and assets older than 30 days
chaathan delete list                        # Catalog and list all scans flagged as eligible for deletion

# Tooling Checks & Provisioning
chaathan setup                              # Install missing external third-party dependencies
chaathan setup --update                     # Force rebuild and update all 27 third-party tools to latest
chaathan tools list                         # Show categorization list of all 27 integrated engines
chaathan tools check                        # Perform disk audits and check binary paths for all tools
```

### 5. Config Management

```bash
chaathan config path                        # Display filepath to local config.yaml
chaathan config show                        # Print compiled configuration schema currently loaded
chaathan config edit                        # Open config.yaml in the system default CLI text editor
chaathan config set api_keys.github ghp_xx  # Programmatically write GitHub token for subdomains
chaathan config set notifications.enabled true # Programmatically enable notification dispatchers
# Passive search-engine providers for `uncover` (Step 5). FOFA / Quake /
# ZoomEye use email-style two-factor auth — set both the key and the email
# half, otherwise the engine is silently dropped from the search:
chaathan config set api_keys.shodan <key>            # Shodan (key only)
chaathan config set api_keys.censys_id <id>          # Censys — id + secret pair
chaathan config set api_keys.censys_secret <secret>
chaathan config set api_keys.fofa <key>              # FOFA — key + email pair
chaathan config set api_keys.fofa_email <email>
chaathan config set api_keys.quake <key>             # Quake (360) — key + email pair
chaathan config set api_keys.quake_email <email>
chaathan config set api_keys.zoomeye <key>           # ZoomEye — key + email pair
chaathan config set api_keys.zoomeye_email <email>
chaathan config reset                       # Overwrite config.yaml back to system defaults
```

### 6. Reports & Text File Exports

```bash
chaathan report generate 1 --format html    # Output an interactive HTML/Markdown report of scan assets
chaathan export 1                           # Dump raw text asset files from database to the workspace directory
```

### 7. Continuous Automation (System Cron)

Integrate these system scheduler triggers directly into your crontab environment for continuous surveillance.

```bash
# Quiet, bandwidth-controlled daily scan at midnight
0 0 * * * /usr/local/bin/chaathan wildcard -d target.com --rate-limit 5

# Compare latest scan states automatically every Sunday
chaathan diff <previous_id> <latest_id>

# Run a weekly database prune to clean out data older than 7 days
0 0 * * 0 /usr/local/bin/chaathan delete old 7
```

---

## 📦 System Provisioning & Requirements

Chaathan is packaged as a single static binary. It acts as an orchestration engine, launching and managing 27 third-party security utilities.

> [!IMPORTANT]  
> **Host Requirements:** Linux operating system (tested extensively on Ubuntu, Arch, and CachyOS) on AMD64, ARM64, or 386 architectures. Git must be pre-installed.
> Go 1.26 or greater is required; if missing or outdated, the setup script automatically installs and configures it under `~/.local/go` (requiring no sudo or root privileges).
> All external scanning engines (such as Amass, Nuclei, Httpx, Dalfox) are dynamically compiled and verified during the `make all` bootstrap process (syntax detailed in the Command Center).

---

## 🌪️ Reconnaissance Pipelines

Chaathan orchestrates complex multi-stage recon chains, consolidating raw outputs into optimized files and structured SQLite database schemas.

### A. Wildcard Workflow (21 Steps)
```
[Proxy Scraping] ──> [Asset Discovery] ──> [DNS & Port Validation] ──> [Content crawling] ──> [Vulnerability Audits] ──> [WAF Fingerprints]
```

| Phase | Steps | Key Tools Used | Central Artifact Generated (in `final_files/`) |
| :--- | :--- | :--- | :--- |
| **Phase 0: Proxy Scraping** | 1 | `mubeng`, `proxy-scraper-checker` | `proxy_pool.txt` + rotating proxy server |
| **Phase 1: Asset Discovery** | 2–5 | `subfinder`, `assetfinder`, `sublist3r`, `amass`, `uncover`, `github-subdomains` | `final_subdomains.txt` |
| **Phase 2: Validation** | 6–10 | `dnsx`, `shuffledns`, `naabu`, `httpx`, `tlsx` | `live_subdomains.txt`, `open_ports.txt` |
| **Phase 3: Content Discovery** | 11–16 | `waybackurls`, `gau`, `katana`, `gospider`, `jsluice`, `ffuf`, `x8`, `httpx` | `all_urls.txt`, `urls_200.txt`, `gf_secrets_findings.txt` |
| **Phase 4: Vulnerability Scan** | 17–20 | `nuclei` (takeovers, infra CVE, DAST), `dalfox` | `vulnerabilities.txt`, `vulnerabilities_critical_high.txt`, `dalfox_xss.jsonl` |
| **Phase 5: Fingerprinting** | 21 | `httpx`, `nuclei` | `httpx_tech.json`, `nuclei_waf.json` |

<details>
<summary>🔍 Expand Detailed 21-Step Pipeline Spec</summary>

| Step | Engine | Purpose / Action | Skip Trigger Flag |
| :--- | :--- | :--- | :--- |
| 1 | `mubeng` | Auto-scrape free proxies, validate against target, start rotating proxy | `--auto-proxy` to enable |
| 2 | `subfinder`, `assetfinder`, `sublist3r` | Passive domain enumeration | - |
| 3 | `amass` | High-depth active DNS brute-forcing | `--skip-amass` |
| 4 | `github-subdomains` | Scraping Github public repos for references | Needs `--github-token` |
| 5 | `uncover` | Passive search engine dorking (Shodan, FOFA) | `--skip-uncover` |
| 6 | `dnsx` | Subdomain validation & initial DNS filtering | - |
| 7 | `shuffledns` | Active DNS wild-card filtering and resolution | `--skip-shuffledns` |
| 8 | `naabu` | Multi-port validation scanning across discoveries | `--skip-naabu` |
| 9 | `httpx` | Live web application probing and tech fingerprinting | - |
| 10 | `tlsx` | SSL/TLS certificate analysis & SAN mining | `--skip-tlsx` |
| 11 | `waybackurls`, `gau` | Querying historical web archives for endpoints | - |
| 12 | `katana`, `gospider` | Dynamic web spiders crawling client assets | `--skip-crawl` |
| 13 | `jsluice` | JavaScript Deep Analysis (AST URL extraction + secrets + source maps) | `--skip-js` |
| 14 | `ffuf` | Focused path discovery using wordlists | Needs `--wordlist` |
| 15 | `x8` | Query parameter and hidden field discovery (ROI-ranked curated dynamic endpoints + fuzzing results) | `--skip-x8` |
| 16 | `httpx` | Live verification of extracted discovery links | - |
| 17 | `nuclei` | Proactive subdomain takeover analysis (findings live-verified before reporting) | `--skip-takeovers` |
| 18 | `nuclei` | General infra misconfiguration & public CVE auditing | `--skip-nuclei` |
| 19 | `nuclei` | Dynamic application testing (DAST) payload fuzzing | `--skip-nuclei` |
| 20 | `dalfox` | High-efficiency parameterized cross-site scripting (XSS) audit | `--skip-dalfox` |
| 21 | `httpx`, `nuclei` | Direct technology classification & WAF identification | `--skip-fingerprint` |

</details>

### B. Company Discovery Workflow (3 Steps)
Automates target profiling and corporate footprinting before launching active domain tests.

| Step | Utility | Scope of Action | Skip Trigger Flag |
| :--- | :--- | :--- | :--- |
| **1** | `metabigor` | Discovers network ranges, ASN prefixes, and routing tables | `--skip-metabigor` |
| **2** | `amass intel` | Performs reverse WHOIS lookups to discover root domain registrations | `--skip-amass-intel` |
| **3** | `cloud_enum` | Audits public cloud storage infrastructure (AWS, GCP, Azure) | `--skip-cloud-enum` |

---

## 🛡️ Enterprise Stealth & WAF Bypass Playbook

Chaathan is designed to traverse hostile, firewalled networks. It includes granular controls for request personalization, proxy routing, and firewall evasion. Detailed CLI flag invocations are cataloged inside the **Consolidated Command Center** under *Reconnaissance & Scanning*.

### 🔑 Authenticated State Auditing
Allows you to audit deeply nested authenticated application zones (private APIs, parameterized endpoints, gated directories). You can feed complex session cookies (`--cookie`), customized request headers (`-H`), and shorthand OAuth authorization tokens (`--token`) directly into Chaathan. The engine transparently parses these structures and cascades them down to sub-executables like `httpx`, `katana`, `nuclei`, and `dalfox`.

### 🕴️ Complete Anonymization & Routing
- **User-Agent Rotation:** Enabled natively by default (`ua_rotation: true` in config). Chaathan dynamically swaps standard command-line user-agent headers for authentic, rotating desktop and mobile browser signatures (Chrome, Firefox, Safari) on every request, evading signature-based blocking.
- **Proxy Cascading:** Pipe all underlying scanning traffic through an external gateway. Pass SOCKS5 (e.g., Tor) or HTTP (e.g., Burp Suite) configurations to route execution, audit logs, or debugging sessions.
- **Automated Proxy Rotation (`--auto-proxy`):** Scrapes and validates free proxies once at scan start (Step 1), then starts `mubeng` as a local rotating proxy server for the remainder of the scan. Every outgoing request from every tool uses a different exit IP address — no manual proxy configuration needed.

### 🎯 Target Scope & Domain Filtering

Chaathan supports precise filtering of target domains, IPs, and ports to restrict scanning activities. The scope configuration is defined in the `config.yaml` file under the `scope` block:
- **Permissive by Default**: Scope configuration is strictly optional. If no scope config is defined, the scan operates in a completely permissive mode (everything is considered in-scope, all ports are allowed, and no IPs are excluded).
- **Default Regex Anchoring**: When scope patterns (in-scope or out-of-scope) are configured, the engine automatically anchors the patterns as `^(?:PATTERN)$` (unless they already start with `^` or end with `$`) to prevent substring-bypass injection (e.g., an in-scope pattern `example.com` will not match `evil-example.com` or `example.com.attacker.io`).
- **IP Target Behavior**: When `in_scope` patterns are active, scanning bare-IP targets (targets where the domain is empty) is blocked. If no `in_scope` patterns are defined, bare-IP targets are permitted.

---

## ⚖️ Legal & Disclaimer

**Disclaimer:** This utility is designed strictly for authorized penetration testing, vulnerability assessment, and approved bug bounty participation. The author assumes absolutely zero liability for unauthorized exploitation, service degradation, or system misuse. Ensure explicit written consent is secured before directing high-volume testing assets at external target nodes.

**License:** MIT License. Developed by [vishnu303](https://github.com/vishnu303).
