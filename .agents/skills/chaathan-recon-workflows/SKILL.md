---
name: chaathan-recon-workflows
description: Use when modifying scan pipeline behavior — wildcard/company workflow steps, output files, scan progression, skip flags, resume, and interactions with reports, database, or notifications.
---

# Chaathan Recon Workflows

## When to use

Activate this skill when modifying or debugging the domain recon workflow steps, intermediate files, tool command arguments, or the data pipelines flowing through execution phases.

---

## 6-Phase Wildcard Workflow Topology (23 Steps)

The wildcard workflow runs in 6 logical phases. Steps communicate through files stored in `intermediate_files/` and save finalized data to SQLite and `final_files/`.

```
Phase 0: Proxy Scraping (Step 1)
   │
   ▼
Phase 1: Asset Discovery (Steps 2-6)   ──► Output: all_subdomains.txt
   │
   ▼
Phase 2: Validation (Steps 7-11)       ──► Output: live_hosts.txt
   │
   ▼
Phase 3: Content Discovery (Steps 12-18) ──► Output: all_urls_live.txt
   │
   ▼
Phase 4: Vulnerability Scan (Steps 19-22) ──► Persisted Findings
   │
   ▼
Phase 5: Fingerprinting (Step 23)      ──► Output: WAF/Tech JSON
```

---

## Workflow Steps Catalog

### Phase 0 — Proxy Scraping (`proxy_scraping.go`)
- **Step 1: `proxy_scraping`** (mubeng, proxy-scraper-checker):
  - Automatically triggered if `--auto-proxy` is set and `--proxy` is not.
  - Runs **once at scan start** (Step 1 only) — the proxy pool is not re-scraped or re-validated between later phases.
  - `proxy-scraper-checker` scrapes 100+ public proxy feeds and validates each against `https://<target-domain>` (10-minute default timeout).
  - Valid proxies are sorted by speed and written to `proxy_pool.txt`.
  - `mubeng` starts as a background rotating proxy process on `127.0.0.1:<random-port>`.
  - Updates `c.Proxy` and `c.Cfg.General.Proxy` so all subsequent tool execution commands route their traffic through the rotating proxy for the rest of the scan.
  - `finalizeScan()` kills the mubeng process group.

### Phase 1 — Asset Discovery (`asset_discovery.go`)
- **Step 2: `passive_enum`** (subfinder, assetfinder, sublist3r parallel run).
- **Step 3: `active_enum`** (amass active run; skip with `--skip-amass`).
- **Step 4: `github_recon`** (github-subdomains; requires `--github-token`).
- **Step 5: `search_engine_recon`** (uncover search engine scraping; skip with `--skip-uncover`).
- **Step 6: `js_subdomain_discovery`** (hakrawler crawl for hosts; skip with `--skip-hakrawler`).

### Phase 2 — Validation (`validation.go`)
- **Step 7: `dns_resolution`** (dnsx validation of gathered subdomains).
- **Step 8: `dns_bruteforce`** (shuffledns + massdns brute forcing; skip with `--skip-shuffledns`).
- **Step 9: `port_scanning`** (naabu TCP scan; skip with `--skip-naabu`). Open ports are merged into the target list for subsequent probing.
- **Step 10: `http_probing`** (httpx probing for live web servers on both standard ports and naabu-discovered ports).
- **Step 11: `tls_analysis`** (tlsx certificate extraction; skip with `--skip-tlsx`). Extracts newly discovered subdomains from SANs, probes them, and merges them back.

### Phase 3 — Content Discovery (`content_discovery.go`)
- **Step 12: `url_discovery`** (waybackurls + gau passive crawl).
- **Step 13: `web_crawling`** (katana + gospider crawling; skip with `--skip-crawl`).
- **Step 14: `js_analysis`** (GoLinkFinder parsing of JS links on all live hosts, capped at top 50).
- **Step 15: `dir_fuzzing`** (ffuf directory fuzzing on up to 25 live hosts; requires `--wordlist`). Fuzzing results write to `ffuf_discovered_urls.txt`.
- **Step 16: `param_discovery`** (x8 parameter discovery; skip with `--skip-x8` or `--skip-arjun`). Natively routes through the rotating proxy using direct proxy arguments `-x`. Targets ONLY curated dynamic endpoints (up to 150 extracted from crawls) and fuzzed directory URLs, completely bypassing flat live hostlists.
- **Step 17: `url_consolidation`** (httpx live URL validation and ROI metadata collection).
- **Step 18: `js_secret_scan`** (downloads JS files, runs gf secret search pattern).

### Phase 4 — Vulnerability Scanning (`vulnerability_scanning.go`)
- **Step 19: `takeover_detection`** (Nuclei takeover checking on CNAME-filtered subdomains; runs first in Phase 4 for early alerts).
- **Step 20: `vuln_scanning`** (Nuclei infra scan: CVE check + misconfigs).
- **Step 21: `vuln_scanning_urls`** (Nuclei DAST fuzzing mode on consolidated URL lists).
- **Step 22: `xss_scanning`** (dalfox parameter fuzzing; skip with `--skip-dalfox`).

### Phase 5 — Fingerprinting (`fingerprinting.go`)
- **Step 23: `tech_waf_fingerprinting`** (httpx + nuclei WAF fingerprint check; runs last to prevent WAF lockouts).

---

## Critical Data Flow Invariants

### 1. High-Performance URL Stream Pipeline ($O(1)$ Memory)
To process huge URL lists (100k+ inputs) without crashing VPS systems:
- Always read inputs line-by-line using `bufio.Scanner` rather than loading entire lists into slice arrays.
- Deduplicate URL paths by formatting path keys (`pathKey()`), storing only unique query formats in memory maps.
- Maintain a bounded min-heap priority queue via the standard `"container/heap"` package to cap URL sets (e.g. `dalfox.max_urls` limit). When the queue is full, lower-scoring items (determined by heuristics such as static file suffixes or missing query parameters) are evicted.

### 2. Authenticated Session Fuzzing
- Support `--cookie`, `--header` (`-H`), and `--token` (sends Bearer token headers) flags.
- Configured globally inside `RunConfig` $\rightarrow$ injected into the command parameters formulating functions inside `pkg/tools/` for Httpx, Katana, ffuf, Nuclei, and Dalfox.

---

## Checklist for Modifying Scan Steps

1. **Verify inputs:** Check which files in `intermediate_files/` the step reads. If these depend on previous phases, ensure they check for file existence.
2. **Verify outputs:** Register output paths inside `Files` in `flow.go` using absolute paths. Never write files with hardcoded local paths.
3. **Step Completion Safety:** Always end step execution by returning:
   ```go
   return c.markStepCompleteIfNoFailure(stepName)
   ```
4. **Context Propagation:** Ensure all tool executions receive `c.GoCtx` to enable clean halts when receiving SIGINT/SIGTERM.
5. **Documentation Integrity (Meta-Rule):** Every time you make changes to scan pipelines, workflow steps, or execution ordering in the codebase, you **must** update this `SKILL.md` and the root `README.md` to keep all step definitions, indices, and tool configurations in sync (only if necessary).
