---
name: chaathan-recon-workflows
description: Use when modifying scan pipeline behavior — wildcard/company workflow steps, output files, scan progression, skip flags, resume, and interactions with reports, database, or notifications.
---

# Chaathan Recon Workflows

## When to use

Activate this skill when modifying or debugging the domain recon workflow steps, intermediate files, tool command arguments, or the data pipelines flowing through execution phases.

---

## 6-Phase Wildcard Workflow Topology (21 Steps)

The wildcard workflow runs in 6 logical phases. Steps communicate through files stored in `intermediate_files/` and save finalized data to SQLite and `final_files/`.

```
Phase 0: Proxy Scraping (Step 1)
   │
   ▼
Phase 1: Asset Discovery (Steps 2-5)   ──► Output: all_subdomains.txt
   │
   ▼
Phase 2: Validation (Steps 6-10)       ──► Output: live_hosts.txt
   │
   ▼
Phase 3: Content Discovery (Steps 11-16) ──► Output: all_urls_live.txt
   │
   ▼
Phase 4: Vulnerability Scan (Steps 17-20) ──► Persisted Findings
   │
   ▼
Phase 5: Fingerprinting (Step 21)      ──► Output: WAF/Tech JSON
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

### Phase 2 — Validation (`validation.go`)
- **Step 6: `dns_resolution`** (dnsx validation of gathered subdomains).
- **Step 7: `dns_bruteforce`** (shuffledns + massdns brute forcing; skip with `--skip-shuffledns`; auto-detects SecLists on device if `--dns-wordlist` is omitted).
- **Step 8: `port_scanning`** (naabu TCP scan; skip with `--skip-naabu`). Open ports are merged into the target list for subsequent probing.
- **Step 9: `http_probing`** (httpx probing for live web servers on both standard ports and naabu-discovered ports).
- **Step 10: `tls_analysis`** (tlsx certificate extraction; skip with `--skip-tlsx`). Extracts newly discovered subdomains from SANs, probes them, and merges them back.

### Phase 3 — Content Discovery (`content_discovery.go`, `js_deep_analysis.go`)
- **Step 11: `url_discovery`** (waybackurls + gau passive crawl).
- **Step 12: `web_crawling`** (katana + gospider crawling; skip with `--skip-crawl`).
- **Step 13: `js_deep_analysis`** (jsluice AST-based JS URL/object extraction + strict-format secret scanning with live validation + source map harvesting + subdomain extraction; priority-ranked top-5000 JS URLs; configurable via `general.js_analysis` in config.yaml).
- **Step 14: `dir_fuzzing`** (ffuf directory fuzzing on up to 1000 live hosts; auto-detects SecLists on device if `--wordlist` is omitted). Fuzzing results write to `ffuf_discovered_urls.txt`.
- **Step 15: `param_discovery`** (x8 parameter discovery; skip with `--skip-x8`; auto-detects SecLists parameter list on device). Natively routes through the rotating proxy using direct proxy arguments `-x`. Targets ONLY curated dynamic endpoints (extracted from crawls) and fuzzed directory URLs, completely bypassing flat live hostlists.
- **Step 16: `url_consolidation`** (httpx live URL validation and ROI metadata collection).

### Phase 4 — Vulnerability Scanning (`vulnerability_scanning.go`)
- **Step 17: `takeover_detection`** (Nuclei takeover checking on CNAME-filtered subdomains; runs first in Phase 4 for early alerts). CNAME data is refreshed into `intermediate_files/dnsx_cname_refresh.json` (never clobbers Step-6 `dnsx_resolved.json`); falls back to `dnsx_resolved.json` if the refresh yields 0 CNAME records.
- **Step 18: `vuln_scanning`** (Nuclei infra scan: CVE check + misconfigs).
- **Step 19: `vuln_scanning_urls`** (Nuclei DAST fuzzing mode on consolidated URL lists).
- **Step 20: `xss_scanning`** (dalfox parameter fuzzing; skip with `--skip-dalfox`).

### Phase 5 — Fingerprinting (`fingerprinting.go`)
- **Step 21: `tech_waf_fingerprinting`** (httpx + nuclei WAF fingerprint check; runs last to prevent WAF lockouts).

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

### 3. Scope Rules & Constraints
- **Optional Nature**: Scope configuration is strictly optional. If no scope config is defined, the scan operates in permissive mode (everything is in-scope, all ports are allowed, no IP exclusions).
- **Default Anchoring**: User-provided scope patterns are automatically anchored as `^(?:PATTERN)$` (unless they already start with `^` or end with `$`) to prevent substring-bypass injection (e.g. `example.com` matching `evil-example.com`).
- **IP Target Filtering**: Bare-IP targets are denied if `in_scope` patterns are defined but the target domain is empty. If no `in_scope` patterns are configured, bare-IP targets are permitted.

---

## Checklist for Adding or Modifying Scan Steps

### Structure & Wiring
1. **Verify inputs:** Check which files in `intermediate_files/` the step reads. If these depend on previous phases, ensure they check for file existence.
2. **Verify outputs:** Register output paths inside `Files` in `flow.go` using absolute paths. Never write files with hardcoded local paths.
3. **Step Completion Safety:** Always end step execution by returning:
   ```go
   return c.markStepCompleteIfNoFailure(stepName)
   ```
4. **Context Propagation (§3.8):** Any function that calls a tool, sends an HTTP request, or performs DNS resolution MUST accept `ctx context.Context` as its first parameter, and callers MUST pass `c.GoCtx`. This applies to internal sub-helpers too — not just the top-level step function. The `contextcheck` linter (enabled in `.golangci.yml`) enforces this; never invent `context.Background()` at an internal boundary to silence it — propagate the parent ctx instead.

### Skip & Cancellation
5. **CLI skip flag:** Every optional step MUST have a `--skip-<name>` flag wired through `cli/wildcard.go` → `RunConfig.Skip<Name>` → checked at the top of the step function with the standard pattern:
   ```go
   if c.SkipX {
       logger.StepHeader("Step N: Skipping X (--skip-x)")
       c.markStepCompleteIfNoFailure("step_name")
       return c.cancelled()
   }
   ```
6. **Interactive 's' key skip:** Long-running steps (fetch loops, bulk processing) MUST listen on `c.SkipChan` during execution. Use `drainSkipSignal(c)` before starting, create a cancellable `fetchCtx`, and spawn a goroutine that cancels it on skip signal. Workers check `fetchCtx.Done()`.
7. **Partial output saving:** If a step collects data incrementally (endpoints, secrets, subdomains), it MUST flush whatever was collected so far to disk on skip or cancellation — never discard findings. Use a `writePartialOutput` helper.

### Flow Integration
8. **Scope filtering:** Any step that extracts new hosts or subdomains MUST filter them through `c.ScopeFilter` (if non-nil) before writing output:
   ```go
   if c.ScopeFilter != nil {
       keep := c.ScopeFilter.IsInScope(s) && !c.ScopeFilter.IsOutOfScope(s)
   }
   ```
9. **Data feedback:** Discovered subdomains MUST be appended to `c.F.ConsolidatedSubs` so they appear in the report. Discovered endpoints MUST be fed to `ingest.ParseEndpointsFile` so they flow into URL consolidation and ROI.
10. **DB persistence:** Findings (secrets, vulns, endpoints) MUST be stored in SQLite via the `pkg/database` layer for ROI scoring and report generation.
11. **Notifications:** High-value findings (confirmed secrets, critical vulns, takeovers) MUST trigger `c.Notifier.SendFinding(...)` so Discord/Slack/Telegram alerts fire in real time.
12. **Progress logging:** Steps processing >100 items MUST log periodic progress (e.g., every 200 items) so the user sees activity during long operations.

### Documentation
13. **Documentation Integrity (Meta-Rule):** Every time you make changes to scan pipelines, workflow steps, or execution ordering in the codebase, you **must** update this `SKILL.md` and the root `README.md` to keep all step definitions, indices, and tool configurations in sync.
