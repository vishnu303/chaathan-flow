# Vulnerability Scanning Overhaul Plan

Scope: Phase 4 of the wildcard workflow — `pkg/wildcard_flow/vulnerability_scanning.go` (Steps 19–22),
the scanner abstraction `pkg/tools/vulnerability_engine.go`, tool wrappers `pkg/tools/tools.go`,
ingest (`pkg/ingest/parser.go`), DB (`pkg/database/`), config (`pkg/config/config.go`),
and downstream surfaces (ROI, query, report, notify).

Goal: turn Phase 4 from "2 nuclei passes + dalfox on whatever URLs survived" into a layered,
config-honest, exploit-aware vuln pipeline — without breaking step names, resume, or DB keys.

---

## 1. Current-state audit (what is actually wrong)

### 1.1 Real defects (bugs, not opinions)

| # | Defect | Evidence |
|---|--------|----------|
| A1 | **`nuclei.severity` config is dead code.** Default is `[low, medium, high, critical]` but no wrapper ever passes `ScanOptions.Severity`, so the hardcoded fallback always wins: `critical,high` (pass A / takeover) and `critical,high,medium` (misconfig / dast). | `pkg/tools/tools.go:736-790` (no `Severity:` field set), fallback logic `pkg/tools/vulnerability_engine.go:53-59` |
| A2 | **`nuclei.exclude_tags` config is dead code.** Same story: `opts.ExcludeTags` never set by any wrapper; only `nucleiModes[mode].etags` applies. | `pkg/tools/vulnerability_engine.go:175`, `tools.go:736-790` |
| A3 | **Naabu results are never used by the vuln phase.** Step 9 discovers open ports (Redis 6379, ES 9200, FTP 21, SSH 22, RDP 3389…). Phase 4 only scans HTTP URLs — zero non-web service coverage. Nuclei supports this natively (`-pt network,ssl` on `host:port` input). | `vulnerability_scanning.go:54-115` only reads `httpx_live_hosts.txt` |
| A4 | **Comment drift:** `stepTakeoverDetection` is headed "Step 20" but is Step 19. | `vulnerability_scanning.go:246-248` |
| A5 | **"from N live URLs" label** is wrong after a skip (file is partial/raw fallback). | `vulnerability_scanning.go:185,190,200` (from log-analysis session) |

### 1.2 Structural weaknesses

| # | Weakness | Why it hurts |
|---|----------|--------------|
| B1 | Pass A is **only** `-as` (nuclei's internal tech map). No explicit tech→tag targeting from the httpx `-tech-detect` data we already collected in step 10. | Templates for detected tech that `-as` doesn't map are never run. |
| B2 | Pass B tags = `default-login,misconfig,unauth` only. The **`exposure` tag family** (`.git/config`, `.env`, backups, debug panels) is excluded in pass A's etags and absent from pass B's tags → classic low-hanging fruit never tested. | `vulnerability_engine.go:99,107` |
| B3 | Step 21 DAST quality is hostage to URL discovery. When crawls are skipped/small (observed: 29 URLs from 343), DAST+Dalfox are near-useless. No fallback targeting. | log: pinterest run |
| B4 | No exploit-context: findings have severity but **no CVE ID extraction, no EPSS score, no CISA-KEV flag**. A "high" CVE with public exploitation looks identical to a theoretical one. ROI (`roi.go:645-654`) scores severity only. | `database.go:229-242`, `roi.go` |
| B5 | Template freshness is never ensured (`nuclei -update-templates` never invoked) → coverage silently decays over time. | — |
| B6 | No SQLi specialist. Nuclei DAST covers basic injection; sqlmap is still materially better for SQLi confirmation on high-value params. | — |
| B7 | Dalfox runs blind (no headless DOM verification) → misses DOM XSS; reflected-only. | `vulnerability_engine.go:221-250` |
| B8 | Takeover false-positive validation loop is serial (DNS+2×HTTP per finding). | `vulnerability_scanning.go:500-549` |
| B9 | Findings are not grouped by CVE across passes/templates in any surface; same CVE via two templates = two rows, no correlation. | `ingest/parser.go:333-387` |

### 1.3 What is already good (do NOT regress)

- Skip-safe partial parsing of every pass (`runWithSkip` + parse-anyway).
- Notification delta-snapshot (`snapshotVulnIDs`) — no flood on resume.
- Takeover CNAME pre-filter + active FP validation.
- DAST rate/concurrency halving, OOB disabled by default, per-run `MaxTimeout`.
- Dedup unique index `(scan_id, host, template_id, url)` on `vulnerabilities`.
- `evidence`/`matcher` retention for reports.

---

## 2. Design decisions (rules for the rewrite)

1. **Step names and order are frozen** (`takeover_detection`, `vuln_scanning`, `vuln_scanning_urls`, `xss_scanning`) → resume and `scans show` stay valid. All new work lands as *sub-passes inside* these steps.
2. **Config must tell the truth.** Every key in `NucleiConfig`/`DalfoxConfig` either gets wired or gets deleted. No dead knobs.
3. **Everything new is default-safe:** offline-friendly, no new required tools, no behavior change for existing users unless a flag/config opts in (exception: wiring dead config keys = bug fix).
4. **O(1)-memory file handling** for any new target-list building (skill invariant §1).
5. **ctx propagation** through every new network call (skill invariant §4; `contextcheck` enforced).
6. **One owner per concern:** scanners → `pkg/tools`, vuln intel → new `pkg/vulnintel`, persistence → `pkg/database`, orchestration stays in `pkg/wildcard_flow`.

---

## 3. Work items

### P0 — Fix the lies (small, do first)

**T1. Wire severity + exclude_tags into all nuclei passes.**
- `pkg/tools/tools.go`: `RunNucleiSmartCVE`, `RunNucleiMisconfig`, `RunNucleiDAST`, `RunNucleiTakeovers` populate `ScanOptions.Severity` and `ScanOptions.ExcludeTags` from `t.config().Nuclei`.
- `pkg/config/config.go`: change defaults to reflect today's *effective* behavior so nothing silently rescans wider: `Severity: [critical, high]`. Add optional `URLSeverity []string yaml:"url_severity"` default `[critical, high, medium]` used by misconfig + dast modes.
- `vulnerability_engine.go:53-59`: keep existing fallbacks only when both config slices are empty.
- Fix A4 comment (Step 20 → Step 19) and A5 label ("from %d URLs") in the same pass.

**T2. Template freshness gate.**
- New helper `ensureNucleiTemplatesFresh(ctx, cfg)` in `pkg/tools` (or `pkg/wildcard_flow/helpers.go`): marker file `~/.chaathan/cache/nuclei-templates.last` (mtime check); if older than `nuclei.template_update_hours` (default 24), run `nuclei -update-templates` with 5-min timeout, non-fatal on failure (debug log only). Called once at the top of step 20.
- Add `template_update_hours` to `NucleiConfig`.

**T3. Takeover validation parallelism (B8).**
- `ValidateTakeoversFile`: collect findings first, then validate with an `errgroup` limited to 10 workers, ctx threaded; preserve "truncate file when nothing validates" semantics.

### P1 — Coverage (the actual "make it not shit" part)

**T4. Pass C — network/service scanning (fixes A3).**
- New nuclei mode `"network"` in `nucleiModes`: `pt: "network,ssl"`? → verify exact `-pt` syntax at implementation time (comma-separated protocol types; `ssl` covers cert-expiry/weak-cipher templates on arbitrary ports).
- Target list: build `host:port` file from `c.F.NaabuOut` (stream, dedup, cap 5k lines). If naabu file missing/empty (step 9 skipped) → skip Pass C with one debug line. Optionally merge `:443` for live hosts as fallback.
- Output `final_files/nuclei_network.json` → `ingest.ParseNucleiOutput` (reuse; no new parser).
- Config: `nuclei.network_scan` (default **true** — it uses data we already have), respects `nuclei.severity`.
- Wrapper `RunNucleiNetwork(ctx, targetsFile, out)` in `tools.go`.

**T5. Pass B+ — exposure & panel templates (fixes B2).**
- Extend misconfig mode tags via new config `nuclei.misconfig_tags` default:
  `[default-login, misconfig, unauth, exposure, panel, debug, backup]`.
- `vulnerability_engine.go`: misconfig mode reads tags from config when set (modeCfg tags as fallback).
- Keep `-pt http`, etags `dos,fuzz`.

**T6. Tech-explicit template targeting (fixes B1, cheap).**
- After Pass A, parse `httpx_live.json` tech arrays → map well-known techs to nuclei tags via a small table (wordpress→`wordpress`, nginx→`nginx`, apache→`apache`, jenkins→`jenkins`, gitlab→`gitlab`, jira→`jira,atlassian`, drupal→`drupal`, phpmyadmin→`phpmyadmin`, elasticsearch→`elasticsearch`, …).
- If ≥1 tag mapped, run Pass A2: `nuclei -tags <mapped> -severity <cfg>` on live hosts (no `-as`), output appended to `nuclei_vulns.json` (dedup via unique index). Skip silently when no tech detected.
- Tag map lives in `pkg/tools` as `var nucleiTechTagMap`; config escape hatch `nuclei.tech_tags_extra map[string]string`.

**T7. Step 21 DAST hardening (fixes B3).**
- If parameterized count < 50, *additionally* include top-ROI URLs (from `CollectScopedURLs` heap, same cap) that carry any query string — already covered — plus **host root URLs of high-value hosts** (admin/login/staging markers) so DAST fuzzing has something to chew on. Implement inside `CollectScopedURLs` as a second-chance fill, clearly logged ("supplemented with %d high-value host roots").
- Add config `nuclei.dast_fuzz_types` (e.g. `query,body`) → maps to nuclei's DAST fuzz placement flag; **verify flag name against installed nuclei version at implementation time** (`-fuzz-type` in v3.3+); omit flag when unset.
- Keep DAST severity = `url_severity`.

**T8. Dalfox DOM verification (fixes B7).**
- `vulnerability_engine.go` `DalfoxScanner.Scan`: when `dalfox.headless` is `on` (or `auto` + chrome/chromium found in PATH), append `--headless`; config `dalfox.headless: auto`.
- Log one debug line when headless is requested but no browser found (fall back silently).

**T9. SQLMap specialist pass (fixes B6) — opt-in, default OFF.**
- Registry + setup: add `sqlmap` to `pkg/tools/registry.go` (optional, InstallURL via git clone / package manager note), `pkg/runner/runner.go` docker-image map entry (skip docker support if image awkward — mark native-only), `pkg/setup` verification.
- Wrapper `RunSQLMap(ctx, url, outDir)` → `sqlmap -u <url> --batch --smart --level=1 --risk=1 --random-agent --forms=false --output-dir=<dir> --results-file=<csv>` with per-URL timeout (config `sqlmap.per_url_timeout_min`, default 3) and proxy via `--proxy`.
- Step 21 sub-pass (after DAST): top-N (`sqlmap.max_urls`, default 25) parameterized URLs by ROI score → sequential sqlmap runs, each in its own `runWithSkip`-aware ctx so one skip aborts the pass; parse `results.csv` (target, parameter, technique, dbms) → `database.AddVulnerability(scanID, host, url, "sqlmap-<technique>", "SQL Injection (sqlmap confirmed)", "high", …)` — sqlmap-confirmed = high confidence.
- Config block `tools.sqlmap: {enabled: false, max_urls: 25, per_url_timeout_min: 3}`; CLI flag `--enable-sqlmap` mirrors other skip flags (positive flag because default-off).

### P2 — Exploit intelligence & triage (fixes B4, B9)

**T10. New package `pkg/vulnintel`.**
- `Enrich(ctx, scanID)` called once at end of step 20 and after step 21/22 passes (idempotent):
  1. Extract CVE IDs (regex `(?i)CVE-\d{4}-\d{4,7}`) from `template_id`, `name`, `description` of unenriched vuln rows; store `cve_id`.
  2. **EPSS**: one bulk GET `https://api.first.org/data/v1/epss?cve=<csv>` (chunks of 100); store score. Cache response per-CVE in `~/.chaathan/cache/epss.json` with 24h TTL (`vuln_intel.cache_hours`).
  3. **CISA KEV**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` cached likewise; set `kev=1` on match.
  - All failures → debug log, continue (offline-safe). ctx throughout.
- **DB migration** (`pkg/database/database.go` init): `PRAGMA table_info(vulnerabilities)` guard → `ALTER TABLE vulnerabilities ADD COLUMN cve_id TEXT`, `ADD COLUMN epss REAL DEFAULT 0`, `ADD COLUMN kev INTEGER DEFAULT 0`. INSERT OR IGNORE signature stays (columns nullable/defaulted).

**T11. Surface the intelligence.**
- ROI (`pkg/database/roi.go`): vuln score multiplier — `kev=1` → +50 bonus (or ×1.5, decide in impl); `epss ≥ 0.5` → +25; cap interactions with existing severity points. Add `KEV`/`EPSS` to `Reasons`.
- `query vulns`: add `--kev` and `--min-epss` filters; default sort unchanged, KEV rows badged.
- Report (`pkg/report`): new subsection "Actively Exploited (CISA KEV)" at the top of vuln section; show EPSS in finding table when >0.
- Notify: KEV findings notify at `medium`+ severity regardless of `min_severity: high` (KEV overrides).

**T12. CVE grouping in report/query (B9).**
- When `cve_id` present, group duplicate CVE rows (different templates/hosts) under one heading with affected hosts listed — report-level only, DB rows unchanged.

### P3 — Docs & validation (mandatory per AGENTS.md meta-rule)

**T13. Documentation sync.**
- `.agents/skills/chaathan-recon-workflows/SKILL.md`: update Phase 4 step descriptions (Pass C, Pass A2, sqlmap sub-pass, enrichment).
- `.agents/skills/chaathan-tooling-setup/SKILL.md`: sqlmap install/verify.
- `.agents/skills/chaathan-reporting-query/SKILL.md`: `--kev` / `--min-epss`, KEV report section.
- `README.md`: vuln phase description + new config keys.
- `AGENTS.md`: only if step catalog/config section is enumerated there (check before editing).

**T14. Validation baseline (WSL):**
```bash
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && gofmt -w ."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && golangci-lint run ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go build -buildvcs=false -o chaathan ."
```
Plus: `./chaathan wildcard --help` diff review; one live smoke scan on a disposable target with crawls enabled; unit tests for: severity/etag wiring (arg builder tests), EPSS/KEV parsing (httptest), sqlmap CSV parser, ROI multiplier, migration idempotency.

---

## 4. Config delta (final shape)

```yaml
tools:
  nuclei:
    severity: [critical, high]            # NOW ACTUALLY WIRED (passes A/A2/C/takeover)
    url_severity: [critical, high, medium] # NEW — passes B/DAST
    exclude_tags: [dos, fuzz]             # NOW ACTUALLY WIRED
    misconfig_tags: [default-login, misconfig, unauth, exposure, panel, debug, backup] # NEW
    network_scan: true                    # NEW — Pass C on naabu ports
    template_update_hours: 24             # NEW
    tech_tags_extra: {}                   # NEW — optional tech→tag overrides
    # unchanged: concurrency, rate_limit, disable_oob, max_timeout_min, dast_aggression
  dalfox:
    headless: auto                        # NEW — auto|on|off
    # unchanged: max_urls, skip_third_party, max_timeout_min
  sqlmap:                                 # NEW — whole block optional
    enabled: false
    max_urls: 25
    per_url_timeout_min: 3
vuln_intel:                               # NEW top-level section
  enabled: true
  epss: true
  kev: true
  cache_hours: 24
```

CLI: `--enable-sqlmap` (wild­card). No new skip flags needed for other passes (config-gated).

---

## 5. Implementation order & effort

| Batch | Tasks | Effort | Risk |
|-------|-------|--------|------|
| 1 | T1, T4-comment/label fixes, T2 | ~2 h | low — arg building + one cache helper |
| 2 | T5, T6, T3 | ~3 h | low — tag lists + errgroup |
| 3 | T4 (Pass C), T7, T8 | ~4 h | medium — verify `-pt`/fuzz flags vs installed nuclei; dalfox headless detection |
| 4 | T10, T11, T12 | ~5 h | medium — DB migration, external APIs, ROI math |
| 5 | T9 (sqlmap) | ~3 h | medium — output parsing, setup flow |
| 6 | T13, T14 | ~2 h | low |

## 6. Explicit non-goals

- No new scan steps / no renumbering (resume compatibility).
- No interactive triage UI, no screenshot pipeline.
- No replacement of nuclei/dalfox as the core engines.
- No docker-mode changes beyond the sqlmap registry note.
- No changes to company_flow vuln logic in this plan (separate pass later if wanted).

## 7. Risks / open questions

1. **nuclei flag drift** (`-pt` values, DAST fuzz placement flag, `-update-templates` behavior) — verify against the pinned tool version during Batch 3; keep flags behind small helpers so a wrong flag fails one pass, not the step.
2. **Pass C noise** — network templates on CDN-fronted ports can false-positive; severity stays config-bound, dedup via unique index, review after first real run.
3. **EPSS/KEV availability** — both endpoints are key-less but internet-dependent; enrichment must never fail the step (debug-log + continue).
4. **sqlmap runtime** — sequential × per-URL timeout can still be slow; keep default OFF and cap conservative.
5. **Migration** — must be idempotent across fresh and legacy DBs; test both paths.
