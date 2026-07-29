# Wildcard Flow — Issue Review & Remediation Plan

Review of `pkg/wildcard_flow/` (23-step, 6-phase domain recon workflow) covering
logical bugs, state-machine issues, scope/OPSEC gaps, performance traps, and
documentation drift. Findings are grouped by severity; each lists location,
description, impact, and remediation. A phased fix plan follows at the end.

---

## 1. Summary

| Severity | Count | Themes |
|---|---|---|
| High | 4 | Resume integrity (ghost scan rows, unvalidated state, lost proxy), stdin busy-loop |
| Medium | 6 | Scope bypass after merges, takeover coverage gap, unbounded metadata collection, nil-config derefs, flag/help mismatch, out-of-scope DB rows |
| Low | 9 | Logging/label inconsistencies, comment/step-number drift, dead constants, cancellation gaps, perf caps |

---

## 2. High-Severity Findings

### H1 — Resume creates a ghost "running" scan record (and misnames the log file)

- **Location:** `pkg/wildcard_flow/flow.go:339-346` (unconditional `database.CreateScan`) vs `flow.go:373-381` (resume branch); log filename at `flow.go:351-364`.
- **Bug:** `database.CreateScan(...)` runs *before* the resume check. On `--resume <id>` a brand-new scans row is inserted with `status='running'` (`pkg/database/database.go:296-318`), then `scanID` is overwritten with the resumed ID. The new row is never updated again → a permanent phantom "running" scan in `scans list`, polluting status/diff/report surfaces. Secondary: the `--log` filename embeds `scanID` and is generated *before* the resume override, so the log file is named after the ghost ID, not the resumed scan.
- **Impact:** DB data-integrity corruption on every resume; misleading log artifacts.
- **Remediation:** Skip `CreateScan` when `cfg.ResumeScanID > 0` (resume must reuse the original scans row). Move the file-logging init to after the scanID resume resolution.

### H2 — Resume state is not validated (target / result-dir mismatch)

- **Location:** `pkg/wildcard_flow/flow.go:373-388`.
- **Bug:** `stateMgr.LoadState(cfg.ResumeScanID)` is trusted blindly. There is no check that `scanState.Target == cfg.Domain` or that `scanState.ResultDir == cfg.ResultDir`. Resuming with a different `-d` (or a different `--output` base) silently skips "completed" steps while reading/writing mismatched directories and attaching new data to the old scan ID. The persisted `scanState.Config` (original skip flags, auto-proxy, wordlists) is also never reconciled with the current invocation.
- **Impact:** Silent cross-target data contamination; confusing "resumed" runs that produce data for the wrong target.
- **Remediation:** After `LoadState`, hard-fail on target mismatch; warn/fail on result-dir mismatch (or adopt `scanState.ResultDir`); compare persisted config and warn when flags differ materially.

### H3 — Resumed scan silently loses proxy rotation

- **Location:** `pkg/wildcard_flow/proxy_scraping.go:29-39` (`resumeOrSkip` early-return), `flow.go:426-429` (proxy wiring).
- **Bug:** A scan started with `--auto-proxy` marks `proxy_scraping` complete. On resume, step 1 is skipped, the mubeng rotator is never restarted, `c.Proxy` stays empty, and all remaining steps (httpx, nuclei, dalfox, crawlers) run direct from the operator's IP. The `c.Cfg.General.Proxy` mutation from the original run was runtime-only.
- **Impact:** Silent OPSEC regression — the rest of the scan runs unproxied while the user believes rotation is active.
- **Remediation:** On resume, read `auto_proxy` from `scanState.Config`; if set, re-run proxy setup (reuse `proxy_pool.txt` when still fresh instead of re-scraping) or loudly warn that the scan continues without proxy.

### H4 — stdin skip-listener busy-loops on EOF and never terminates

- **Location:** `pkg/wildcard_flow/flow.go:295-312`.
- **Bug:** `n, err := os.Stdin.Read(buf); if err != nil || n == 0 { continue }` — when stdin is closed/EOF (CI pipelines, redirected stdin, backgrounded process), `Read` returns `(0, io.EOF)` immediately and the loop spins forever, pinning one CPU core for the entire scan. The goroutine also has no exit path when the scan ends.
- **Impact:** 100% CPU burn on one core in non-interactive environments; goroutine leak.
- **Remediation:** `return` on any read error; `select` on `goCtx.Done()` alongside stdin reads.

---

## 3. Medium-Severity Findings

### M1 — Out-of-scope subdomains re-enter the pipeline after the step-7 scope filter

- **Location:** `pkg/wildcard_flow/validation.go:196-212` (shuffledns merge, step 8) and `validation.go:340-440` (TLS SAN merge, step 11; suffix-only check at line 378).
- **Bug:** Scope filtering (`ScopeFilter.IsInScope/IsOutOfScope`) runs once in step 7 (`validation.go:72-82`). Steps 8 and 11 later merge *new* subdomains into `ConsolidatedSubs` re-applying only the `*.<domain>` suffix check — never the scope filter. Out-of-scope brute-forced/SAN hosts flow into naabu, httpx, nuclei, and dalfox targets.
- **Impact:** Scanning/exploitation traffic hits out-of-scope assets — a rules-of-engagement violation.
- **Remediation:** Extract the scope filter into a helper (e.g. `c.filterSubsToScope(file)`) and re-apply it after every merge into `ConsolidatedSubs`/`HttpxLiveHosts`.

### M2 — Takeover detection misses brute-forced and SAN-discovered subdomains

- **Location:** `pkg/wildcard_flow/vulnerability_scanning.go:263-268` (`filterCNAMESubdomains` reads only `c.F.DnsxOut`).
- **Bug:** CNAME filtering uses `dnsx_resolved.json` from step 7. Subdomains discovered later — shuffledns (step 8) and TLS SANs (step 11) — are never in that file, so their CNAME records are never evaluated. A dangling CNAME on a brute-forced host is silently missed.
- **Impact:** False-negative on the highest-severity finding class (subdomain takeover).
- **Remediation:** Before takeover filtering, run a targeted dnsx CNAME query over the final `ConsolidatedSubs` (or capture CNAMEs during steps 8/11) so `takeover_candidates.txt` reflects the full attack surface.

### M3 — Metadata collection is unbounded; cap constants are dead code

- **Location:** `pkg/wildcard_flow/helpers.go:21-28` (`metadataHostCap = 250`, `paramDiscoveryCap = 150` — never referenced); `content_discovery.go:756` (`collectROIMetadataTargetsFromFile(..., 0, 0)` = no per-host or total limit); `validation.go:461-474` (all live hosts loaded, no cap); `pkg/metadata/collector.go:57,90` (no internal cap, ~5 req/s rate limit at lines 162-166).
- **Bug:** The URL-metadata path passes `0, 0` limits, so every high-value URL (potentially tens of thousands) is fetched at 5 req/s. Host metadata dedupes by host but is likewise uncapped. The caps that were clearly intended sit unused as constants.
- **Impact:** On large scopes the "lightweight metadata" phase alone can take hours; scan appears hung.
- **Remediation:** Wire `metadataHostCap` into the step-11 host-metadata call; pass explicit limits (e.g. per-host 5 / total 250) to `collectROIMetadataTargetsFromFile`; either use or delete `paramDiscoveryCap`.

### M4 — Unguarded `c.Cfg` dereferences in vulnerability steps (latent panic / zero-timeout trap)

- **Location:** `pkg/wildcard_flow/vulnerability_scanning.go:74, 111` (`c.Cfg.Tools.Nuclei.MaxTimeout`) and `:360` (`c.Cfg.Tools.Dalfox.MaxTimeout`).
- **Bug:** The rest of the package nil-guards `c.Cfg` (e.g. `flow.go:422,427,444`, `proxy_scraping.go:74`); these three sites dereference directly. Additionally, a user config with `max_timeout_min: 0` produces `context.WithTimeout(ctx, 0)` — an instantly-expired context that makes nuclei/dalfox "time out" immediately with a confusing message.
- **Impact:** Panic for embedded/test callers with nil config; broken scans with a zeroed timeout key.
- **Remediation:** Nil-guard like the rest of the package and clamp timeouts to the documented defaults when `<= 0`.

### M5 — `--skip-nuclei` help claims it skips takeovers; it doesn't

- **Location:** `cli/wildcard.go:105` ("Skip vulnerability scanning (Nuclei infra/URLs/takeovers)") vs `pkg/wildcard_flow/vulnerability_scanning.go:257` (step 19 checks only `SkipTakeovers`).
- **Bug:** Users passing `--skip-nuclei` still get the nuclei takeover run (and nuclei WAF detection in step 23, gated only by `--skip-fingerprint`).
- **Impact:** Flag/behavior mismatch; unexpected active nuclei traffic.
- **Remediation:** Either gate step 19 on `SkipNuclei || SkipTakeovers` (and note WAF under `--skip-fingerprint`), or correct the help text.

### M6 — Out-of-scope subdomains persisted to the DB during Phase 1

- **Location:** `pkg/wildcard_flow/asset_discovery.go:103-106, 167-168, 223-224, 275-276, 331-332` (ingest during steps 2-6) vs the scope filter that only runs later on the consolidated file (`validation.go:72-82`).
- **Bug:** `ingest.ParseSubdomainsFile` filters only by target-domain suffix (`pkg/ingest/parser.go:119-139`), not the user's scope config. Out-of-scope subdomains are inserted in Phase 1 and never removed; step 7 filters only the *file*. `query subdomains`, ROI ranking, and reports then include out-of-scope assets.
- **Impact:** Scope leak into every DB-backed product surface.
- **Remediation:** Thread `ScopeFilter` into ingest (or filter files before `Parse*` calls), and/or delete out-of-scope rows for the scan after step 7.

---

## 4. Low-Severity Findings

- **L1 — Fallback mislabeling on httpx failure:** `content_discovery.go:728-751` — when URL live-check *fails* (not user-skip), raw URLs are copied to `AllURLsLive` and stored with **no** "(from fallback)" label (label only set when `urlCheckSkipped`). Unvalidated URLs are presented as "live".
- **L2 — Step-number drift in section banners:** `content_discovery.go` headers say 11/12/13/14/15/16/17 but the steps are 12/13/14/16/17/18/15 (lines 44, 149, 266, 459, 674, 772, 1342); `vulnerability_scanning.go` banners say 18/19/20/21 but are steps 20/21/19/22 (lines 33, 155, 244, 325); `validation.go:49` comment says "Step 4" for uncover output (step 5). The same files also still reference "Arjun" though the tool is x8, and `.agents/skills/chaathan-recon-workflows/SKILL.md` documents a non-existent `--skip-arjun` flag.
- **L3 — Misleading GitHub token hint:** `asset_discovery.go:199` says "Set GITHUB_TOKEN env var or use --github-token", but the env var is intentionally never read (`cli/wildcard.go:146`; `pkg/tools/tools.go:909-916` requires `-t`). Message should point to the config API key or the flag.
- **L4 — Inconsistent completion helpers:** `stepURLDiscovery`/`stepWebCrawling` use `markStepCompleteSafe` while other steps use `markStepCompleteIfNoFailure` (`content_discovery.go:142, 259`). Harmless today (failure is only marked in the else-branch) but violates the single-pattern rule in AGENTS.md §6.
- **L5 — Skip-with-3s-timeout may leak a running tool:** `helpers.go:118-127` — if a tool ignores ctx cancellation, `runWithSkip` proceeds after 3s while the goroutine/process may still write to shared output files consumed by the next step. Verify `pkg/runner` kills the process group on ctx cancel; otherwise track and reap at `finalizeScan`.
- **L6 — Takeover validator DNS lookup ignores ctx:** `vulnerability_scanning.go:555` uses `net.LookupCNAME(host)` (no context). Cancellation stalls up to the DNS timeout mid-validation-loop. Use `(&net.Resolver{}).LookupCNAME(ctx, host)`.
- **L7 — No early-exit on empty consolidation:** `validation.go:67+` — when Phase 1 yields 0 subdomains, all remaining steps still execute against empty inputs. The `Required: true` flag on `dns_resolution`/`http_probing` (`pkg/scan/scan.go:66,69`) has no enforcement. Add a guard that aborts (or loudly warns and skips dependent phases) when consolidation is empty.
- **L8 — JS-analysis cap applied before port filtering:** `content_discovery.go:371-377` — `loadLineSlice(..., jsAnalysisHostCap)` takes the first 1000 live hosts, then `filterAndDeduplicateHosts` drops non-80/443 entries, so the effective coverage can be far below 1000. Filter first, then cap.
- **L9 — `js_limit: 0` unbounded memory:** `content_discovery.go:1258-1270` + `:1010` — JS URLs are fully materialized (slice + buffered channel). Default 2000 is safe; an explicit 0 in config removes the bound. Clamp or document.

---

## 5. Remediation Plan (Phased)

### Phase 1 — Correctness & Data Integrity (H1, H2, H4, M4)
1. `flow.go`: skip `database.CreateScan` on resume; resolve final `scanID` *before* log-file init.
2. `flow.go`: validate resumed state (`Target`, `ResultDir`) and reconcile against persisted `scanState.Config`.
3. `flow.go`: fix stdin goroutine (return on error, exit on ctx done).
4. `vulnerability_scanning.go`: nil-guard `c.Cfg` and clamp `MaxTimeout <= 0` to defaults (mirror `tools.ffufMaxTimeout()` pattern).
5. Tests: resume-unit test asserting no new scans row; state-mismatch rejection test; zero-timeout clamp test.

### Phase 2 — Scope & OPSEC (M1, M2, M5, M6, H3)
1. Add `c.filterSubsToScope(path)` helper; call after shuffledns merge (step 8) and SAN merge (step 11).
2. Refresh CNAME data for the full consolidated list before takeover filtering (step 19).
3. Gate takeover step on `SkipNuclei || SkipTakeovers` (or fix help text — decide behavior first).
4. Apply scope filtering at ingest time (or post-step-7 DB cleanup) so out-of-scope rows never reach query/report surfaces.
5. Restore proxy on resume: detect `auto_proxy` in persisted config; restart rotator from `proxy_pool.txt` or warn explicitly.

### Phase 3 — Performance & Robustness (M3, L5, L6, L7, L8, L9)
1. Wire `metadataHostCap` into step 11; pass explicit per-host/total limits in step 17 URL-metadata call; remove or use `paramDiscoveryCap`.
2. Verify runner process-group kill on cancel; otherwise reap leaked tools at finalize.
3. Context-aware DNS lookup in takeover validation.
4. Empty-consolidation guard after step 7.
5. Filter 80/443 before applying the 1000-host JS-analysis cap; clamp `js_limit <= 0`.

### Phase 4 — Consistency & Documentation (L1, L2, L3, L4)
1. "(from fallback)" label on both skip and failure paths in `url_consolidation`.
2. Fix all step-number banners and Arjun→x8 references; sync `SKILL.md` (remove `--skip-arjun`, correct step indices) and root `README.md` per the Documentation Sync meta-rule.
3. Correct the GitHub-token hint message.
4. Standardize on `markStepCompleteIfNoFailure` at every step exit.

---

## 6. Verification

Per AGENTS.md baseline (via WSL on Windows):

```bash
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && gofmt -w ."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && golangci-lint run ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go build -buildvcs=false -o chaathan ."
```

Behavioral checks after the fix phases:
- `scans list` shows no new "running" row after `--resume`; resume with mismatched `-d` fails fast.
- With `--auto-proxy`, interrupt mid-scan and resume: rotator restarts (or an explicit no-proxy warning prints).
- Scope config excluding `dev.*`: confirm excluded brute-forced/SAN hosts never appear in httpx input, nuclei targets, or `query subdomains`.
- Takeover run covers a dangling-CNAME host discovered only via shuffledns.
- Large-URL fixture: metadata phase bounded by the configured caps.
- `./chaathan wildcard --help` text matches actual skip-flag behavior.

---

## 7. Notes / Non-issues (checked, intentionally not planned)

- ffuf per-host timeout uses `Ffuf.MaxTimeout` per host run (up to 1000 hosts sequentially) — a known design cost; revisit only if a global step-15 time budget is desired.
- `collectLiveHostTargetsFromHttpx` re-derives `HttpxLiveHosts` from `HttpxOut` in later steps; SAN results are appended to `HttpxOut`, so re-derivation is consistent — no data loss.
- `MarkStepComplete` clearing prior failure records for the step is relied upon by skip-paths; behavior is intentional (`pkg/scan/scan.go:167-187`).
- Failed (non-completed) steps re-run on resume — intended resume semantics.
