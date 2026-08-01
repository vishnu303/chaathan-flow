# Wildcard Flow Command Audit & Optimization Plan

Audit of every external command in the 21-step wildcard flow against current tool
capabilities, focusing on **result coverage** (do we get the most possible good
results?). All tool flags below were verified against current upstream docs.

Verdict legend: ✅ good as-is · ⚠️ good but could yield more · ❌ gap

---

## Step-by-step audit

| Step | Command (current flags) | Verdict | Gaps |
|---|---|---|---|
| 1. Proxy scraping | mubeng + proxy-scraper-checker (config-driven) | ✅ | — |
| 2. Passive enum | subfinder `-silent -t 30 -timeout 30` | ⚠️ | `-all` missing → only ~15 default sources used, API keys injected via env are never leveraged |
| 2. Passive enum | assetfinder `--subs-only` | ✅ | — |
| 2. Passive enum | sublist3r `-d -t 50 -v` | ✅ | — |
| 3. Active enum | amass `enum -active -alts` | ✅ | Project archived (2024); still functional but frozen |
| 4. GitHub recon | github-subdomains `-d -t -o` | ✅ | — |
| 5. Search engines | uncover `-q -json -e <engines>` | ✅ | — |
| 6. DNS resolution | dnsx `-a -aaaa -cname -mx -txt -resp -json -timeout 3 -retry 2` | ⚠️ | **No wildcard filtering** — wildcard DNS domains pollute resolved host lists with hundreds of garbage hosts that later get httpx-probed and DB-persisted |
| 7. DNS brute-force | shuffledns `-d -w -o -silent -mode bruteforce` | ⚠️ | **No `-sw` strict wildcard check**; default wordlist `subdomains-top1million-5000.txt` is small (5k words) |
| 8. Port scanning | naabu `-rate 1000 -c 25 -timeout 3 -top-ports 1000` | ⚠️ | `-passive` (Shodan/Censys port enrichment) not used; top-1000 only (fine as default) |
| 9. HTTP probing | httpx `-ports ... -tech-detect -title -status-code -json` | ⚠️ | No `-ip -cname -asn -cdn` metadata → DB/ROI lacks IP/ASN/CDN signals |
| 10. TLS analysis | tlsx `-json -silent -nc -duc -c 50` | ✅ | — |
| 11. URL discovery | waybackurls, gau `--providers wayback,commoncrawl,otx,urlscan --subs` | ✅ | — |
| 12. Web crawling | katana `-jc -timeout 15` (depth default 3) | ⚠️ | No `-jsluice` (native JS endpoint extraction), no `-kf` (robots.txt + sitemap.xml), depth not configurable |
| 12. Web crawling | gospider `-q -c 10 -d 3 -t 10` | ⚠️ | No sitemap fetch (`-s`), no linkfinder (`-k`) |
| 13. JS deep analysis | in-process jsluice + secrets + source maps | ⚠️ | Source map URL hardcoded as `jsURL + ".map"` (ignores inline `//# sourceMappingURL=`); JS URLs from ffuf/x8 outputs never analyzed; secret pattern set could be broader |
| 14. Dir fuzzing | ffuf `-mc 200,201,204,301,302,307,401,403,405,500 -of json -t 50` | ⚠️ | No `-ac` auto-calibration → mass false positives on hosts that return the same status for every path; wordlist `common.txt` (4.7k words) is minimal |
| 15. Param discovery | x8 `-O json -w <params> -H ... -x proxy` | ✅ | — |
| 16. URL consolidation | httpx URL check `-no-fallback` | ✅ | — |
| 17. Takeover detection | dnsx CNAME refresh + nuclei `-tags takeover` + live validation | ✅ | — |
| 18. Infra vuln scan | nuclei `-as` (smart-cve) + `-tags default-login,misconfig,unauth` | ⚠️ | `severity` config is dead code (hardcoded fallback wins); OOB/interactsh disabled by default (no blind SSRF/RCE detection) |
| 19. DAST | nuclei `-dast -fa high` | ✅ | — |
| 20. XSS | dalfox file mode `--worker 20 --timeout 10` | ✅ | — |
| 21. Fingerprinting | httpx `-tech-detect` + nuclei `-tags waf` | ✅ | — |

---

## Prioritized improvements

### P1 — Highest impact, low effort (pure flag additions)

**1. DNS wildcard filtering (Steps 6 + 7)** — the single biggest result-quality win.
Wildcard DNS (`*.example.com` → same IP) currently floods Step 6 output with
garbage hosts that propagate to httpx, DB, and every downstream scan.

- `pkg/tools/tools.go` `RunDnsx`: add `-auto-wildcard` (auto-detects wildcard roots,
  works with `-l` list input, preserves JSON output).
- `pkg/tools/tools.go` `RunShuffleDNS`: add `-sw` (strict wildcard check on all
  found subdomains). Requires massdns resolvers — already the intended path.
- Risk: minimal. Effect: fewer, accurate resolved hosts.

**2. Katana coverage (Step 12)** — `pkg/tools/tools.go` `RunKatana`:
- Add `-kf robotstxt,sitemapxml` (crawl robots.txt + sitemap.xml; needs depth ≥ 3,
  current default is 3 ✅).
- Add `-jsluice` (native JS URL/endpoint extraction while crawling — feeds both
  Step 12 output and Step 13 JS collection). Caveat: memory-intensive on huge
  crawls → make it config-driven (`tools.katana.jsluice`, default true) so users
  can disable.
- Make depth configurable (`tools.katana.depth`, default 3, allow 5).

**3. ffuf auto-calibration (Step 14)** — `buildFfufArgs`: add `-ac` (ffuf sends a
baseline request per host and auto-excludes content-lengths that match it). Kills
the classic "every path returns 200" false-positive storm. Config flag to disable
if the target's dynamic pages break calibration.

**4. subfinder `-all` (Step 2)** — `RunSubfinder`: add `-all` so the API keys
already injected via env vars (`VT_API_KEY`, `PDCP_API_KEY`, `SHODAN_API_KEY`,
`SECURITYTRAILS_API_KEY`) are actually used, unlocking chaos/virustotal/shodan/
securitytrails/netlas/robtex/etc. sources. Cost: slower step 2, more results.

### P2 — Meaningful gains, small code changes

**5. gospider sitemap + linkfinder (Step 12)** — `RunGoSpider`: add `-s` (fetch
sitemap.xml) and `-k` (linkfinder on JS files). Both feed the URL pipeline.

**6. Source map inline URL (Step 13)** — `js_deep_analysis.go` `fetchSourceMap`:
parse `//# sourceMappingURL=<url>` (and `/*# sourceMappingURL= */`) from the JS
body first; fall back to `jsURL + ".map"` only when absent.

**7. Analyze JS from ffuf/x8 outputs (Step 13)** — add `c.F.FfufDiscoveredURLs`
and `c.F.X8URLsOut` to the `crawlerFiles` list in `stepJSDeepAnalysis` so JS files
found by fuzzing/param discovery are also deep-analyzed.

**8. Broaden JS secret patterns (Step 13)** — `jsSecretPatterns`: add Azure
storage keys, npm tokens, SendGrid/Twilio/Mailgun keys, Slack bot tokens
(`xoxb-`), Discord webhooks/bot tokens, Telegram bot tokens, OpenAI/Anthropic
keys, GCP service-account JSON markers.

**9. Wire nuclei severity config (Step 18)** — fix A1 from `VULN_SCANNING_PLAN.md`:
pass `t.nucleiSeverity()` into `ScanOptions.Severity` (and map default severity
list per mode) so `nuclei.severity` in config.yaml actually works. Optionally add
`medium` to Pass A.

**10. Optional OOB detection (Steps 18–19)** — flip `DisableOOB` from
config-only to also accept `--enable-oob` CLI flag → removes `-no-interactsh`,
enabling blind SSRF/RCE detection via interactsh. Default stays off (no external
callback infra needed).

**11. Naabu passive enrichment (Step 8)** — add `-passive` (requires Shodan/
Censys keys via env, same mechanism as uncover). Adds open ports from historical
scan data at zero packet cost. Config-driven (`tools.naabu.passive`, default off
when no keys).

**12. httpx metadata (Steps 9 + 16)** — add `-ip -cname -asn -cdn` to
`RunHttpx` so JSON output (and DB metadata/ROI) gains IP/CNAME/ASN/CDN signals.
JSON schema of existing parsers unchanged (additive fields only).

**13. Bigger default DNS wordlist (Step 7)** — bump auto-detected wordlist from
`subdomains-top1million-5000.txt` to `subdomains-top1million-20000.txt` when
present on device; keep `--dns-wordlist` override.

### P3 — Nice-to-haves / config defaults

**14. ffuf wordlist default** — prefer `directory-list-2.3-medium.txt` over
`common.txt` when both exist (more paths found; slower). Config override stays.

**15. Amass replacement note** — OWASP Amass is archived. Keep current behavior
(works), but consider swapping `-active` pass for `puredns` brute-force with
permutations (dnsgen) in a future cycle if amass output degrades.

**16. collectHighSignalEndpoints keywords (Step 15)** — add `/graphql`,
`/socket`, `/oauth`, `/token`, `/session`, `/profile`, `/account`, `/cart`,
`/checkout`, `/invoice`, `/webhook` to the x8 target selection.

**17. dalfox redirects** — make `--follow-redirects` config-driven (off by
default; some reflected-XSS chains live behind redirects).

---

## Implementation order

1. P1 items 1–4 (pure flag/config changes in `pkg/tools/tools.go` + config) — one PR.
2. P2 items 5–9 (crawler/JS/secret improvements) — second PR.
3. P2 items 10–13 (OOB opt-in, naabu passive, httpx metadata, wordlist bump) — third PR.
4. P3 items 14–17 (defaults & tuning) — as time permits.

## Verification per change

- `go build -buildvcs=false -o chaathan .` && `go test ./...`
- Extend `test/pkg/tools/tools_test.go` argument-assertion tests for new flags
  (pattern: `TestScannerRunsUseNoRetry`).
- `golangci-lint run ./...` when available (env currently lacks it).
- Update `README.md` + `.agents/skills/chaathan-recon-workflows/SKILL.md` when
  flags/config keys change (meta-rule).
