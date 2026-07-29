# Wildcard Flow Improvement Plan — Automation & Bug-Finding ROI

**Scope:** `pkg/wildcard_flow/` (23-step Wildcard Reconnaissance Workflow) + closely-coupled helpers in `pkg/scan`, `pkg/tools`, `pkg/metadata`, `cli/wildcard.go`.
**Goal:** Make `chaathan wildcard -d target.com` produce **verified, exploitable findings with zero required flags** and **no silent no-ops** by default; expose every heavyweight phase behind an opt-*out* (not opt-in) flag.
**Audience:** Maintainer + agents (matches the AGENTS.md "thin CLI, thick packages" rule).
**Status:** Proposal only — no code modified.

---

## 0. Diagnosis — why today's flow misses bugs

The 23-step pipeline has solid recon but loses bugs at three predictable failure points. Every item below maps to fixing one of them.

| # | Failure point (today) | Concrete evidence |
|---|---|---|
| D1 | **OOB disabled by default** | `pkg/config/config.go:460` sets `DisableOOB: newBool(true)`. `pkg/tools/vulnerability_engine.go:61` emits `-no-interactsh`. Blind SSRF/XXE/SSTI/log4shell-blind/OOB-SQLi are **silent no-ops** — the user sees no error, no warning, no finding. |
| D2 | **Optional-but-needed tools skip silently when no flag is passed** | `stepDirFuzzing` skips unless `--wordlist` is set (and its only `Required=false`). `stepDNSBruteforce` skips unless `--dns-wordlist` is passed. `x8` only runs with a wordlist. Default `chaathan wildcard -d target.com` runs no content fuzzing and no DNS brute-forcing. The user thinks they got a "full" scan. |
| D3 | **Vuln phase is detection-only with one tool per bug class** | `stepVulnScanningInfra` = Nuclei `-as` + misconfig. `stepVulnScanningURLs` = Nuclei DAST. `stepXSSScanning` = Dalfox only. No CORS verification, no JWT analysis, no GraphQL introspection, no OpenAPI-driven fuzzing, no prototype pollution, no cache poisoning, no host-header injection, no S3-bucket takeover, no HTTP method abuse, no blind param probing, no CVE→CPE enrichment. |
| D4 | **JS secret scan is shallow** | `stepJSSecretScan` runs `gf`-patterns over `JS_URLsFile`, but the URLs come from `katana`/`gospider`. Many high-value JS files never appear in crawl output (login-only, post-render, lazy-loaded). The flow never *downloads* JS bodies at scale and scans them with secret/PII regexes. |
| D5 | **Takeover signature list is stale** | `ValidateTakeoverCandidate` (`pkg/wildcard_flow/vulnerability_scanning.go:594`) has 11 hardcoded signatures and 9 CNAME fingerprints. `can-i-take-over-xyz` lists ~50+ active services with rotating signatures. Takeover coverage is much narrower than the user realises. |
| D6 | **No automation chain between steps** | Each step emits a `.txt` and the next reads it — but no auto wordlist bundling, no per-host scaling, no per-host cooldown, no auto-resume of just-failed steps, no SPI/DAST/CORS hand-off from one finding to a deeper probe. |
| D7 | **Top-1000 ports by default misses bounty-class infra ports** | `naabu` defaults to top-1000 (`pkg/tools/tools.go:362`). Docker 2375/2376, etcd 2379/2380, k8s/kubelet 6443/10250/10255, registry 5000/5001, Elastic 9200/9300, Memcached 11211, RDP-with-weak-cipher-not-in-top-1000 — all skipped by default. |
| D8 | **Passive enum misses free sources already plumbed** | `APIKeys.SecurityTrails` exists in config (`pkg/config/config.go:102`) and is read by `GetAPIKey`, but no flow step queries it. The flow has no `crt.sh`/CT-log pull, no `AlienVault OTX`, no `Anubis`, no `Hackertarget`, no `DNSdumpster`. Subfinder covers most but not all of these for every program. |

Each theme below fixes ≥1 of D1-D8.

---

## 1. Themes (each = one or more PRs, all of which pass `wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./... && go vet ./... && go build -buildvcs=false -o chaathan ."`)

| Theme | Diagnosis fixed | Outcome |
|-------|-----------------|---------|
| Tx.1 — **Zero-flag defaults** | D2 | `chaathan wildcard -d target.com` runs fuzzing, DNS brute, x8 by default using bundled wordlists (or auto-fetched seclists). |
| Tx.2 — **Verify-and-strip every vuln step** | D3, D5 | Replace detection-only output with FP-stripped, CVE-enriched verified findings (same pattern as `ValidateTakeoversFile`). |
| Tx.3 — **Modern bug-class coverage** | D3, D7 | Add steps for GraphQL, OpenAPI/gRPC, WebSocket, JWT, CORS, host-header, cache-poisoning, prototype pollution, blind param probe, container/K8s infra exposure. |
| Tx.4 — **Blind-class enablement via self-hosted collaborator** | D1 | Replace `-no-interactsh` with a Chaathan-managed OOB listener; blind SSRF/XXE fire by default. |
| Tx.5 — **Deep JS recon & secret mining** | D4 | Download JS bodies in batch, regex for secrets/PII/tokens, parse them with `linkfinder`-equivalent, and feed discovered URLs *back* into the crawl+vuln loops. Loop once. |
| Tx.6 — **Automation chains & adaptive execution** | D6 | Auto-resume failed steps, per-host cooldown, scope-based parallelism, deep-recurse ffuf on discovered dirs. |
| Tx.7 — **Recon depth via modern free sources** | D8 | Add `crt.sh`, `SecurityTrails` (already-keyed), `AlienVault OTX`, `Anubis`, `Hackertarget`, `DNSdumpster` as parallel passive enums. |

Roadmap at the end fuses these themes into the existing 6-phase structure (no phase removed, only *inserted* and *strengthened*).

---

## 2. Concrete work units

Each item below lists: **why**, **what changes conceptually**, **files touched**, **validation**, and **risk**.

---

### 2.1 Tx.1 — Zero-flag defaults (fix D2)

The single biggest UX → bug-finding win. Today the user *must* pass `--wordlist` / `--dns-wordlist` / `--params` to enable content discovery, DNS brute, and hidden-param fuzzing. **Defaults should make a scan deep by default.**

#### 2.1.1 Auto-bundle mini-wordlists; flip ffuf/shuffledns/x8 defaults

**Why.** `stepDirFuzzing` (`pkg/wildcard_flow/content_discovery.go:1346`) returns `markStepCompleteSafe` when `c.WordlistPath == ""` — silently skipping directory enumeration entirely. `stepDNSBruteforce` (validation.go:139) and `stepParamDiscovery` (content_discovery.go:466) behave the same.

**What.**
1. Ship three small wordlists inside the binary via `embed.FS` at `pkg/wordlists/data/`:
   - `directories-mini.txt` (~400 curated entries — common admin/api/static dirs, not common.txt's 4.6k)
   - `dns-mini.txt` (~1k common subdomain prefixes)
   - `params-mini.txt` (~120 interesting param names)
2. The flow's `newFiles()` writes them to `intermediate_files/wordlists/` on first run.
3. `stepDirFuzzing` uses the CLI `--wordlist` if provided → else `cfg.General.Wordlists.Directories` if file exists → else the bundled mini.
4. Same for DNS wordlist and x8 param wordlist.
5. Add a `--shallow` shorthand flag that disables all three heavy optional steps together (`--shallow = --skip-dalfox --skip-nuclei --skip-naabu --skip-x8 --skip-dir-fuzz`). Replaces the current `chaathan wildcard -d t.com --skip-amass --skip-naabu --skip-nuclei` shortcut pattern in the README.

**Files.**
- New `pkg/wordlists/wordlists.go` (one helper, embed accessors).
- New `pkg/wordlists/data/*.txt`.
- `pkg/wildcard_flow/flow.go:147 newFiles()` (write wordlists to disk on first scan).
- `pkg/wildcard_flow/content_discovery.go:stepDirFuzzing`, `stepParamDiscovery`.
- `pkg/wildcard_flow/validation.go:stepDNSBruteforce`.
- `cli/wildcard.go` (add `--shallow`, default wordlist resolution).
- `pkg/scan/scan.go:WildcardSteps` (rename `dir_fuzzing` note from "requires --wordlist" to "default-on").

**Validation.** `chaathan wildcard -d example.test --skip-passive` against a local DVWA / juice-shop style target → expect ffuf to discover `/admin` and `/login`, x8 to discover `debug`, shuffledns to find at least one common prefix. Test: existing `--wordlist` flag still wins.

**Risk.** Wordlist size/memory; bundle size. Mini lists keep binary +50 KB. Acceptable.

---

#### 2.1.2 Auto-`httpx -asm` favicon + 404 baseline

**Why.** When the flow later runs `ffuf` blindly against a live host, it can't distinguish real 404/500 random responses from real content. Today `ffufMatchCodes` is hardcoded to `{200,201,204,301,302,307,401,403,405,500}` (`pkg/config/config.go:478`). On a wildcard-404 host every URL returns 200 with size 1234 — ffuf will report noise.

**What.** Before `stepDirFuzzing`, for each live host, request `/<random-40-chars>` and capture `(status, content_length, server_header, body_hash)`. Store as the host's "404 baseline". Pass to `ffuf` via `-fc <baseline_status>` and `-fs <baseline_size>` so it auto-filters soft-404s. Persist in DB for the host (`host_metadata.soft404_status`, `soft404_size`).

**Files.** `pkg/metadata/collector.go` (extend), `pkg/wildcard_flow/content_discovery.go:stepDirFuzzing` (use baseline when building ffuf args), `pkg/tools/tools.go:buildFfufArgs` (accept filters), `pkg/database/database.go` (schema migration for `host_metadata` columns).

**Validation.** Soft-404 target → ffuf output decreases by ≥80%; real finding count unchanged.

**Risk.** One extra HTTP request per live host. Negligible.

---

### 2.2 Tx.2 — Verify-and-strip every vuln step (fix D3, D5)

Pattern already exists in the codebase (`ValidateTakeoversFile` / `ValidateTakeoverCandidate` in `vulnerability_scanning.go:483-631`): read scanner JSONL → for each row, do a live re-fetch and re-check → rewrite the file with only verified findings → notify only verified ones. Today this exists for one step. **Generalise it.**

#### 2.2.1 Generalised verifier framework

**What.** New `pkg/wildcard_flow/verifiers.go` exposing:
```go
type Verifier func(row map[string]any, probe ProbeClient) (keep bool, evidence string)

func VerifyJSONL(findingsFile string, v Verifier, proxy string) (kept int, dropped int, err error)
```
- Reads JSONL findings, runs each through `v`, rewrites the file with the survivors, persists evidence in DB.
- Used by takeover (existing logic refactored to fit), CORS, SSRF, JWT, S3, GraphQL-introspection, prototype-pollution.
- A failed verifier logs to `intermediate_files/verifications.log` so the user can audit what was dropped.

**Files.** `pkg/wildcard_flow/verifiers.go` (new), refactor `vulnerability_scanning.go:483-631` to use it.

**Risk.** Low — pure refactor plus extraction.

---

#### 2.2.2 CVE → CPE enrichment beyond Nuclei

**Why.** `RunNucleiSmartCVE` uses Nuclei's `-as` which only fires if PD ship a curated template. NVD has ~250k CVEs; many of the year's high-payout BB findings are CVEs awaiting a Nuclei template.

**What.** After `httpx_tech.json`, parse `tech[]` + version strings; for each `(cpe, version)` pair, query NVD 2.0 API:
- Free tier: 50 req / 30 min (good for ad-hoc), `api_keys.nvd` optional for higher quota.
- Filter CVEs by CVSS ≥7.0 and `exploitabilityScore >= 7`.
- Insert into `vulnerabilities` table with `source='nvd-cpe'`, `template_id='CVE-YYYY-NNNNN'`, deduped against any Nuclei-firing of the same CVE.

**Files.** New `pkg/vulnint/nvd.go`, new `pkg/wildcard_flow/vulnerability_scanning.go:stepNVDEnrich` (insert after `stepVulnScanningInfra`), `pkg/config/config.go` (extend `APIKeys` with `NVD string`), `cli/config.go` (`config set api_keys.nvd <key>`).

**Validation.** Run against a host running nginx 1.17.0 (CVE-2019-9511) → expect the CVE row in DB even though no Nuclei template fires.

**Risk.** NVD rate limit; mitigated by in-memory cache + backoff. No PII.

---

#### 2.2.3 Auto-merge Nuclei tags from detected tech

**Why.** Nuclei modes in `pkg/tools/vulnerability_engine.go:97-134` set tag lists manually per mode. Tech from `httpx_tech.json` is parsed into DB but never fed back to Nuclei.

**What.** After `stepHTTPProbing`, write a `nuclei-tech-tags.txt` (one tag per detected technology) per scan to `intermediate_files/`. Pass via `-tags` to `RunNucleiSmartCVE` so it picks up templates for *detected* tech (e.g. only Joomla templates when Joomla seen, etc.) — narrows template count, raises hit rate, lowers noise.

**Files.** `pkg/wildcard_flow/vulnerability_scanning.go:stepVulnScanningInfra`, `pkg/tools/vulnerability_engine.go:nucleiModes` (allow runtime tag injection).

**Risk.** Two passes against the same hosts (marginally slower). Mitigation: gated by `cfg.Tools.Nuclei.TechTargeted` (default true).

---

### 2.3 Tx.3 — Modern bug-class coverage (fix D3, D7)

Each new step is opt-out via `--skip-*` (flip default behaviour: on by default unless skipped).

#### 2.3.1 GraphQL discovery + abuse (new Phase 3 step after `stepJSAnalysis`)

**Why.** GraphQL recon absent. GraphQL has high BB ROI: introspection, batch queries, field suggestions, alias-DoS, SSRF via `request`-type fields, IDOR via `node(id:)`.

**Plan.**
- New file `pkg/wildcard_flow/graphql.go` with `stepGraphQLRecon(c *Ctx) bool`.
- Probes live hosts against candidate paths: `/graphql`, `/v1/graphql`, `/v2/graphql`, `/api/graphql`, `/gql`, `/query`, `/_next/data/<build>/<page>.json`, `/console`.
- Sends introspection query (POST + GET) for each. Captures: introspection-enabled, suggestion-enabled, mutation-over-GET enabled.
- Runs `graphql-cop` (`github.com/dolevf/graphql-cop`) on confirmed endpoints for deeper checks (depth-limit, cost-analysis, batch, suggestions).
- Verifier: replicate introspection once and rewrite the file to only real endpoints (skip 200-but-no-GraphQL). Persist as a new `graphql_endpoints` table.
- New `--skip-graphql` flag.

**Files.** `pkg/wildcard_flow/graphql.go` (new), `pkg/wildcard_flow/flow.go` (register step), `pkg/scan/scan.go:WildcardSteps` (add `graphql_recon` def), `pkg/tools/registry.go` (`graphql-cop`), `pkg/tools/tools.go` (`RunGraphQLCop`), `pkg/database/database.go` (`graphql_endpoints` table migration), `cli/wildcard.go` (`--skip-graphql`).

**Validation.** Run against `https://rickandmortyapi.com/graphql` (safe) — expect row in `graphql_endpoints` with `introspection=true`.

---

#### 2.3.2 OpenAPI / Swagger spec ingestion (new Phase 3 step)

**Why.** Crawler misses spec files; GraphQL/REST specs are gold because they enumerate method/parameter pairs the rest of the flow has to guess.

**Plan.** New `stepSpecExtraction` after `stepJSAnalysis`.
- Scan `all_urls_live.txt` for `*.json` / `*.yaml` matching `openapi`/`swagger`/`paths:` patterns.
- Parse with `github.com/getkin/kin-openapi`.
- For each operation+parameter combination, write a row to the `endpoints` table with `source='openapi'`.
- Append synthesised parameterised URLs to `ParamURLsFile` so downstream DAST/Dalfox/blind-param tests get spec-driven inputs.
- Persist `spec_files` table for direct inspection.

**Files.** `pkg/specparser/openapi.go`, `pkg/wildcard_flow/spec_recon.go`, `pkg/database/database.go` (new tables), `pkg/scan/scan.go:WildcardSteps` (`spec_extraction`), `cli/wildcard.go` (`--skip-specs`).

---

#### 2.3.3 WebSocket probing (new Phase 3 step)

**Why.** `ws://`/`wss://` endpoints are silent. CSWSH (cross-site WebSocket hijacking) is recurring BB.

**Plan.** New `pkg/probes/websocket/probe.go` using `github.com/gorilla/websocket`.
- From `GoLinkFinderOut` + `katana` results, extract `new WebSocket("…")` literal URLs.
- For each, with the `--cookie` session: probe (a) cross-origin (`Origin: https://evil.com` accepted by reflected-by-default server), (b) reachability without `Auth` header, (c) advisory JSON message round-trip.
- Persist `websocket_endpoints` table.

**Files.** `pkg/probes/websocket/probe.go`, `pkg/wildcard_flow/websocket.go` (`stepWebSocketProbe`), `pkg/database/database.go`, `pkg/scan/scan.go:WildcardSteps` (`websocket_probe`), `cli/wildcard.go` (`--skip-websocket`).

---

#### 2.3.4 JWT analysis suite (new Phase 4 step)

**Why.** Alg=none, HS256 vs RS256 confusion, kid path traversal, weak-secret acceptance, replay-with-shifted-exp — all consistent BB payouts, all invisible today.

**Plan.** New `pkg/probes/jwt/jwt.go`:
- Pull JWTs from `--cookie`/`--header` user input AND from any `Authorization: Bearer <token>` in `katana`/`gospider` JS we already have.
- Decode (without verifying) → store (alg, kid, exp).
- Replay tests against previously observed URLs:
  1. `alg=none` — strip signature, replay; compare response body hash.
  2. **HS256 confusion** — pull RSA public key from `/.well-known/jwks.json`; use it as HMAC secret; replay.
  3. `kid` path traversal — set `kid:` to `../../../../dev/null`, `../../../../etc/hosts`.
  4. Weak secret brute: top 5000 from `sec-lists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt` (cut to top 5000) using `golang-jwt/jwt/v5`.
  5. `exp` shift — set `exp=now+99 years`; replay.
- Persist `jwt_findings` table, `Type: jwt` notification.

**Files.** `pkg/probes/jwt/jwt.go`, `pkg/wildcard_flow/jwt_audit.go` (`stepJWTAudit`), `pkg/database/database.go`, `pkg/scan/scan.go:WildcardSteps` (`jwt_audit`), `cli/wildcard.go` (`--skip-jwt`).

---

#### 2.3.5 CORS verified-audit (new Phase 4 step)

**Why.** DB tracks `cors_wildcard` boolean only (`database.go:198`). Reflected-origin, null-origin, regex-bypass (`^https?://(.*\.)?target\.com/`) — far higher BB value.

**Plan.** New `pkg/probes/cors/probe.go`.
- For each scoped live URL, send 4 probe origins:
  1. `https://evil.com`
  2. `null`
  3. `https://target.com.evil.com`
  4. `https://evil.target.com`
- Parse `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials`. Keep only when reflected-or-allowed AND `allow-credentials: true`. Persist each probe row in `cors_findings`.

**Files.** `pkg/probes/cors/probe.go`, `pkg/wildcard_flow/cors_audit.go` (`stepCORSAudit`), `pkg/database/database.go`, `pkg/scan/scan.go:WildcardSteps`, `cli/wildcard.go` (`--skip-cors`). Query command: `chaathan query cors <scan>`.

---

#### 2.3.6 Host-header injection & cache poisoning probe

**Why.** Two recurring BB reports against password-reset flows and reverse-proxy caching.

**Plan.** New `pkg/probes/host_header/probe.go`:
- For each scoped live URL, replay with each of:
  - `Host: evil.com`
  - `X-Forwarded-Host: evil.com`
  - `X-Original-URL: /admin`
  - `X-Rewrite-URL: /admin`
  - `X-Forwarded-For: 127.0.0.1`
  - `X-Real-IP: 127.0.0.1`
- A finding is positive if the reflected body / Referer / Location header / password-reset email field contains the spoofed value, OR if access to a previously-403 resource flips to 200.

**Files.** `pkg/probes/host_header/probe.go`, `pkg/wildcard_flow/host_header_audit.go` (`stepHostHeaderAudit`), `pkg/database/database.go`, `pkg/scan/scan.go:WildcardSteps`, `cli/wildcard.go` (`--skip-host-header`).

---

#### 2.3.7 Cloud-bucket takeover (new Phase 1 step)

**Why.** S3/GCS/Azure Blob enumeration runs in company_flow only, keyword-only. BB programs pay for `https://target.com.s3.amazonaws.com` (path style) and `s3.amazonaws.com/target.com` (virtual style) permutations.

**Plan.** New `pkg/cloud/buckets.go` (native Go prober — faster than shelling out):
- Permutations: `{domain, www, dev, prod, staging, api, assets, static, files, backups, archive, screenshots, user-content, media} × easy-bucket-name`.
- HEAD each S3/GCS/Azure URL; classify response:
  - `NoSuchBucket` → **available, exploitation candidate**.
  - `AccessDenied` with 200/403 → exists, may be misconfigured → enumerate objects.
- Verifier: a 200 with `Content` length 0 is "exists but empty" not a bug; only `NoSuchBucket` or an unauthenticated 200/Listing → finding.
- Persist `cloud_buckets` table.

**Files.** `pkg/cloud/buckets.go`, `pkg/wildcard_flow/cloud_enum_target.go` (`stepCloudEnumTarget`), `pkg/database/database.go`, `pkg/scan/scan.go:WildcardSteps`, `cli/wildcard.go` (`--skip-bucket-enum`).

---

#### 2.3.8 Container / K8s exposure probe (extends Phase 2/4)

**Why.** `naabu` top-1000 misses 2375/2376/2379/2380/6443/10250/10255/5000/5601/9200/11211 (D1 of D7).

**Plan.**
- Add a `naabu.bounty_ports` config with `"2375,2376,2379,2380,5000,5601,6443,9200,9300,10250,10255,11211,27017,3306,6379,11211,5432"` (override-able).
- For each open bounty port, run a protocol-aware probe:
  - 2375/2376 → `GET /version` (Docker API)
  - 2379/2380 → `GET /v2/keys/?recursive=true` (etcd v2)
  - 6443 → `GET /api` (k8s API server)
  - 10250 → `GET /pods` (kubelet, often auth-bypassed)
  - 5000 → `GET /v2/_catalog` (registry)
  - 9200 → `GET /` (Elastic)
  - 11211 → trivial UDP read (memcached)
- Persist as `vulnerabilities` with `template_id='infra-exposure-<service>'`, `severity='high'`.

**Files.** `pkg/probes/infra/{docker,etcd,k8s,kubelet,registry,elastic,memcached}.go`, `pkg/wildcard_flow/infra_audit.go` (`stepInfraAudit` after `stepPortScanning`), `pkg/config/config.go:NaabuConfig.BountyPorts`, `pkg/tools/tools.go:naabuPorts`.

---

### 2.4 Tx.4 — Blind-class enablement via self-hosted collaborator (fix D1)

This is the single biggest bug-finding delta per hour invested.

#### 2.4.1 Self-hosted OOB listener

**Plan.** New package `pkg/collaborator/` implementing:
- HTTP listener (port 80 or any `:0` system-assigned) returning a scan-unique `Access-Log` to map back to the scan-URL pair that sent the payload.
- DNS listener (`miekg/dns`) on port 53 for `*.ct.<owner-domain>` A queries.
- (Optional) SMTP listener port 25 for `*@ct.<owner-domain>`.
- For each interaction: persist `(scan_id, host, url, source_ip, protocol, raw, created_at)`.
- Auto-purchase / use a wildcard domain (`*.t.<user-domain>`) — wire via DNS-only mode for self-host on a VPS, or use the public **interactsh.com** relay as a graceful fallback (`enable_interactsh_relay: true`).

**Files.** `pkg/collaborator/{server,store,config,mappings}.go`, `pkg/config/config.go` (`Collaborator` block), `pkg/database/database.go` (`oob_interactions` table).

---

#### 2.4.2 Wire collaborator into Nuclei + new blind-param step

**Plan.**
- When `collaborator.enabled` and the `nuclei` mode produces OOB-callback templates: drop `-no-interactsh` (`pkg/tools/vulnerability_engine.go:61`), pass `-interactsh-url <our_url>`.
- New `stepBlindParamProbe` in Phase 4 (after `stepXSSScanning`):
  - Take `ParamURLsFile`.
  - For each URL × each parameter (query, body, JSON), inject the collaborator URL.
  - Probe dangerous headers too: `X-Forwarded-For`, `X-Original-URL`, `X-Forwarded-Host`, `Forwarded`, `True-Client-IP`, `X-Real-IP`.
  - Also POST XML with `<!DOCTYPE x [<!ENTITY % d SYSTEM "http://ct.../?id=xml">]>` for blind XXE.
  - Poll the `oob_interactions` table over the next 15 min; for each interaction matching this scan, store a blind SSRF / blind XXE `vulnerabilities` row.
- New `--skip-blind-param` flag.

**Files.** `pkg/probes/blindparam/probe.go`, `pkg/wildcard_flow/blind_param.go` (`stepBlindParamProbe`), `pkg/wildcard_flow/vulnerability_scanning.go:snapshotVulnIDs` (extend to mark as new), `pkg/tools/vulnerability_engine.go:NucleiScanner.Scan` (drop `-no-interactsh` when collaborator is configured).

**Validation.** Run against a DVWA blind-SSRF lab or `https://httpbin.org/anything?url=<collaborator>` → expect OOB hit logged within 30s; rewrite `vulnerabilities` row.

---

### 2.5 Tx.5 — Deep JS recon & secret mining (fix D4)

#### 2.5.1 Bulk JS downloader

**Plan.** After `stepJSAnalysis`, new `stepJSDownload`:
- Read `JSURLsFile` (collected from katana / gospider / golinkfinder).
- Download each `*.js*` in parallel (cap = `cfg.JSDownload.Concurrency`, default 8) with the configured `--cookie`.
- Cap body size at 5 MB; persist body under `intermediate_files/js/<host>/<sha1>.js`.
- Re-run `linkfinder` regex over each body; discovered URLs feed back into `all_urls_live.txt` (merge), so vuln-scanning sees them.
- This is the loop: js → urls → (next scan step) → rerun.

**Files.** `pkg/wildcard_flow/js_download.go` (`stepJSDownload`), reuses `pkg/runner.Runner`.

---

#### 2.5.2 JS secret regex library

**Plan.** New `pkg/secrets/regexmap.go` — a curated `*regexp.Regexp` array covering: AWS access keys (`AKIA[0-9A-Z]{16}`), Google API keys (`AIza[0-9A-Za-z_\-]{35}`), Stripe (`sk_live_[A-Za-z0-9]{24,}`), Slack (`xox[abp]-...`), SendGrid (`SG\.`), GitHub PAT (`ghp_[A-Za-z0-9]{36}`), JWT (header + payload), Firebase `apiKey:` (`"apiKey":"[A-Za-z0-9_-]{39}"`), Heroku (`[0-9a-f]{8}-...`), Twilio (`SK[0-9a-f]{32}`), private keys (`-----BEGIN … PRIVATE KEY-----`), and a few generic regexes for `password=`, `secret=`, `token=` in single-quoted JS string contexts.
- Each match is verified: try the S3 / Stripe / Slack live API to confirm the key is *live*, not a documentation example.
- Persist as `js_secrets` table with `verified : bool` column.

**Files.** `pkg/secrets/regexmap.go`, `pkg/secrets/verify.go` (per-provider verify), `pkg/wildcard_flow/js_secret_audit.go` (replaces the existing low-fidelity `gf secrets` step), `pkg/database/database.go` (`js_secrets` table), `cli/query.go` (`chaathan query secrets <scan>`).

---

### 2.6 Tx.6 — Automation chains & adaptive execution (fix D6)

#### 2.6.1 Auto-resume of just-failed steps

**Why.** `finalizeScan` returns to CLI on complete; failed steps stay flagged in `state.json`. User must `chaathan scans resume <id>`. In long-running scans this is friction.

**Plan.** New behaviour: at end-of-scan, if `len(state.FailedSteps) > 0` and `config.AutoRetry` is enabled (default true), retry each failed step once with a 3× longer timeout, before finalising. Log diff: "Step X retried → success". Persist as `state.RetriedSteps` slice.

**Files.** `pkg/scan/scan.go` (`RetriedSteps` field + `MarkStepRetried`), `pkg/wildcard_flow/flow.go:executeStep` (retry hook), `pkg/config/config.go` (`AutoRetry bool`).

---

#### 2.6.2 Per-host cooldown + adaptive scope-based parallelism

**Why.** `RateLimits.GlobalRPS` is global & static. A 200-host scan dominated by a few hostile targets all hit the global rate at the same time; per-host bans stack up.

**Plan.**
- Track per-host error rate in `Ctx.HostStats map[string]hostStat` (`429s`, `500s`, timeouts).
- When a host exceeds N% errors (configurable), add it to a `Cooldowns` set; downstream steps skip cooled-down hosts (logged at Info level).
- For parallel steps (`stepPassiveEnum`, `stepURLDiscovery`, `stepWebCrawling`), default concurrency = `min(8, len(liveHosts)/4)` — but never below one.

**Files.** `pkg/orchestrate/throttle.go` (new), `pkg/wildcard_flow/flow.go` (wire `HostStats`), integration in each multi-tool step.

---

#### 2.6.3 Recursive content discovery in `ffuf`

**Why.** Today `RunFfuf` is depth=1 on a single URL.

**Plan.**
- Pass `-recursion -recursion-depth 3 -auto-calibrate` to ffuf when `cfg.Tools.Ffuf.Recursive=true` (default true).
- Use the mini-wordlist (2.1.1) for the first pass, switch to directories-large from seclists if `-recursion` finds content on a path (`-recursion-strategy greedy best-scan`) — keeps the first pass fast.

**Files.** `pkg/tools/tools.go:buildFfufArgs`, `pkg/config/config.go:FfufConfig` (add `Recursive`, `RecursionDepth`).

---

#### 2.6.4 Screenshots & visual flag

**Why.** Visual inspection is the second-most productive enumerator after JS analysis for BB hunters. Stale panels, debug pages, "test" environments live long before they get fixed.

**Plan.** New optional step `stepScreenshots` (default off, opt-in via `--screenshots`):
- Use `headless` (`github.com/chromedp/chromedp`) to capture each live host's `/`.
- Store under `final_files/screenshots/<host>.png`.
- Hash each image (pHash) and group dups; visually similar hosts flagged as "potential staging twin".

**Files.** `pkg/wildcard_flow/screenshots.go`, `cli/wildcard.go` (`--screenshots`).

---

### 2.7 Tx.7 — Recon depth via modern free sources (fix D8)

Each new pair plugs into `stepPassiveEnum` as an additional goroutine.

#### 2.7.1 `crt.sh` CT-log pull (no API key)

**Plan.**
- `GET https://crt.sh/?q=%.<domain>&output=json`.
- Parse `common_name` + `name_value` (multiline SANs).
- Append unique to `ConsolidatedSubs`.

**Files.** `pkg/recon/crtsh.go`, wired into `stepPassiveEnum` parallel goroutine pool.

---

#### 2.7.2 SecurityTrails integration (key **already configured** but unused)

**Why.** `pkg/config/config.go:102` defines `APIKeys.SecurityTrails`. `pkg/config/config.go:GetAPIKey` already returns it. No flow step uses it.

**Plan.**
- `GET https://api.securitytrails.com/v1/history/<domain>/subdomains` with `APIKEY` header.
- `GET https://api.securitytrails.com/v1/domain/<domain>/subdomains`.
- Merge results into passive-enum output.

**Files.** `pkg/recon/securitytrails.go`.

---

#### 2.7.3 AlienVault OTX, Hackertarget, DNSdumpster, Anubis

All free, no account. Add as parallel passive enum sources, each with its own goroutine, all merging into `ConsolidatedSubs`.

**Files.** `pkg/recon/{otx,hackertarget,dnsdumpster,anubis}.go`.

---

## 3. Final phase / step layout (proposed)

The pipeline keeps its **6 phases**. Inserted steps are **bold**; renamed ones are **italic**. Nothing is removed.

```
PHASE 0 — PROXY SETUP
  1. proxy_scraping                                        (existing)

PHASE 1 — ASSET DISCOVERY
  2. passive_enum                                          (+ crt.sh, ST, OTX, Hackertarget, DNSdumpster, Anubis goroutines)
  3. active_enum (Amass)                                   (existing)
  4. github_recon                                          (existing)
  5. search_engine_recon (Uncover)                         (existing)
  6. js_subdomain_discovery (Hakrawler)                    (existing)
  6b. cloud_bucket_enum            [NEW — Tx.3.7]
  6c. typosquatting                [NEW — bonus, low effort: reuse dnstwist-go]

PHASE 2 — VALIDATION & FINGERPRINT
  7. dns_resolution (DNSx)                                  (existing)
  8. dns_bruteforce (ShuffleDNS)                            (now default-on via mini-wordlist)
  9. port_scanning (Naabu, default bounty ports)            (better default port list)
  10. http_probing (Httpx + soft-404 baseline)               (baseline handoff to ffuf)
  11. tls_analysis (tlsx)                                   (existing)
  11b. infra_port_audit             [NEW — Tx.3.8]

PHASE 3 — CONTENT DISCOVERY
  12. url_discovery (Wayback + GAU)                         (existing)
  13. web_crawling (Katana + GoSpider)                      (existing)
  14. js_analysis (GoLinkFinder)                            (existing)
  14b. js_download                 [NEW — Tx.5.1]
  14c. js_secret_audit            [NEW — Tx.5.2; replaces shallow stepJSSecretScan]
  14d. graphql_recon               [NEW — Tx.3.1]
  14e. spec_extraction            [NEW — Tx.3.2]
  14f. websocket_probe            [NEW — Tx.3.3]
  15. dir_fuzzing (ffuf, recursive by default)              (was optional, now default-on)
  16. param_discovery (x8)                                  (now default-on)
  17. url_consolidation & live check (httpx + ROI)          (existing)
  18. js_secret_scan (gf)                                   (kept as shallow fallback)

PHASE 4 — VULNERABILITY SCANNING
  19. takeover_detection (Nuclei + subzy + refreshed sigs)  (existing, strengthened by Tx.2.x)
  20. vuln_scanning — Infra (Nuclei -as + misconfig + tech tag injection)  (Tx.2.3)
  20b. nvd_cpe_enrich              [NEW — Tx.2.2]
  21. vuln_scanning_urls (Nuclei DAST)                      (existing)
  21b. blind_param_probe          [NEW — Tx.4.2 — blind SSRF/XXE]
  22. xss_scanning (Dalfox)                                 (existing)
  22b. jwt_audit                  [NEW — Tx.3.4]
  22c. cors_audit                 [NEW — Tx.3.5]
  22d. host_header_audit          [NEW — Tx.3.6]

PHASE 5 — FINGERPRINTING
  23. tech_waf_fingerprinting                                (existing)
  23b. email_posture (SPF/DMARC/DKIM)  [NEW — bonus]
  23c. screenshots                   [NEW — opt-in, Tx.6.4]
```

Total: 23 → 37 effective steps (existing 23 + 14 bonus steps). Defaults remain "scan full pipeline"; `--shallow` runs the legacy 23 as today.

---

## 4. Skip-flag matrix (user can opt out of any new step)

New flags added to `cli/wildcard.go`:

| Flag | Skips step(s) | Default |
|------|---------------|---------|
| `--shallow` | all new Phase 1/3/4/5 bonus steps | off |
| `--skip-graphql` | `graphql_recon` | off |
| `--skip-specs` | `spec_extraction` | off |
| `--skip-websocket` | `websocket_probe` | off |
| `--skip-jwt` | `jwt_audit` | off |
| `--skip-cors` | `cors_audit` | off |
| `--skip-host-header` | `host_header_audit` | off |
| `--skip-bucket-enum` | `cloud_bucket_enum` | off |
| `--skip-infra-audit` | `infra_port_audit` | off |
| `--skip-blind-param` | `blind_param_probe` | off |
| `--skip-js-download` | `js_download` | off |
| `--skip-typosquat` | `typosquatting` | off |
| `--skip-nvd` | `nvd_cpe_enrich` | off |
| `--skip-email-posture` | `email_posture` | off |
| `--screenshots` | `screenshots` | **off (opt-in)** |

Existing `--wordlist` / `--dns-wordlist` flags still override the bundled mini defaults.

---

## 5. Validation & rollout

Every PR ends with this mandatory gate (matches AGENTS.md):
```bash
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./... && go vet ./... && go build -buildvcs=false -o chaathan ."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan --help"
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan wildcard --help"
```

Suggested PR ordering (each is independently shippable):

| PR | Title | Respect meta-rule §7 (doc sync) |
|----|-------|---------------------------------|
| **PR-1** | **Tx.1.1 — Bundled mini-wordlists, default-on ffuf/DNS/x8** | Update README + `chaathan-recon-workflows/SKILL.md` step table |
| **PR-2** | **Tx.2.1 — Generalised verifier framework; refactor takeover fit** | Update `chaathan-recon-workflows/SKILL.md` |
| **PR-3** | **Tx.4.1 — Self-hosted collaborator + interactsh re-enable** | Update README + `chaathan-recon-workflows/SKILL.md` |
| **PR-4** | **Tx.4.2 — Blind param probe step** | Update `chaathan-recon-workflows/SKILL.md` |
| **PR-5** | **Tx.3.5 — CORS audit + verifier (small, reusable)** | Update skill, README |
| **PR-6** | **Tx.3.4 — JWT audit (self-contained Go)** | Update skill |
| **PR-7** | **Tx.3.1 — GraphQL recon + verifier** | Update skill |
| **PR-8** | **Tx.3.2 — OpenAPI/gRPC spec ingestion** | Update skill |
| **PR-9** | **Tx.5.1 + 5.2 — JS download + secret regex library** | Replaces `stepJSSecretScan`; big README change |
| **PR-10** | **Tx.3.6 — Host-header / cache poisoning probe** | Update skill |
| **PR-11** | **Tx.3.7 — Cloud bucket enum** | Update skill |
| **PR-12** | **Tx.3.8 — Bounty ports + infra exposure probes** | Update `pkg/tools/registry.go` for help text |
| **PR-13** | **Tx.2.2 — NVD CVE enrichment** | Update config docs (`api_keys.nvd`) |
| **PR-14** | **Tx.6.1 — Auto-retry failed steps** | Update `chaathan-recon-workflows/SKILL.md` resume section |
| **PR-15** | **Tx.6.2 — Per-host cooldown + adaptive parallelism** | Update skill |
| **PR-16** | **Tx.6.3 — Recursive ffuf defaults** | Update `pkg/tools/registry.go` description |
| **PR-17** | **Tx.6.4 — Screenshots (opt-in)** | Optional, artistic |
| **PR-18** | **Tx.7.* — crt.sh / SecurityTrails / OTX / Hackertarget / DNSdumpster / Anubis** | Update enum skills |
| **PR-19** | **Email posture** | Bonus |
| **PR-20** | **Typosquatting** | Bonus |

---

## 6. Effort estimates & priorities

Sized so a single agent / PR achieves the goal in one sitting; nothing here is a multi-week effort.

| Tier | PRs | Sizing each | Bug-finding ROI |
|------|------|-------------|-----------------|
| **1 (weekend)** | PR-1 (defaults), PR-3 (collaborator), PR-4 (blind param), PR-5 (CORS) | 4-6h each | **Highest** — converts silent scans into live findings immediately |
| **2 (week)** | PR-2 (verifier framework), PR-7 (GraphQL), PR-9 (JS secrets), PR-13 (NVD) | 6-8h each | High |
| **3 (next 2 weeks)** | PR-6 (JWT), PR-8 (OpenAPI), PR-10 (host-header), PR-11 (cloud buckets), PR-12 (infra audit), PR-18 (recon sources) | 6-10h each | Medium-high |
| **4 (polish)** | PR-14, PR-15, PR-16, PR-17, PR-19, PR-20 | 3-6h each | Medium |

---

## 7. What this plan deliberately does **not** propose

- **No new CLI top-level commands.** All work lives in `chaathan wildcard` — keeps the cognitive surface area flat. (Multi-target batching, REST server, monitor daemon, plugins belong in the broader `IMPROVEMENT_PLAN.md`, not this file.)
- **No DB schema rewrite.** Each new step adds additive tables / columns; runs through the existing `runMigrations()` additive path until a proper migration framework lands (separate decision).
- **No removal of existing steps.** Old `stepJSSecretScan` (`gf secrets`) stays as a fast fallback; new `js_secret_audit` runs in addition (and notifies only verified keys).
- **No changes to `network` flag layout or `CMD` shape.** Output files keep their current names; new outputs go to `intermediate_files/` with new predictable names so existing tooling still works.
- **No third-party binary dependencies for verifier framework.** Verifiers do plain Go HTTP/DNS — install footprint unchanged.

---

## 8. Open questions for maintainer (decide before PR-1 merges)

1. **Wordlist embedding** — ship embedded mini-lists in the binary (preferred, ~50KB) or download from a GitHub release at first run?
2. **Collaborator deployment** — self-host on a VPS with `*.ct.<owner-domain>` (preferred), or use `interactsh.com` relay shared with PD? Relay loses private scan identity.
3. **Default-on aggressive options** — keep `naabu` at top-1000 today, or change default to `BountyPorts` so Sprint-12 picks up infra exposures by default? Some BB program rules forbid high-rate port scans.
4. **JS body storage** — keep bodies on-disk (preferred, easy to replay) or only regex in-memory? On-disk enables Burp ingestion but eats space (typical scan: 10–200 MB).
5. **NVD rate limit** — accept the free 50 req/30min (slow on batch), or make `api_keys.nvd` mandatory for Tier-2 PR-13?
6. **`--shallow`** — alias to today's `--skip-amass --skip-naabu --skip-nuclei` or broader (also skip dalfox + new bonus steps)?

Answer #2 first — it unblocks PR-3/PR-4 which together deliver the single largest bug-finding delta.