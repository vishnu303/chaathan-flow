# Chaathan Improvement Plan — From a Bug Bounty + Go Engineering Lens

**Author perspective:** 20-year bug bounty hunter / pentester / Go developer
**Scope:** New tools, workflow changes, features, and engineering quality
**Horizon:** 6 months, ordered by bug-finding ROI first, then ops scale, then tech debt
**Status:** Proposal — no code modified yet. Pick a tier / item to start.

---

## 0. Executive Summary

Chaathan is already strong on the **breadth of passive recon** but the **vulnerability exploitation phase** is thin (≈3 Nuclei passes + Dalfox). From a bug bounty hunter's POV the highest-leverage improvements, in order, are:

1. **Cover modern attack surfaces that are blind today** → GraphQL, OIDC/SAML, OpenAPI, WebSocket, HTTP/3, cloud-bucket takeover, blind-SSRF/OOB, container/K8s exposure, email-security posture. *(Tier 1)*
2. **Close the OOB gap**: interactsh is disabled by default (`nuclei.DisableOOB = true`) so an entire class of blind bugs (SSRF, XXE, log4shell, SSTI-blind) never fires. A self-hosted collaborator + tuned enablement fixes this without recompiles. *(Tier 1)*
3. **Replace rote enumeration with verified exploitation evidence** — strip false positives in takeovers, CORS, SSRF the same way `ValidateTakeoversFile` already does. *(Tier 1)*
4. **Operate at bug-bounty program scale**: multi-target batch, scope-file ingestion (HackerOne/Bugcrowd), continuous-monitor scheduler with diff-driven alerting, REST API surface. *(Tier 2)*
5. **Engineering debt that's blocking every test run**: CGO requirement (switch to `modernc.org/sqlite`), config-drift between `DefaultConfig` and `applyDefaults`, leaf-package inversion in `utils`, no schema-versioning, no `.gitattributes`. *(Tier 3)*

Each item below is sized to ship as one PR and lists the concrete file-level changes so an agent or contributor can implement it without re-discovering the architecture.

---

## 1. Strategic Themes

| # | Theme | Target outcome |
|---|-------|----------------|
| T1 | **Modern attack-surface coverage** | New scan steps + tools that target GraphQL, OIDC/SAML, OpenAPI, WebSocket, HTTP/3, cloud buckets, container/K8s, email security. Find bug classes that today produce zero findings. |
| T2 | **Verified, dedup'd, OOB-enabled vulnerability phase** | Self-hosted collaborator, FP-stripping for CORS/SSRF/S3, dup-detection across scans, NVD/CPE enrichment beyond Nuclei's `-as`. |
| T3 | **Bounty-program-scale operations** | Multi-target batch, scope-file import, continuous-monitor daemon, REST API, plugin lifecycle. |
| T4 | **Recon depth & fresh sources** | CT logs, SecurityTrails/VirusTotal/Quake/ZoomEye graph pivot, fresh-URL delta detection, typosquat & homoglyph, DMARC/SPF/DKIM. |
| T5 | **Engineering quality & testability** | CGO-free SQLite, schema versioning, structured logging, context propagation, package boundaries, lint config, CRLF fix. |

---

## 2. Tier 1 — Highest bug-finding ROI (do these first)

### 1.1 Self-hosted OOB collaborator + safe enablement of interactsh

**Problem.** `pkg/tools/tools.go:390` returns `nucleiDisableOOB()=true` by default and `pkg/config/config.go:460` sets `DisableOOB: newBool(true)`. With OOB off, **all blind templates (SSRF, XXE, SSTI-blind, RCE-blind, log4shell, OOB-SQLi) silently no-op** — an entire bug class is invisible.

**Plan.**
- New package `pkg/collaborator/` implementing an HTTP/DNS/SMTP listener (`Larry`-style) returning rotated subdomains of `*.ct.<local>` and logging which interaction came from which scan/URL.
- Config block `collaborator:` with `enabled`, `domain`, `listen_addr`, `public_url`, `auth_token`.
- Auto-detect: if `collaborator.enabled=true`, override `nuclei.DisableOOB=false` and pass `-interactsh-url`/`-interactsh-token` to `RunNucleiDAST`/`RunNucleiSmartCVE`.
- Persist interactions in a new table `oob_interactions(scan_id, host, url, source_ip, protocol, raw, created_at)` so `chaathan query oob <scan>` can replay them.
- Notify on first interaction for the scan.

**Files.** `pkg/collaborator/{server.go,store.go,test_exports.go}`, edits to `pkg/config/config.go` (`Collaborator` block), `pkg/tools/tools.go` (nuclei opts), `pkg/wildcard_flow/vulnerability_scanning.go` (wire URL), `cli/query.go` (new `oob` subcommand), `cli/config.go` (`config set collaborator.enabled true`).

**Validation.** Run `chaathan wildcard -d <lab> --skip-passive` against a Juiceshop / world-readable log4j target, expect OOB rows in DB and a Discord ping. Unit test:HTTP/DNS interaction parsing.

---

### 1.2 GraphQL surface discovery & abuse

**Problem.** No GraphQL discovery anywhere in the 23 steps. GraphQL is a top BB target (introspection, batching, mutation abuse, field suggestions, alias-based DoS, SSRF `request` field, IDOR via `node(id)`).

**Plan.** New step **`graphql_recon`** inserted after `http_probing` (between Step 10 and 11), gated by `--skip-graphql`.
- Probe `live_subdomains.txt` against common paths: `/graphql`, `/graphql/console`, `/v1/graphql`, `/api/graphql`, `/gql`, `/query`, `/_next/data/*` (Next.js), plus `IntrospectionQuery` POST.
- Tool: integrate **`graphinder`** (`github.com/escape-velocity/graphinder`) and/or **`graphql-cop`** (`github.com/dolevf/graphql-cop`) for vuln checks (introspection enabled, suggestions, batching, mutation-over-GET).
- Verify findings same as takeover validation: replicate and rewrite `graphql_findings.txt` to only real ones.

**Files.** New `pkg/wildcard_flow/graphql.go`, registry entries, `pkg/tools/tools.go` (`RunGraphinder`, `RunGraphQLCop`), `pkg/scan/steps.go` (step def), `cli/wildcard.go` (`--skip-graphql`), `pkg/database/database.go` (new table `graphql_endpoints`).

**Validation.** against a real GraphQL target r/w introspection enabled — expect endpoints + introspection-status rows.

---

### 1.3 CORS misconfiguration detector (verified)

**Problem.** Only `cors_wildcard` boolean column exists (`pkg/database/database.go:198`). Bug bounties pay for reflected-origin, null-origin, regex-bypass (`/^https?://(.*\.)?target\.com/`), and subdomain reflection — none of which a single boolean captures.

**Plan.** New package `pkg/probes/cors/` that, given a live URL, sends 4 probe origins:
1. `https://evil.com`
2. `null`
3. `https://target.com.evil.com`
4. `https://evil.target.com`

…then parses `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials: true`. Persist each probe + reflection result in a new table `cors_findings(scan_id, url, probe_origin, reflected_origin, allow_credentials, evidence)`. FP-strip: write only confirmed (reflected + credentialed) findings.

**Files.** `pkg/probes/cors/probe.go`, `pkg/wildcard_flow/vulnerability_scanning.go` (new `stepCORSAudit` after `xss_scanning`), `pkg/database/database.go` (table + queries), `cli/query.go` (`query cors <scan>`).

---

### 1.4 Subdomain-takeover signature refresh + FP enforcement

**Problem.** `ValidateTakeoverCandidate` in `pkg/wildcard_flow/vulnerability_scanning.go:594-606` only knows ~11 signatures (S3, GitHub, Heroku, Shopify, Squarespace, Wix, Ghost, Tumblr, Pantheon) plus 9 CNAME fingerprints. Modern platforms missing: **Vercel, Netlify, Render, Fly.io, Surge.sh, Fastly, Azure Front Door, Strikingly, Tilda, Webflow, S3-Website-<region>, Firebase Hosting, Cloudfront (dangling)**.

**Plan.**
- Extend `vulnerableSignatures` and `cnameFingerprints` to cover the full `can-i-take-over-xyz` catalogue (https://github.com/EdOverflow/can-i-take-over-xyz/).
- Or replace bespoke validation with **`subzy`** (`github.com/LukaSikic/subzy`) integrated as a scan step (it auto-fetches the signatures and performs live verification). Keep `ValidateTakeoverCandidate` as the FP-stripper on top.
- Add monthly auto-refresh job pulling the signatures JSON into `~/.chaathan/takeover-signatures.json`.

**Files.** `pkg/wildcard_flow/vulnerability_scanning.go` (signatures list / new `stepTakeoverSubzy`), `pkg/tools/tools.go` (`RunSubzy`), `pkg/tools/registry.go`, `pkg/setup/` (install path).

---

### 1.5 Cloud-bucket & cloud-asset takeover (dedicated step)

**Problem.** `cloud_enum` (Python) runs only in the company flow as Step 3, keyword-based. It's slow, unmaintained, and not run per wildcard target. S3/GCS/Azure-blob enumeration continues to be one of the highest-paying BB classes.

**Plan.** New wildcard step **`cloud_enum_target`** (Phase 1, after passive enum) running per-domain:
- Probe `s3.amazonaws.com/<bucket>` permutations built from `{domain, www, dev, prod, staging, api, assets, static, files, backups, archive, screenshots, user-content}` × easy-utils.
- Add **`gcs`** (Google Cloud Storage) and **Azure Blob** variants.
- Verify with HTTP HEAD: a 404 from `NoSuchBucket` ≠ "available"; only `NoSuchBucket` body or `Code: NoSuchKey` with no objects is takeover candidate. Use the same FP-stripping pattern as takeovers.
- Integrate `cloudfox`-style enumeration by reading CSP/CNAME evidence collected in Phase 2/3 (`amazonaws.com`, `storage.googleapis.com`, `blob.core.windows.net`).

**Files.** `pkg/cloud/buckets.go` (native Go bucket prober — faster than calling out), `pkg/wildcard_flow/asset_discovery.go` (new step), `pkg/database/database.go` (`cloud_buckets` table), `cli/query.go` (`query buckets <scan>`).

---

### 1.6 Blind-SSRF & blind-XXE parameter injection (uses 1.1 collaborator)

**Problem.** OOB disabled (see 1.1) means blind SSRF/XXE blind classes are silent. Even after enabling, we lack coverage: `Nuclei DAST` targets a generic URL list, but blind SSRF requires injecting a payload into every reflected/interesting parameter, with high coverage and low noise.

**Plan.** After DAST step, new **`blind_param_probe`** step:
- For each scoped parameterized URL (`ParamURLsFile`), inject the collaborator URL into every parameter value.
- Also probe headers (`X-Forwarded-For`, `X-Original-URL`, `X-Forwarded-Host`, `X-Rewrite-URL`, `Forwarded`).
- Compare against DB-backed interaction list from `pkg/collaborator`. A hit within ±15 min marks the URL+param as a blind SSRF finding with severity `high`.
- Repeat for XXE: POST XML body with external entity referencing the collaborator; trace DNS interaction.

**Files.** `pkg/probes/blindparam/probe.go`, `pkg/wildcard_flow/vulnerability_scanning.go` (`stepBlindParamProbe`), reuse 1.1 infra.

---

### 1.7 JWT analysis suite

**Problem.** JWT-related bugs (alg=none, HS256 with weak/RSA-public-as-HS-secret confusion, kid path traversal, expired-but-accepted) are consistent BB payouts and currently invisible.

**Plan.** New `pkg/probes/jwt/` module that for each discovered `Authorization: Bearer <jwt>` (collected in `pkg/metadata/collector.go` `has_session_cookie`/headers):
1. Decode header+payload without verifying.
2. Try `alg:none` rewrite + replay to a known endpoint; compare response.
3. Try **HS256 confusion** using the public RSA key from `/.well-known/jwks.json` (if discoverable) as HMAC secret.
4. Try `kid:` path traversal (`../../../dev/null`, `../../../../etc/hosts`).
5. Try common weak secrets (`secret`, `password`, base64 of `kid`) via `jwt-cracker`-equivalent Go brute.
6. Try replay with shifted `exp` (`exp = now + 99 years`).

**Files.** `pkg/probes/jwt/jwt.go` (uses `github.com/golang-jwt/jwt/v5`), new step `jwt_audit`, `pkg/database/database.go` (`jwt_findings` table).

---

### 1.8 OpenAPI / Swagger / gRPC spec ingestion → endpoint fuzzing

**Problem.** `pkg/database` has an `endpoints` table populated only by `katana`/`gospider`/`golinkfinder` — i.e. crawls. Spec files are discovered and discarded into the URL pool. Bug bounty value: parse spec → enumerate every method/parameter pair → feed Nuclei DAST + Dalfox + BlindParamProbe with structured coverage.

**Plan.** Step inside Phase 3: after `url_discovery`, scan `all_urls_live` for `swagger.json`, `openapi.json`, `swagger.yaml`, `*.proto`, GraphQL SDL. Parse with `kin-openapi` (`github.com/getkin/kin-openapi`) and emit one row per method+path+permutation to endpoints/buckets with `source='openapi'`. Append those to `ParamURLsFile` for downstream scanners.

**Files.** `pkg/specparser/openapi.go`, `pkg/specparser/grpc.go`, `pkg/wildcard_flow/content_discovery.go` (`stepSpecExtraction`), new query `chaathan query endpoints <scan> --source openapi`.

---

### 1.9 HTTP/2 & HTTP/3 (QUIC) probing surface

**Problem.** `httpx` invocation in `RunHttpx` (`pkg/tools/tools.go:595`) doesn't pass `-http2` or `-http3`. Many modern targets (Cloudflare, Fastly, Google) ship features only over HTTP/3; some bugs (rapid-reset CVE-2023-44487 detection, :method smuggling) are blind over HTTP/1.1.

**Plan.** Expose `httpx.http2` and `httpx.http3` config flags; pass `-http2 true` / `-http3 true`; capture which protocol each host speaks and store it in a new `protocol` column on `urls` (or a per-host table `host_protocols`). Upgrade `naabu` to include UDP/443 so we know QUIC is reachable.

**Files.** `pkg/config/config.go` (`Httpx.HTTP3`), `pkg/tools/tools.go` (`RunHttpx` arg construction), schema migration for `host_protocols` table.

---

### 1.10 WebSocket probing

**Problem.** `ws://` and `wss://` endpoints are not enumerated or fuzzed. Cross-site WebSocket hijacking (CSWSH) is a recurring BB class.

**Plan.** Step in Phase 3:
- From JS analysis (`GoLinkFinderOut`) extract `new WebSocket("…")` URLs into `ws_endpoints.txt`.
- Probe each with a custom Go client (`gorilla/websocket`) passing the cookie header from `--cookie`.
- Test: (a) cross-origin (Origin reflection / `*`),  (b) unauthenticated reachability, (c) advisory轰炸 of authentication handshake (no token).

**Files.** `pkg/probes/websocket/probe.go`, `pkg/wildcard_flow/content_discovery.go` (`stepWebSocketProbe`), `pkg/database/database.go` (`websocket_endpoints` table).

---

### 1.11 CVE → CPE enrichment beyond Nuclei `-as`

**Problem.** `RunNucleiSmartCVE` uses Nuclei's Wappalyzer mapping which only includes templates the Nuclei dev team curates. The full MITRE/NVD CVE space is larger.

**Plan.**
- For each `(host, tech, version)` tuple from `httpx_tech.json`, query NVD's API for `cpe:<cpe>` → CVE list, filter by CVSS ≥7.0 and a known exploit/ref.
- Also use `cpe2cve` (`github.com/steffak/taycan/)`) or `vulnrichment` data.
- Insert into `vulnerabilities` table with `source='nvd'`, `template_id='CVE-2024-XXXXX'`, deduped against any Nuclei-firing.
- Useful when Nuclei templates haven't caught up.

**Files.** `pkg/vulnint/nvd.go`, `pkg/wildcard_flow/vulnerability_scanning.go` (`stepNVDEnrich`).

---

### 1.12 Email-security posture (SPF / DMARC / DKIM / MX)

**Problem.** SPB/DMARC misconfig (e.g. `v=spf1 -all` missing, `p=none`, no DKIM) is widely paid on HackerOne (e.g. email spoofing for password-reset triggers). Today Chaathan never queries these.

**Plan.** New package `pkg/probes/emailsec/` issuing TXT (`_dmarc`, `_spf`, host) + MX queries via `net.LookupTXT`/`net.LookupMX`. Report:
- Missing DMARC, `p=none`, `pct=0`
- Missing SPF / `-all` / `~all`/`+all`
- DKIM: probe common selectors (`google`, `default`, `selector1`, `selector2`, `s1`, `s2`, `mail`).
- MX records exposing internal hosts.

**Files.** `pkg/probes/emailsec/emailsec.go`, `pkg/wildcard_flow/fingerprinting.go` (post-Phase 5 step `email_posture`).

---

### 1.13 Container / orchestration exposure

**Problem.** `naabu` defaults to `top-1000` ports and ignores operationsense ports such as 2375/2376 (Docker), 2379/2380 (etcd), 6443/10250/10255 (k8s API + kubelet), 5000 (registry), 5601/9200 (elastic). Detecting these closed-loop classes is high ROI.

**Plan.**
- Add a `naabu.bounty_ports` string list (`"2375,2376,2379,5000,5601,6443,9200,10250,11211,…"`).
- For each open `infra` port, send protocol-aware probes (Docker `/version`, etcd `/v2/keys`, k8s `/api`, kubelet `/pods` via `kubectl-equivalent`, registry `/v2/_catalog`).
- Insert findings as vulnerabilities `source='infra-exposure'`.

**Files.** `pkg/probes/k8s/`, `pkg/probes/docker/`, `pkg/wildcard_flow/vulnerability_scanning.go` (after infra-pass).

---

## 3. Tier 2 — Bug-bounty program scale & operations

### 2.1 Multi-target batch + scope-file ingestion

**Plan.**
- New CLI: `chaathan wildcard -l targets.txt` (parallelism configurable, default 4).
- Scope-file importers for HackerOne (`*.json` with `StructuredScope`), Bugcrowd (`*.csv`), Intigriti (`*.yaml`).
- Quarterly scheduler: re-scan all targets in scope on a cron.

**Files.** `cli/wildcard.go` (new `-l` flag), `pkg/scope/h1import.go`, `pkg/scope/bugcrowdimport.go`, `pkg/orchestrate/batch.go`.

---

### 2.2 Continuous-monitor daemon + delta-only alerting

**Plan.** `chaathan monitor` subcommand runs as a daemon with a scheduler (`gocron`):
- Re-runs each target on a configured cadence.
- After each scan, computes a delta against the previous scan via existing `diff` logic and notifies only on `new_subdomains`, `new_ports`, `new_vulns`, `new_takeovers`.
- Maintain `monitor_profiles.yaml` for per-target cron expressions.

**Files.** `cli/monitor.go`, `pkg/monitor/daemon.go`, `pkg/notify/` (delta finding type).

---

### 2.3 REST API server mode

**Plan.** `chaathan serve --listen 127.0.0.1:7331` exposing:
- `GET /scans`, `GET /scans/{id}`, `POST /scans` (kick off)
- `GET /scans/{id}/subdomains`, `/ports`, `/vulns`, `/roi`, `/endpoints`
- `GET /scans/{id}/diff?against={id}`
- `GET /scans/{id}/report?format=html`
- Reuse existing `pkg/database` queries; thin handlers only (sticks to AGENTS rule §1).

**Files.** `cli/serve.go`, `pkg/api/` (new). Optional simple static dashboard at `/ui` so users get a browser view.

---

### 2.4 Plugin / custom-tool lifecycle

**Plan.** Let users register custom Go plugins (Go plugin + RPC) or shell scripts that hook into the 23 steps via lifecycle events (`PreStep`, `PostStep`, `Finding`).
- Drop a YAML in `~/.chaathan/plugins/foo.yaml` with `hook: post_step`, `step: vuln_scanning`, `exec: ./foo.sh`.
- Chaathan pipes the relevant artifact file into the plugin's stdin and ingests its stdout as findings.

**Files.** `pkg/plugins/registry.go`, `pkg/plugins/runner.go`, `pkg/wildcard_flow/flow.go` (hook emission).

---

### 2.5 Adaptive rate-limiting + per-host cooldown

**Problem.** Today `RateLimits.GlobalRPS` is global and static. Targets throttling us (429/503 with `Retry-After`) are silently retried by Nuclei until `max-host-error` trips. We never adapt globally.

**Plan.** A `pkg/orchestrate/throttle.go` that tracks per-host error rate; when a host exceeds N% 429/503, it is added to a cooldown list and excluded from the next upstream step in the same scan (not future scans).

**Files.** `pkg/orchestrate/`, integrates with `pkg/tools/tools.go` `appendProxy`-style helpers.

---

### 2.6 Recon-depth additions (CT logs, SecurityTrails graph, public datasets)

**Plan.**
- `crt.sh` JSON pull in `stepPassiveEnum` (cert transparency). Cheap, high-yield source not yet used (only `tlsx` SAN mining after live host discovery).
- `SecurityTrails` API integration for subdomains + history + associated domains (the `APIKeys.SecurityTrails` config field is **already plumbed but unused** — see `pkg/config/config.go:101`).
- `VirusTotal` **graph API** for related hosts.
- `Quake`/`ZoomEye`/`FOFA` enrich with proper email wiring (currently `tools.go:1006` warns FOFA unconfigured).

**Files.** `pkg/reconsources/{crtsh,securitytrails,virustotal,quake,zoomeye}.go`, plus marketing update of `uncoverEngines()` in `pkg/tools/tools.go:1049`.

---

### 2.7 DNS typosquatting / homoglyph / lookalike domains

**Plan.** New step in Phase 1 (after asset discovery):
- Generate candidate typosquats/homoglyphs via `dnstwist`-equivalent Go port (`github.com/elceloud/dnstwist-go` or fork).
- For each candidate, resolve and probe httpx; if reachable, flag as phishing infrastructure.
- Persist in `typosquat_candidates` table.

**Files.** `pkg/reconsources/dnstwist.go`, `pkg/wildcard_flow/asset_discovery.go`.

---

### 2.8 Wordlist auto-fetcher + permutational content discovery

**Problem.** `Wordlists.Directories` defaults to `common.txt` (~4.6K entries). Content discovery at scale needs permutational fuzzing (paths + extensions + recursion). `ffuf` is fine but lacks recursion-aware auto-pruning.

**Plan.** Replace `ffuf` with **`feroxbuster`** (`github.com/epi052/feroxbuster`) as an option:
- Recursive with depth limit, auto-extends wordlist on discovered dirs.
- On-the-fly extension tuning based on `Content-Type` observed.
- Still keep `ffuf` for parameter fuzzing.

**Files.** `pkg/tools/tools.go` (`RunFeroxbuster`), registry entry, `pkg/wildcard_flow/content_discovery.go` (`stepFeroxRecursive` replacing some of step 15).

---

## 4. Tier 3 — Engineering quality (unblocks everything else)

### 3.1 Switch SQLite driver to `modernc.org/sqlite` (CGO-free)

**Why first.** PHASE0_BASELINE.md F-003: 4 highest-complexity test packages (database, report, tui, utils) are **unrunnable today** because `mattn/go-sqlite3` needs CGO + gcc, which WSL doesn't have. `make test` is broken. Every future DB change ships untested.

**Plan.**
1. Add `modernc.org/sqlite` import.
2. Open with `sql.Open("sqlite", …)`. Same SQL surface, modernc passes 100% of the SQLite test suite.
3. Drop `mattn/go-sqlite3` from `go.mod`.
4. Re-enable `-race` in `make test`.
5. Re-write DB-backed tests to actually run.

**Files.** `go.mod`/`go.sum`, `pkg/database/database.go:12` (import + driver name), `Makefile` (`-race`).

**Validation.** `wsl bash -i -c "cd … && go test ./pkg/database/... -race"` must pass.

---

### 3.2 Canonical database schema (Migrations framework omitted)

**Status.** Consolidated into a clean, single-pass canonical schema setup in `createTables()`. `runMigrations()` was removed entirely. External migration versioning frameworks are omitted since local database resets are handled directly.

**Files.** `pkg/database/database.go`.

---

### 3.3 Resolve config default-drift (F-021) and API-key dispatch (F-022)

**Problem.** PHASE1_FINDINGS.md F-021: `DefaultConfig()` and `applyDefaults()` disagree (e.g. `Dalfox.MaxTimeout=120` only in `applyDefaults`; sparse configs get zero threads/ports). F-022: `GetAPIKey("fofa")` returns `""` even when configured.

**Plan.**
- Remove `applyDefaults` entirely; `DefaultConfig()` is the only source of truth.
- Extend `GetAPIKey` switch to cover `censys`, `fofa`, `email`-style (quake, zoomeye).
- Add a `config_test.go` that diffs `DefaultConfig()` against a sparse YAML → all fields populated.

**Files.** `pkg/config/config.go`, `pkg/tools/tools.go:1006` (remove the stale FOFA warning).

---

### 3.4 Leaf-package inversion: extract `pkg/ingest`

**Problem.** F-024: `utils` imports `pkg/database` and `pkg/logger`, so the "foundation" package is coupled to persistence. Functions like `ParseNucleiOutput` are really ingest logic.

**Plan.** Move the `Parse*Output` family to `pkg/ingest/`. Leave `utils/` with only file IO, string/host normalization, and pure helpers — no DB, no logger imports.

**Files.** New `pkg/ingest/`; incrementally update importers; preserve old `utils.ParseXxxExport` shims temporarily to keep external Go consumers working.

---

### 3.5 Centralized logger output cleanup (`logger.Print`)

**Status.** Replaced raw `fmt.Printf` / `fmt.Println` calls in CLI commands (`cli/root.go`, `cli/scans.go`, `cli/status.go`, `cli/tools_cmd.go`) with `logger.Print(...)`. All CLI output now routes through the central logger engine, ensuring clean ANSI stripping, file mirroring to `~/.chaathan/logs/`, and consistent output handling.

**Files.** `cli/root.go`, `cli/scans.go`, `cli/status.go`, `cli/tools_cmd.go`.

---

### 3.6 `.gitattributes` + CRLF normalization

**Problem.** PHASE0 F-002: 14 files rewritten with CRLF endings, will keep recurring.

**Plan.**
```
# .gitattributes
*.go text eol=lf
go.mod text eol=lf
go.sum text eol=lf
```
One-time `git add --renormalize .` + commit.

**Files.** `.gitattributes` (new), single normalizing commit.

---

### 3.7 `golangci-lint` config & agent skill validation

**Problem.** `Makefile lint` target references `golangci-lint` but there's no `.golangci.yml` configuration file (F-014).

**Plan.** Add `.golangci.yml` enabling key linters (`govet`, `staticcheck`, `errcheck`, `gocyclo`, `misspell`, `ineffassign`, `unused`). Wire `golangci-lint run ./...` directly into `.agents/skills/chaathan-dev/SKILL.md` and `AGENTS.md` post-edit validation steps (CI workflow omitted per user choice).

**Files.** `.golangci.yml`, `AGENTS.md`, `.agents/skills/chaathan-dev/SKILL.md`.

---

### 3.8 Context propagation audit

**Problem.** `context.Context` only appears in 18/115 files. `pkg/wildcard_flow` calls `c.Tb.RunXxx(ctx, …)` but many internal phases don't propagate sCtx through sub-helpers, so cancellation can lag.

**Plan.** Sweep priorities: any function that calls a tool or HTTP must accept `ctx context.Context`. Add lint check via custom rule or `contextcheck` linter.

---

### 3.9 This plan file `.agents/skills` sync

Per AGENTS.md Meta-Rule §7, every accepted Tier-1 item updates the relevant skill `.md` (e.g., `chaathan-recon-workflows/SKILL.md` for new steps, `chaathan-tooling-setup/SKILL.md` for new tool integrations) plus the `README.md` step tables.

---

## 5. Roadmap (6-month, prioritised)

| Sprint | Items | Outcome |
|--------|-------|---------|
| **Sprint 1** (2 wk) | **3.1** CGO-free SQLite, **3.6** CRLF, **3.7** lint/CI | Tests runnable, baseline hygiene fixed |
| **Sprint 2** (2 wk) | **3.2** migrations, **3.3** config drift fix, **3.4** ingest package | Architecture ready for new findings |
| **Sprint 3** (3 wk) | **1.1** Self-hosted collaborator, **1.6** Blind SSRF/XXE | First blind-class bugs start firing |
| **Sprint 4** (3 wk) | **1.4** Takeover refresh, **1.5** Cloud-bucket enum, **1.12** Email sec | Takeover/S3/DMARC classes covered |
| **Sprint 5** (3 wk) | **1.2** GraphQL, **1.8** OpenAPI/gRPC, **1.10** WebSocket | Modern API surfaces covered |
| **Sprint 6** (3 wk) | **1.3** CORS, **1.7** JWT, **1.11** NVD enrichment | Logic / auth bugs |
| **Sprint 7** (2 wk) | **1.9** HTTP/3, **1.13** Container/K8s exposure, **2.6** CT/ST/VT graph | Recon depth + infra exposure |
| **Sprint 8** (3 wk) | **2.1** Multi-target batch, **2.2** Monitor daemon, **2.3** REST API | Operate at program scale |
| **Sprint 9** (2 wk) | **2.4** Plugins, **2.5** Adaptive throttle, **2.7** Typosquat, **2.8** Feroxbuster | Long-tail wins |

Each sprint ends with: `go build -buildvcs=false`, `go vet ./...`, `go test ./...` (now CGO-free), and updated skill docs + README step table.

---

## 6. Suggested first PRs (smallest viable)

If only a weekend of work is available, start here:

1. **PR-1: Pure-Go SQLite** (Tier-3.1) — unblocks everything below.
2. **PR-2: Self-hosted collaborator + interactsh re-enable** (Tier-1.1 + 1.6) — single largest bug-finding delta; reuses the new SQLite.
3. **PR-3: Takeover signature refresh** (Tier-1.4) — small, immediate BB value, no new architecture.
4. **PR-4: CT-log + SecurityTrails passive enum** (Tier-2.6, just the crt.sh + SecurityTrails bits) — adds a missing recon source without new steps; closes a TODO on the already-plumbed `APIKeys.SecurityTrails` field.

These four would convert Chaathan from "broad passive recon + a starter vuln pass" into "broad passive recon + a verified, blind-class-aware vulnerability pass" in roughly a month.

---

## 7. Open questions for maintainer

1. **Collaborator hosting**: self-host a Go binary on a VPS (preferred), or wire to interactsh.com relay shared with PD team?
2. **Plugin system**: Go-native plugins (signing + version match) vs. plain shell-script hooks (simpler, no ABI risk)?
3. **HTTP/3 default-on**: opt-in (safer) or opt-out (modern by default)?
4. **NVD API quota**: free 50 req/30 min — fine for ad-hoc; for batch we need to register an NVD key. OK to add `api_keys.nvd`?
5. **Scope-file format priority**: HackerOne `*.json` first (most BB programs there), Bugcrowd `*.csv`, or both simultaneously?
6. **`chaathan serve` security**: bind 127.0.0.1 only with token auth, or also expose plain read-only mode?

Answer #1 and #2 first — they unblock Tier-1.1 which is the single highest-ROI item.