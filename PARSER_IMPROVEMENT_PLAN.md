# Parser Improvement Plan — `pkg/ingest/parser.go`

**Scope:** `pkg/ingest/parser.go` (tool-output ingestion: JSONL/text → SQLite), its helpers in `utils/`, and its DB surface in `pkg/database/`.
**Goal:** Eliminate silent data loss and garbage-row inserts in the ingestion layer; make scope/case/dedup handling consistent across all 11 `Parse*` functions.
**Audience:** Maintainer + agents (matches AGENTS.md "one owner per concern" — ingestion stays in `pkg/ingest`, persistence in `pkg/database`).
**Status:** Proposal only — no code modified.

---

## 0. What was checked

- All 11 parsers in `pkg/ingest/parser.go` (818 lines): `ParseSubdomainsFile`, `ParseHttpxOutput`, `ParseNucleiOutput`, `ParseNaabuOutput`, `ParseEndpointsFile`, `ParseURLsFile`, `ParseLiveURLsFile`, `ParseFfufOutput`, `ParseTlsxOutput`, `ParseUncoverOutput`, `ParseDalfoxOutput`, plus helpers (`scanJSONLines`, `scanTextLines`, `writeLines`, `getTargetDomain`, `isDomainInScope`, `isURLInScope`, `extractDomainsFromLine`, `normalizeIPHost`, `extractURLFromToken`).
- Dependencies: `utils/validate.go` (`ValidateDomain`), `utils/parser.go` (`IsHTTPMethod`, `NormalizeHostValue`, `IsWeakTLSVersion`).
- DB layer: `AddSubdomains`, `AddURL`, `AddPort`, `AddEndpoint`, `AddVulnerability`, `UpdateSubdomainLive`, `UpsertHostMetadata`, and the schema's UNIQUE constraints (`pkg/database/database.go:136-279`).
- All callers in `pkg/wildcard_flow/` (asset_discovery, validation, content_discovery, vulnerability_scanning, fingerprinting).
- Existing tests: `test/utils/utils_test.go` (`setupTestDB` pattern, scan target `example.com`).

### Confirmed NON-issues (no change needed)

| Check | Verdict |
|---|---|
| Dedup across runs | OK — schema has `UNIQUE(scan_id,domain)`, `UNIQUE(scan_id,host,port,protocol)`, `UNIQUE(scan_id,url)`, `UNIQUE(scan_id,url,method)`, and `idx_vulns_unique` on `(scan_id,host,template_id,url)`; all inserts use `OR IGNORE`/upsert. |
| `AddURL` source merging | OK — `ON CONFLICT` clause appends distinct sources and backfills empty fields only. |
| `normalizeIPHost` | OK — handles `1.2.3.4:443`, `[::1]:8443`, bare IPv6 correctly; only strips numeric ports. |
| `writeLines` close-error path | OK — flush/close errors returned, not dropped. |
| `scanTextLines` filtering | OK — trims, skips blanks and `#` comments; 4 MB scanner buffer shared. |

---

## 1. Diagnosis — confirmed logical issues

Severity: **P0** = data loss / garbage rows in a live ingestion path, **P1** = correctness/consistency, **P2** = performance (defer per package header's keep-it-simple note).

| # | Sev | Location | Issue | Evidence |
|---|-----|----------|-------|----------|
| F1 | P0 | `ParseEndpointsFile` (parser.go:427-429) | **Relative endpoints silently dropped.** golinkfinder (step 14) emits paths like `/api/v1/users`. `isURLInScope` → `neturl.Parse` → `Hostname()==""` → `isDomainInScope("", target)` false → dropped on every wildcard scan (target always set). | Caller: `content_discovery.go:440` ingests `GoLinkFinderOut` via this parser. |
| F2 | P0 | `ParseHttpxOutput` (parser.go:251-254) | **`result.Input` fallback mangles IPv6 / URL inputs.** `LastIndex(":")` turns bare `2001:db8::1` into `2001:db8:` and `https://host:8443` into `https://host` — neither matches the subdomains table, so live-marking silently no-ops. | `utils.NormalizeHostValue` (utils/parser.go:30) already handles URL / host:port / bracketed IPv6 correctly. |
| F3 | P0 | `ParseHttpxOutput` (parser.go:241) | **No empty-URL guard.** An httpx line with empty/missing `url` inserts an empty-string row into `urls`. | `AddURL` (database.go:672) stores `""` when parse yields no host. |
| F4 | P0 | `ParseDalfoxOutput` text fallback (parser.go:776-803) | **Inserts vulns with empty host+URL.** A `[POC]`/`[V]` line with no `http(s)://` token still calls `AddVulnerability(scanID, "", "", ...)`. | JSON branch (parser.go:718-723) has the guard; text branch doesn't. |
| F5 | P0 | `ParseTlsxOutput` (parser.go:567), `ParseUncoverOutput` (parser.go:671) | **Case-sensitive scope matching.** `ValidateDomain` accepts uppercase, but `san == targetDomain \|\| HasSuffix(san, "."+targetDomain)` compares raw case → `Www.Example.COM` silently dropped. `targetDomain` comes from `c.Domain`, not normalized. | Both hand-roll the check instead of reusing `isDomainInScope` (parser.go:120). |
| F6 | P0 | `ParseSubdomainsFile` (parser.go:182-186) | **Case inconsistency.** `seen` keyed lowercase but original-case string kept, sorted (case-sensitive ASCII), and written to the rewritten file — while `AddSubdomains` (database.go:448) lowercases. File content ≠ DB content. | `extractDomainsFromLine` (parser.go:141) preserves case. |
| F7 | P1 | `ParseNaabuOutput` (parser.go:399) | Only `port > 0` checked — `host:99999` stored; host never validated (`foo:123` stores host `foo`). | Needs `1 ≤ port ≤ 65535` + IP-or-`ValidateDomain` check. |
| F8 | P1 | `ParseNucleiOutput` (parser.go:333) | Empty `matched-at` → empty `url`; `idx_vulns_unique` then collapses distinct same-template findings on one host into a single row. | Index: database.go:275. Fallback to `result.Host` keeps rows distinct. |
| F9 | P1 | `ParseFfufOutput` (parser.go:512-524) | `count++` fires even when **both** DB inserts fail (all other parsers count successes only); also the only URL-ingesting parser with no scope check. | Scope check is defense-in-depth (ffuf targets live hosts anyway) — keep consistent. |
| F10 | P1 | `scanJSONLines` (parser.go:50), `ParseLiveURLsFile` (parser.go:476), `isDomainInScope` (parser.go:120) | Whitespace-only lines reach `json.Unmarshal` (inconsistent with `scanTextLines`); live-URL dedup is case-sensitive (`HTTP://Example.com` counted twice); `isDomainInScope` lowercases only `domain`, assuming pre-normalized target. | Cosmetic-to-minor; batch together. |
| F11 | P2 | `ParseTlsxOutput` (parser.go:569) | `AddSubdomains` called per SAN — one SQLite transaction each. SAN-heavy certs → many txns. | Collect SANs, single `AddSubdomains` call; keep `newSubs` semantics "unique SANs seen". |

---

## 2. Work units

Each item lists: **what**, **files touched**, **validation**, **risk**.

### Phase 1 — P0 bug fixes

**1.1 Keep relative endpoints (F1)**
- What: in `ParseEndpointsFile`, when the extracted `url` is path-only (no scheme, leading `/` or no host), keep it — skip the scope check (a relative path carries no host to be out of scope) and store as-is. Log scope-drops at `FileDebug` so future drops are observable.
- Files: `pkg/ingest/parser.go`.
- Validation: new test — `/api/v1/users` with target `example.com` is stored; `https://other.org/x` still dropped.
- Risk: low — stores data that was previously lost; DB dedup via `UNIQUE(scan_id,url,method)` unchanged.

**1.2 Fix httpx live-marking fallback + empty-URL guard (F2, F3)**
- What: skip lines with empty trimmed `result.URL`; replace the `LastIndex(":")` fallback with `utils.NormalizeHostValue(result.Input)`.
- Files: `pkg/ingest/parser.go`.
- Validation: tests — empty-url line inserts nothing; input `2001:db8::1` and `https://example.com:8443` fall back to correct hostnames.
- Risk: low — fallback path only.

**1.3 Guard dalfox text fallback (F4)**
- What: return early when no `http(s)://` token found in a `[POC]`/`[V]` line.
- Files: `pkg/ingest/parser.go`.
- Validation: test — `[POC]` line without URL inserts 0 vulns.
- Risk: none.

**1.4 Centralize scope matching with case normalization (F5)**
- What: normalize both args inside `isDomainInScope`; make tlsx/uncover use it instead of hand-rolled suffix checks. Lowercase SANs/hosts before `seen` keys.
- Files: `pkg/ingest/parser.go`.
- Validation: tests — SAN `Www.Example.COM` with target `example.com` accepted; mixed-case `c.Domain` accepted.
- Risk: low — strictly widens acceptance to what already passes `ValidateDomain`.

**1.5 Case-consistent subdomain files (F6)**
- What: lowercase once in `ParseSubdomainsFile` before dedup/store so the rewritten file and DB agree; sort order becomes deterministic.
- Files: `pkg/ingest/parser.go`.
- Validation: test — file with `Sub.Example.COM` rewritten as `sub.example.com` exactly once.
- Risk: low — DB already lowercases; only file content changes.

### Phase 2 — P1 consistency fixes

**2.1 Naabu validation (F7)**
- What: require `1 ≤ port ≤ 65535`; require host to be a parseable IP or pass `ValidateDomain`.
- Validation: tests — `host:99999` and `foo:123` rejected; `example.com:80`, `1.2.3.4:443`, `[::1]:8443` accepted.

**2.2 Nuclei matched-at fallback (F8)**
- What: `if result.MatchedAt == "" { result.MatchedAt = result.Host }` before insert.
- Validation: test — two same-template findings with empty `matched-at` and different hosts both stored.

**2.3 Ffuf count semantics + scope check (F9)**
- What: increment `count` only when at least one insert succeeds; apply `isURLInScope` when `getTargetDomain(scanID)` returns non-empty.
- Validation: test — out-of-scope ffuf URL skipped; count reflects stored rows.

**2.4 Small consistency batch (F10)**
- What: `scanJSONLines` skips whitespace-only lines (`TrimSpace`); `ParseLiveURLsFile` dedup key lowercased.
- Validation: existing tests keep passing; add whitespace-line case.

### Phase 3 — P2 (optional, only if approved)

**3.1 Batch tlsx SAN inserts (F11)**
- What: collect in-scope unique SANs during scan; one `AddSubdomains` call after the loop.
- Risk: `newSubs` counts unique SANs seen, not rows inserted (INSERT OR IGNORE) — document in the return-value comment.
- Deferred by default, per the package header's "defer optimizations unless profiling shows a hot path" note.

### Phase 4 — Tests

- Extend `test/utils/utils_test.go` (existing `setupTestDB` pattern, target `example.com`) with one regression test per finding: F1-F10. No new test infrastructure needed.
- Keep parser tests in the same file/package as the existing ingest tests (project convention).

### Phase 5 — Validation baseline

```bash
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && gofmt -w ."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && golangci-lint run ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go build -buildvcs=false -o chaathan ."
```

---

## 3. Explicitly out of scope

- Bulk-insert APIs for URLs/ports/endpoints (per-line `Exec` → batched txns) — performance-only, needs profiling first.
- Streaming decode of ffuf's single-JSON output — same rationale (package header note).
- Changing any `Parse*` signature or DB row shape — both are product surfaces (AGENTS.md rule 5); all fixes are internal to `pkg/ingest/parser.go`.
- CLI flags, scan steps, workflow ordering — untouched, so no SKILL.md/README sync expected (re-verify at the end per AGENTS.md meta-rule).

---

## 4. Execution order

```
Phase 1 (F1-F6)  →  six independent single-file fixes, land together
Phase 2 (F7-F10) →  consistency batch
Phase 4          →  regression tests alongside each phase
Phase 5          →  gofmt / test / lint / build via WSL
Phase 3 (F11)    →  optional, last, only if approved
```
