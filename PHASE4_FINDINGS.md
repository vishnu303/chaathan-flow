# Phase 4 Findings Report — Orchestration & Workflows

**Status: scan complete. No fixes applied.** Continues `CODE_REVIEW_PLAN.md` Phase 4; IDs continue from `PHASE2_FINDINGS.md` (F-081…F-085).

| | |
|---|---|
| Date | 2026-07-25 |
| Scope | 26 files: `pkg/orchestrate` (1), `pkg/wildcard_flow` (9), `pkg/company_flow` (4), `pkg/proxy_scraping` (3); tests: orchestrate (1), company_flow (1), wildcard_flow (6), proxy_scraping (1) |
| Method | Full manual read + repo-wide compilation verification + targeted verification greps |
| Note | Findings are evaluated against the current state of the repository (with Phase 1 & 2 fixes applied). |

---

## 1. Dead code — verified (C10)

No dead functions or variables were found in the Phase 4 production or test-export packages. All exported symbols in `test_exports.go` files are actively consumed by the unit test suite.

---

## 2. Major findings

| ID | Cat | Location | Finding |
|----|-----|----------|---------|
| F-086 | C6 | `pkg/wildcard_flow/flow.go:294-311` | **Stdin-listening goroutine leak in `Run()`.** The background goroutine spawned to listen for skip requests ('s'/'S') blocks indefinitely on `os.Stdin.Read(buf)`. When `Run()` completes or is cancelled, this goroutine remains blocked forever. Every scan or test execution leaks a goroutine. |
| F-087 | C5 | `pkg/wildcard_flow/vulnerability_scanning.go:559-570` | **Socket and goroutine leak in `ValidateTakeoverCandidate`.** A new `http.Transport` and `http.Client` are allocated for *every* candidate host validated. However, `transport.CloseIdleConnections()` is never called. This leaves connection pools and internal dialer goroutines alive in memory. |
| F-088 | C5 | `pkg/wildcard_flow/content_discovery.go:984-997` | **Connection leak in `runInMemoryJSSecretScan`.** Similar to F-087, the `http.Transport` created at the start of the in-memory JS scanner does not close its idle connections upon function exit. A `defer transport.CloseIdleConnections()` is missing. |
| F-089 | C2/C5 | `pkg/wildcard_flow/content_discovery.go:1089-1168` | **CPU/Memory exhaustion risk on minified JavaScript files.** In `runInMemoryJSSecretScan`, scanning a single-line minified JS file of up to 10MB via `re.FindAllStringSubmatchIndex` on a single giant line blocks the worker thread and consumes excessive CPU. There is no maximum line length check or truncation. |

---

## 3. Minor findings

| ID | Cat | Location | Finding |
|----|-----|----------|---------|
| F-090 | C1 | Multiple files | **Swallowed `Close()` errors on write handles.** In `pkg/wildcard_flow/helpers.go` (`copyFile`, `CollectScopedURLs`, `collectLiveHostTargetsFromHttpx`, `collectROIMetadataTargetsFromFile`, `extractUncoverHosts`, `filterCNAMESubdomains`) and `pkg/wildcard_flow/content_discovery.go` (`stepParamDiscovery`, `stepDirFuzzing`), files are created and closed via deferred `Close()` without checking the error. Failed disk flushes go unreported. |
| F-091 | C8/C1 | `pkg/wildcard_flow/content_discovery.go:1070-1074` | **Non-200 responses are parsed as JS files.** If fetching a JavaScript URL returns `404 Not Found` or `500 Internal Server Error`, the scanner still reads its HTML body (up to 10MB) and runs regexes. It should assert `resp.StatusCode == http.StatusOK` before parsing. |
| F-092 | C6/C8 | `pkg/wildcard_flow/helpers.go:140-148` | **Infinite loop risk in `drainSkipSignal`.** If `SkipChan` is ever closed, `<-c.SkipChan` returns immediately, causing `drainSkipSignal` to loop infinitely and consume 100% CPU. Add a comma-ok check to return if closed. |
| F-093 | C6 | `pkg/orchestrate/orchestrate.go:81-94` | **`HandleSignals` lacks double-interrupt force termination.** If the scan hangs during graceful shutdown, a second Ctrl+C does not force-terminate the process. |

---

## 4. Test findings (C11)

| ID | Severity | Location | Finding |
|----|----------|----------|---------|
| F-094 | minor | Multiple test files | **OS temp dir pollution.** `test/pkg/proxy_scraping/proxy_test.go` and `test/pkg/wildcard_flow/helpers_test.go`, `resolvers_test.go` use `os.MkdirTemp` and `os.RemoveAll` instead of `t.TempDir()`. |
| F-095 | minor | `test/pkg/wildcard_flow/` | **Low test coverage.** `content_discovery.go` has 1671 LOC of crawl, parameter discovery, and secret scanning logic, but `content_discovery_test.go` only tests `FilterAndDeduplicateHosts`. `validation.go` (527 LOC) is only covered by `resolvers_test.go`. |

---

## 5. Clean files (no findings)

- `pkg/wildcard_flow/proxy_scraping.go` — Clean; well-integrated with mubeng and harvester.
- `pkg/company_flow/asn_discovery.go`, `cloud_enum.go`, `domain_discovery.go` — Clean; simple Cobra flow shims.
- `pkg/proxy_scraping/test_exports.go`, `pkg/wildcard_flow/test_exports.go` — Clean; minimal, strictly scoped.
- `test/pkg/company_flow/flow_test.go`, `test/pkg/orchestrate/orchestrate_test.go` — Clean.

---

## 6. Phase 4 exit-criteria check (from CODE_REVIEW_PLAN)

| Criterion | Status | Notes |
|-----------|--------|-------|
| Every step function audited for rule-6 compliance | ✅ PASS | All 23 wildcard flow and 3 company flow step functions return `c.cancelled()` on exit/failure and use `markStepCompleteIfNoFailure` or conditional branches correctly. |
| `content_discovery.go` and `helpers.go` decomposition decided | ✅ PASS | Decided to split `content_discovery.go` into modular step files (crawling, js_endpoints, fuzzing, parameters, secrets, consolidation). Shared file utility helpers in `helpers.go` will be promoted to `utils/`. |
| Flow-level shared scaffolding deduplicated | ✅ PASS | Already use `orchestrate.NewInfra` and `orchestrate.HandleSignals`. Further generalization is unnecessary due to distinct step registry and resume semantics. |

---

## 7. Suggested fix order (when implementation is approved)

1. **F-086** (Stdin leak) — Stop the stdin-reading goroutine using a done/cancel channel when the scan exits.
2. **F-087 & F-088** (Connection leaks) — Close idle connections on `http.Transport` instances to clean up background socket descriptors.
3. **F-089** (Minified JS CPU hog) — Truncate or skip processing very long lines in downloaded JS files.
4. **F-091 & F-092** (HTTP check + loop risk) — Assert 200 OK and fix closed channel check in `drainSkipSignal`.
5. Nits: F-090, F-093, F-094, F-095.
