# Phase 0 Baseline Report — Chaathan Code Quality Scan

**Status: measurement complete. No fixes applied. No tools installed.**

| | |
|---|---|
| Date | 2026-07-25 |
| Commit | `dd7897c` (working tree **dirty** — 8 modified files, 1 untracked plan doc) |
| Environment | WSL, Go 1.26.5 linux/amd64, no gcc, CGO unavailable |
| Parent plan | `CODE_REVIEW_PLAN.md` (Phase 0) |
| Scope | All 115 tracked Go files + non-Go artifacts |

---

## 1. Gate results

| Gate | Result | Detail |
|------|--------|--------|
| `go build -buildvcs=false` | **PASS** | clean |
| `go vet ./...` | **PASS** | clean, zero diagnostics |
| `gofmt -l .` | **57 files flagged** | 14 files CRLF whole-file rewrites; ~43 files trivial whitespace only (trailing spaces on blank lines, doubled blank lines) |
| `go test ./...` | **17 packages PASS, 4 packages FAIL, rest `[no test files]` (by design)** | all 4 failures share one environmental cause (below) |

### Test failures — environmental, not code defects
All 11 failing tests in `test/pkg/database`, `test/pkg/report`, `test/pkg/tui`, `test/utils` fail with:
`go-sqlite3 requires cgo to work. Binary was compiled with 'CGO_ENABLED=0'`.
WSL has no gcc, so `CGO_ENABLED=1` cannot build either (`gcc not found`). **Consequence: DB-backed tests are unrunnable in the current environment**, and `make test` (uses `-race`, which also needs cgo) is blocked too.

### gofmt breakdown (verified by diff inspection)
- **14 CRLF files**: `main.go`, `pkg/database/database.go`, `pkg/setup/{gf_patterns,massdns,prereqs,seclists,x8}.go`, `pkg/tools/tools.go`, `pkg/wildcard_flow/{content_discovery,fingerprinting,flow,helpers,proxy_scraping,validation}.go`
- **43 whitespace-only files**: trailing spaces / extra blank lines (e.g. `cli/query.go:382` double blank, `utils/parser.go` trailing spaces)
- Root cause enabler: **no `.gitattributes`, `core.autocrlf` unset** → CRLF will keep recurring.

## 2. Lint/static-analysis tool availability

| Tool | Status | Note |
|------|--------|------|
| `gofmt`, `go vet` | available (toolchain) | used for this baseline |
| `golangci-lint` | **not installed** | referenced by `Makefile lint` target; no `.golangci.yml` config in repo |
| `staticcheck`, `gocyclo`, `dupl`, `deadcode` | **not installed** | pending maintainer approval (Phase 0 step 2 of parent plan) |

## 3. Repository size & complexity baseline

**Totals (115 Go files):** 24,833 LOC · 823 functions · 4,390 decision points (`if/for/case/&&/||`)

### Complexity leaderboard (top 15 by decision points)

| Decisions | LOC | Funcs | File |
|-----------|-----|-------|------|
| 360 | 1486 | 21 | `pkg/wildcard_flow/content_discovery.go` |
| 313 | 1357 | 43 | `pkg/tui/query_console.go` |
| 238 | 1027 | 27 | `pkg/database/roi.go` |
| 216 | 1279 | 46 | `pkg/database/database.go` |
| 190 | 798 | 19 | `utils/parser.go` |
| 182 | 999 | 92 | `pkg/tools/tools.go` |
| 147 | 675 | 32 | `pkg/wildcard_flow/helpers.go` |
| 116 | 561 | 10 | `pkg/wildcard_flow/vulnerability_scanning.go` |
| 107 | 473 | 5 | `pkg/wildcard_flow/validation.go` (5 funcs — avg 21 decisions/func) |
| 104 | 695 | 29 | `pkg/notify/notify.go` |
| 101 | 669 | 9 | `pkg/wildcard_flow/flow.go` |
| 87 | 517 | 19 | `test/utils/utils_test.go` |
| 79 | 460 | 5 | `pkg/tui/dashboard.go` |
| 68 | 572 | 11 | `pkg/report/report.go` |
| 66 | 333 | 8 | `pkg/metadata/collector.go` |

## 4. Signal heatmap (measured, regex-based counts)

### 4.1 `fmt.Print*` — 93 occurrences, 9 files (C7)
| Count | File | Initial read |
|-------|------|--------------|
| 25 | `cli/tools_cmd.go` | CLI table output — disposition: logger vs direct |
| 14 | `cli/scans.go` | same |
| 14 | `pkg/progress/progress.go` | progress bars — likely by design, verify |
| 13 | `cli/query.go` | tabwriter output |
| 11 | `cli/root.go` | |
| 10 | `cli/diff.go` | |
| 3 | `cli/status.go` | |
| 2 | `cli/config.go` | |
| 1 | `cli/helpers.go` | |

### 4.2 Ignored errors (`_ =`) — 77 occurrences, 25 files (C1)
Top sites: `pkg/setup/go_installer.go` (8), `pkg/wildcard_flow/content_discovery.go` (8), `pkg/database/database.go` (8), `pkg/wildcard_flow/validation.go` (6), `pkg/proxy_scraping/scraping.go` (6), `pkg/runner/runner.go` (5), `pkg/logger/logger.go` (4).

### 4.3 Package-level `var` — 116 declarations, 40 files (C6/design)
Top: `cli/query.go` (8), `cli/config.go` (7), `cli/scans.go` (6), `cli/delete.go` (6) — mostly cobra flag vars (expected); `test_exports.go` files hold 15 (`pkg/setup` 8, `pkg/wildcard_flow` 7); `pkg/logger/logger.go` (4) — check for mutable global state.

### 4.4 TODO/FIXME — **4 real** (the `XXX` token in `\uXXXX` comments caused 7 false positives in the raw grep)
1. `pkg/database/roi.go:69` — full-scan memory load, scaling concern
2. `pkg/tools/tools.go:112` — hardcoded User-Agent pool aging
3. `pkg/tools/tools.go:822` — missing `General.HakrawlerTimeout` config field
4. `pkg/tools/tools.go:1056` — fofa support blocked on `APIKeysConfig` field

### 4.5 `panic` — 1
`pkg/paths/paths.go:53` — deliberate "used before Init()" guard. Candidate for error-return refactor; low priority.

### 4.6 `time.Sleep` — 6 (4 in production)
`pkg/notify/notify.go:654` (retry backoff — legitimate), `pkg/proxy_scraping/rotator.go:227` (200ms poll — review), `pkg/update/update.go:54,61` (2s ×2 — review), 2 in `test/pkg/progress/progress_test.go` (acceptable).

### 4.7 `context.Context` adoption — 18 of 115 files
Notably absent from most of `pkg/wildcard_flow`, `pkg/company_flow`, `pkg/setup`, `pkg/report` — propagation audit scheduled as Sweep S7.

### 4.8 Exported-symbol doc-comment coverage — **66.8%** (506/757, approximate: preceding-line heuristic)
Worst files (≥5 exported): `cli/scans.go` 0/6, `cli/root.go` 0/5, `cli/query.go` 0/7, `cli/delete.go` 0/6, `cli/config.go` 1/8, `pkg/config/config.go` 9/30, `pkg/database/roi.go` 10/31, `pkg/tui/query_console.go` 21/44, `pkg/runner/runner.go` 11/25.

## 5. Test-suite inventory

- **17 test packages pass**: cli, company_flow, config, logger, metadata, notify, orchestrate, paths, progress, proxy_scraping, runner, scan, scope, setup, tools, update, wildcard_flow
- **4 blocked by cgo** (§1): database, report, tui, utils — coverage of the **highest-complexity packages is currently unverifiable**
- `pkg/tools/export_test.go` compiles with `[no tests to run]` — only in-package test file; placement anomaly vs `test/` convention
- Thin test files relative to source size (flagged for Phase 4/5): `content_discovery_test.go` 75 LOC vs 1486 source; `vulnerability_scanning_test.go` 62 vs 561; `query_console_test.go` 68 vs 1357; `cli_test.go` 26 LOC for 14 commands

## 6. Findings log (initialized — all dispositions pending, no fixes applied)

| ID | Category | Severity | Finding |
|----|----------|----------|---------|
| F-001 | C8 fmt | minor | 43 files with whitespace-only gofmt violations |
| F-002 | C8 fmt | major | 14 files with CRLF endings; no `.gitattributes`, autocrlf unset — will recur |
| F-003 | env | major | DB-backed tests unrunnable (CGO off, no gcc); blocks `make test` (`-race` needs cgo) |
| F-004 | C7 logging | pending | 93 `fmt.Print*` in 9 files (79 in `cli/`, 14 in `pkg/progress`) |
| F-005 | C1 errors | pending | 77 ignored errors in 25 files; worst: go_installer, content_discovery, database (8 each) |
| F-006 | C6 state | pending | 116 package-level vars in 40 files; audit for hidden mutable state |
| F-007 | debt | minor | 4 real TODOs (roi.go:69, tools.go:112/822/1056) |
| F-008 | C1 errors | nit | panic guard at `pkg/paths/paths.go:53` |
| F-009 | C6 sync | nit | 2 reviewable prod sleeps (rotator.go:227, update.go:54/61) |
| F-010 | C6 ctx | pending | context.Context in only 18/115 files |
| F-011 | C9 docs | pending | 66.8% exported-symbol doc coverage; `cli/` ~0% |
| F-012 | C2 complexity | pending | 6 files exceed both 550 LOC and 100 decision points (§3) |
| F-013 | hygiene | minor | baseline taken on dirty tree (8 modified files) — commit before Phase 1 fixes |
| F-014 | tooling | minor | `Makefile lint` references golangci-lint; not installed, no config file |
| F-015 | C11 tests | nit | `pkg/tools/export_test.go` placement anomaly, zero test funcs |

## 7. Open decisions for maintainer (required before Phase 1)

1. **gcc in WSL**: install (`apt install gcc`) to unblock 4 cgo test packages + `-race`? — *environment change, needs approval*
2. **Linters**: approve isolated install of `staticcheck`/`gocyclo`/`dupl`, or adopt `golangci-lint` with a repo config?
3. **CRLF policy**: add `.gitattributes` (`*.go text eol=lf`) + one-time normalize, or leave to editors?
4. **Dirty tree**: commit/stash the 8 modified files before any Phase 1 fix lands (keeps fix diffs attributable).

## 8. Phase 1 entry checklist

- [ ] Decisions §7.1–7.4 answered
- [ ] Baseline re-run green after environment fixes (if any)
- [ ] Findings-log severities confirmed
- [ ] Begin `CODE_REVIEW_PLAN.md` Phase 1 file checklist (21 files: `main.go`, `utils/`, `paths`, `logger`, `progress`, `config` + tests)
