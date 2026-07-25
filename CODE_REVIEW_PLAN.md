# Chaathan Code Quality Scan Plan

A phase-wise, file-wise review plan for finding **code-quality issues and improving coding practices** across the entire codebase. **Security issues are explicitly out of scope.**

- Total files in scope: **115 tracked files** (108 Go, 7 non-Go)
- Review order follows the dependency graph (leaf packages first) so foundational fixes land before the packages that depend on them are reviewed.
- Every phase has: objective → mechanical checks → file checklist → manual review focus → exit criteria.

---

## Check taxonomy (applied to every file)

| # | Category | What to look for |
|---|----------|------------------|
| C1 | Error handling | Ignored errors (`_ =`), unwrapped errors, swallowed `err` returns, missing sentinel errors |
| C2 | Function quality | Over-long functions (>80 lines), deep nesting (>4), high cyclomatic complexity, multiple responsibilities |
| C3 | Duplication | Copy-pasted blocks, repeated literals, near-identical functions across files |
| C4 | Architecture fit | Violations of `AGENTS.md` rules: business logic in `cli/`, orchestration outside workflow packages, concern leakage across owners |
| C5 | Resource management | Missing `defer Close()`, unclosed files/rows/HTTP bodies, goroutine leaks, missing `WaitGroup`/channel hygiene |
| C6 | Concurrency & context | Shared state without sync, missing `context.Context` propagation (only 18 files use it today), `time.Sleep` as synchronization |
| C7 | Logging consistency | `fmt.Print*` bypassing `pkg/logger` (93 occurrences repo-wide), mixed output styles |
| C8 | Idiomatic Go | Naming, early returns over else-chains, interface placement, `gofmt`/`goimports` cleanliness, magic numbers/strings vs `utils/constants.go` |
| C9 | API & docs | Exported symbols without doc comments, stale comments, misleading names |
| C10 | Dead code | Unused functions/vars/imports, unreachable branches, leftover debug code |
| C11 | Test quality | Missing table tests, untested error paths, `test_exports.go` surface minimality, fixture hygiene |
| C12 | Docs sync | `AGENTS.md` meta-rule #7: README/skills/AGENTS.md drift from implementation |

## Baseline signals already measured (Phase 0 output)

| Signal | Count | Primary hunt grounds |
|--------|-------|----------------------|
| `go vet ./...` | **clean** | — |
| `fmt.Print*` | 93 | `pkg/logger`, `cli/`, `pkg/tui` expected; flag elsewhere |
| Ignored errors (`_ =`) | 77 | audit each for intent |
| Package-level `var` | 77 | check for hidden mutable global state |
| `TODO/FIXME/HACK` | 10 | resolve or ticket |
| `panic(` | 1 | must not exist in library code |
| `time.Sleep(` | 6 | replace with proper sync/polling |
| Largest files | `content_discovery.go` 1486, `query_console.go` 1357, `database.go` 1279, `roi.go` 1027, `tools.go` 999 | C2/C3 splitting candidates |
| Most functions | `tools.go` 92, `database.go` 46, `query_console.go` 43, `helpers.go` 32, `notify.go` 29 | C2/C3 |

## Standard commands (run per phase, via WSL)

```bash
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && gofmt -l <paths> && go vet ./<pkg>/... && go test ./test/<pkg>/..."
# Optional deeper analysis if approved:
#   staticcheck ./...   gocyclo -over 15 .   deadcode ./...   dupl -t 60 .
```

---

## Phase 0 — Baseline & tooling (no file review)

**Objective:** freeze measurable starting point; decide which linters are allowed.

1. Record `go vet`, `gofmt -l .`, `go test ./...` results (vet already clean).
2. Get maintainer approval before installing `staticcheck`, `gocyclo`, `dupl`, `deadcode` — install only into an isolated `GOBIN`.
3. Record per-file LOC + function counts (already captured above) as the complexity leaderboard.
4. Create the findings log (template at bottom of this doc).

**Exit criteria:** baseline metrics committed to the findings log; tool allow-list agreed.

---

## Phase 1 — Foundations (leaf packages, zero/low internal deps)

**Objective:** fix the foundation layer everything else imports. Small files, fast wins. Focus: C1, C8, C9, C10.

| File | LOC | Review focus |
|------|-----|--------------|
| `main.go` | 29 | Init order, deferred DB close correctness, error exit codes |
| `utils/constants.go` | 152 | Are constants actually used; orphan constants; grouping/naming |
| `utils/file.go` | 276 | C1: every `os.Open/Write` error path; C5: all handles closed; dedupe read/write helpers |
| `utils/parser.go` | 798 | C2: biggest `utils` file — look for splittable parser families; C3: repeated scan/tokenize loops |
| `utils/export.go` | 315 | C3 vs `pkg/report` export paths; error wrapping on I/O |
| `utils/format.go` | 57 | Pure functions — verify nil-safety |
| `utils/validate.go` | 48 | Single canonical validators vs duplicates in `cli/` |
| `utils/tls.go` | 33 | Config defaults sanity; error returns (not security review — just error shape) |
| `pkg/paths/paths.go` | 76 | C8: path-join idiom (`filepath.Join`), env overrides honored consistently |
| `pkg/paths/test_helpers.go` | 8 | Minimal surface |
| `pkg/logger/logger.go` | 478 | C2: 27 funcs — check style/format duplication; C7: is this the only place that should print? |
| `pkg/logger/colors.go` | 68 | Color-disable path; constants vs `utils/constants.go` overlap |
| `pkg/logger/test_exports.go` | 12 | Minimal surface |
| `pkg/progress/progress.go` | 246 | C6: spinner goroutine lifecycle, stop-channel leaks |
| `pkg/progress/test_exports.go` | 2 | Minimal surface |
| `pkg/config/config.go` | 626 | C2: 12 funcs but large struct work — defaults merging duplication; C1: YAML decode errors; validate defaults vs docs |
| `test/utils/utils_test.go` | 517 | C11: table-test coverage of parser/file edge cases |
| `test/pkg/paths/paths_test.go` | 67 | C11 |
| `test/pkg/logger/logger_test.go` | 157 | C11 |
| `test/pkg/progress/progress_test.go` | 102 | C11: goroutine-leak assertions present? |
| `test/pkg/config/config_test.go` | 87 | C11 |

**Exit criteria:** zero unhandled errors in `utils/`; no `fmt.Print*` outside logger; constants deduplicated; tests green.

---

## Phase 2 — Execution core (runner, tools, setup)

**Objective:** review how external commands are built, executed, retried, and installed. Focus: C1, C2, C3, C5, C8.

| File | LOC | Review focus |
|------|-----|--------------|
| `pkg/runner/runner.go` | 383 | C2: 18 funcs — retry loop clarity; C5: stdout/stderr pipe draining (deadlock risk); C6: context cancellation honored; docker vs host path duplication (C3) |
| `pkg/tools/tools.go` | 999 | **Top C2/C3 target**: 92 funcs in one file — split per-tool wrappers into sub-files; repeated flag-building patterns → table-driven registry |
| `pkg/tools/registry.go` | 94 | Single source of truth for tool metadata; drift vs `tools.go` |
| `pkg/tools/vulnerability_engine.go` | 164 | C8: severity mapping as constants; error propagation |
| `pkg/tools/test_helpers.go` | 19 | Minimal surface |
| `pkg/tools/export_test.go` | 1 | **Placement anomaly**: only in-package test file in repo (convention is `test/`) — keep or relocate deliberately |
| `pkg/setup/setup.go` | 120 | Orchestration of installers; failure aggregation pattern |
| `pkg/setup/prereqs.go` | 263 | C3: repeated check/install blocks → unify |
| `pkg/setup/go_installer.go` | 275 | C1: download/verify error paths; C5: temp-file cleanup |
| `pkg/setup/go_tools.go` | 104 | Table-driven install list vs hardcoded |
| `pkg/setup/python_tools.go` | 147 | Same shape as `go_tools.go` — dedupe opportunity (C3) |
| `pkg/setup/massdns.go` | 83 | Build-from-source error handling |
| `pkg/setup/seclists.go` | 78 | Download cleanup, partial-failure state |
| `pkg/setup/gf_patterns.go` | 104 | C3 with seclists download logic |
| `pkg/setup/x8.go` | 111 | C3 with go_installer logic |
| `pkg/setup/http.go` | 47 | Shared HTTP helper — is it used by all downloaders (C3)? |
| `pkg/setup/log.go` | 100 | C7: should delegate to `pkg/logger` |
| `pkg/setup/sys_linux.go` / `sys_other.go` | 13/5 | Build-tag parity: both files must export identical symbols |
| `pkg/setup/test_exports.go` | 14 | Minimal surface |
| `test/pkg/runner/runner_test.go` | 56 | C11: retry/timeout paths covered? |
| `test/pkg/runner/runnerfaketest/runnerfake.go` | 37 | Fake fidelity vs real runner interface |
| `test/pkg/tools/tools_test.go` | 338 | C11 |
| `test/pkg/tools/vulnerability_engine_test.go` | 27 | C11: thin — flag coverage gap |
| `test/pkg/tools/out.txt` | — | Fixture: referenced? stale? |
| `test/pkg/setup/setup_test.go` | 58 | C11 |
| `test/pkg/setup/go_installer_test.go` | 108 | C11 |
| `test/pkg/setup/prereqs_test.go` | 94 | C11 |
| `test/pkg/setup/python_tools_test.go` | 47 | C11 |

**Exit criteria:** `tools.go` decomposed or explicitly justified; all installers share one download/verify helper; pipe-draining verified deadlock-free.

---

## Phase 3 — Data layer (database, scan state, scope, metadata)

**Objective:** persistence correctness, query quality, and state-machine integrity. Focus: C1, C2, C4, C5, C8.

| File | LOC | Review focus |
|------|-----|--------------|
| `pkg/database/database.go` | 1279 | **C2 target**: 46 funcs — split by entity (scans/subs/vulns/ports/urls); C5: every `Query` has `rows.Close()`; C3: repeated scan-loop→struct code → generic row mapper; transaction usage consistency |
| `pkg/database/roi.go` | 1027 | **C2 target**: 27 funcs of scoring logic — extract weight tables to constants; C3 in score computation branches |
| `pkg/database/metadata.go` | 267 | C3 vs `database.go` insert patterns |
| `pkg/database/test_exports.go` | 9 | Minimal surface |
| `pkg/scan/scan.go` | 308 | C4: step state machine — verify `MarkStepComplete`-after-`MarkStepFailed` invariant (AGENTS.md rule 6); C8: step list as data not code |
| `pkg/scope/scope.go` | 204 | C8: matcher clarity; C1 on regex compile; dedupe inclusion/exclusion paths (C3) |
| `pkg/metadata/collector.go` | 333 | C5: response bodies closed on all paths; C6: context timeouts; C3 in header parsing |
| `pkg/metadata/test_exports.go` | 6 | Minimal surface |
| `test/pkg/database/database_test.go` | 184 | C11: rollback paths tested? |
| `test/pkg/scan/scan_test.go` | 153 | C11: state-transition table test |
| `test/pkg/scope/scope_test.go` | 217 | C11 |
| `test/pkg/metadata/collector_test.go` | 183 | C11 |

**Exit criteria:** every DB read closes rows; scan state machine has explicit transition table test; ROI weights externalized.

---

## Phase 4 — Orchestration & workflows (the scan pipelines)

**Objective:** the heart of the product — 23-step wildcard flow and 3-step company flow. Focus: C2, C3, C4, C5, C6. Respect `AGENTS.md` rule 6 (step functions return `c.cancelled()`).

| File | LOC | Review focus |
|------|-----|--------------|
| `pkg/orchestrate/orchestrate.go` | 86 | Signal handling correctness; infra bootstrap ordering; error propagation from runner/toolbox/notifier init |
| `pkg/wildcard_flow/flow.go` | 669 | C2: step sequencing clarity — step registry as table; C4: no tool-exec details here (belongs in `pkg/tools`) |
| `pkg/wildcard_flow/content_discovery.go` | 1486 | **Biggest file in repo — top C2/C3 target**: 21 funcs; split into crawl/params/secrets/js sub-files; dedupe per-host loops |
| `pkg/wildcard_flow/helpers.go` | 675 | **C3 target**: 32 funcs named "helpers" is a smell — redistribute to owning files or promote to `utils/` |
| `pkg/wildcard_flow/validation.go` | 473 | C3: dedupe validate/sanitize chains; C1 on DNS/HTTP errors |
| `pkg/wildcard_flow/asset_discovery.go` | 309 | C2: per-source loops → uniform source-runner abstraction |
| `pkg/wildcard_flow/vulnerability_scanning.go` | 561 | C2: 10 large funcs; C3 in nuclei/x8 orchestration vs `pkg/tools/vulnerability_engine.go` boundary (C4) |
| `pkg/wildcard_flow/fingerprinting.go` | 183 | C1: probe error handling; C8 |
| `pkg/wildcard_flow/proxy_scraping.go` | 144 | C4: thin wrapper — should only adapt `pkg/proxy_scraping`, no logic |
| `pkg/wildcard_flow/test_exports.go` | 23 | Largest test-export surface — justify each export |
| `pkg/company_flow/flow.go` | 311 | C2: 3-step sequencing; C3 vs `wildcard_flow/flow.go` shared scaffolding — extract common flow runner? |
| `pkg/company_flow/asn_discovery.go` | 35 | C1 |
| `pkg/company_flow/cloud_enum.go` | 34 | C1 |
| `pkg/company_flow/domain_discovery.go` | 36 | C1 |
| `pkg/proxy_scraping/scraping.go` | 286 | C5: HTTP body closes; C6: rotation loop context; C1 on scrape parse errors |
| `pkg/proxy_scraping/rotator.go` | 218 | C6: shared proxy state synchronization; C8 |
| `pkg/proxy_scraping/test_exports.go` | 8 | Minimal surface |
| `test/pkg/orchestrate/orchestrate_test.go` | 67 | C11 |
| `test/pkg/company_flow/flow_test.go` | 34 | C11: thin — 3-step flow needs more |
| `test/pkg/wildcard_flow/content_discovery_test.go` | 75 | C11: low ratio vs 1486 LOC source — flag |
| `test/pkg/wildcard_flow/helpers_test.go` | 146 | C11 |
| `test/pkg/wildcard_flow/validation*` (resolvers_test.go) | 85 | C11 |
| `test/pkg/wildcard_flow/vulnerability_scanning_test.go` | 62 | C11: low vs 561 LOC — flag |
| `test/pkg/wildcard_flow/custom_auth_test.go` | 70 | C11 |
| `test/pkg/wildcard_flow/secret_scan_helpers_test.go` | 67 | C11 |
| `test/pkg/proxy_scraping/proxy_test.go` | 84 | C11 |

**Exit criteria:** every step function audited for rule-6 compliance; `content_discovery.go` and `helpers.go` decomposition decided; flow-level shared scaffolding deduplicated.

---

## Phase 5 — Presentation & delivery (report, notify, tui, cli)

**Objective:** output correctness and the "thin CLI" rule. Focus: C3, C4, C7, C8, C9.

| File | LOC | Review focus |
|------|-----|--------------|
| `pkg/report/report.go` | 572 | C3: per-format export branches → format-strategy map; C1 on file writes; C4: no DB queries here (belongs in `pkg/database`)? |
| `pkg/notify/notify.go` | 695 | **C3 target**: 29 funcs — Discord/Slack/Telegram senders share payload/retry logic → one webhook client; C1: notification failures must degrade gracefully; C7 |
| `pkg/notify/test_exports.go` | 8 | Minimal surface |
| `pkg/tui/query_console.go` | 1357 | **C2 target**: 43 funcs — split keybindings/render/query-execution; C4: SQL building in TUI? (belongs in `pkg/database`) |
| `pkg/tui/dashboard.go` | 460 | C2: render loop; C6: refresh goroutine lifecycle |
| `pkg/tui/test_exports.go` | 36 | Largest TUI export surface — justify |
| `pkg/update/update.go` | 189 | C1: version-check errors degrade silently by design?; C5: body close |
| `pkg/update/test_exports.go` | 3 | Minimal surface |
| `cli/root.go` | 166 | C4: PersistentPreRun only wires, no logic; flag registration consistency |
| `cli/wildcard.go` | 190 | C4: **flag parsing only** — any scan logic here violates rule 1 |
| `cli/company.go` | 100 | C4: same check |
| `cli/query.go` | 363 | C4: biggest cli file — formatting helpers OK, query logic must stay in `pkg/database` |
| `cli/scans.go` | 276 | C4: delegate to `pkg/scan` |
| `cli/tools_cmd.go` | 237 | C4: delegate to `pkg/tools`/`pkg/setup` |
| `cli/config.go` | 219 | C4: delegate to `pkg/config` |
| `cli/diff.go` | 202 | C3: diff rendering vs report formatting overlap |
| `cli/delete.go` | 196 | C1: confirmation-path errors |
| `cli/export.go` | 136 | C4: delegate to `utils/export.go` / `pkg/report` |
| `cli/status.go` | 117 | C4 |
| `cli/report.go` | 71 | C4 |
| `cli/setup.go` | 50 | C4 |
| `cli/helpers.go` | 65 | C3: shared flag-validation helpers actually shared? |
| `test/pkg/report/report_test.go` | 157 | C11 |
| `test/pkg/notify/notify_test.go` | 233 | C11 |
| `test/pkg/tui/query_console_test.go` | 68 | C11: low vs 1357 LOC — flag |
| `test/pkg/tui/dashboard_test.go` | 98 | C11 |
| `test/pkg/update/update_test.go` | 103 | C11 |
| `test/cli/cli_test.go` | 26 | C11: nearly empty — CLI has 14 commands; flag-parsing tests needed |

**Exit criteria:** zero business logic found in `cli/`; notify senders unified; TUI contains no SQL; `fmt.Print*` in cli only where logger is inappropriate (documented).

---

## Phase 6 — Cross-cutting sweeps (whole repo, after per-file passes)

**Objective:** catch what file-wise review misses. Each sweep is one focused `grep`/tool pass over all 108 Go files.

| Sweep | Command / method | Target |
|-------|------------------|--------|
| S1 Ignored errors | `git grep -n "_ = " -- '*.go'` | 77 sites — classify each: intentional (comment it) or bug (fix) |
| S2 Raw printing | `git grep -n "fmt\.Print" -- '*.go'` | 93 sites — route through `pkg/logger` where user-facing |
| S3 TODO debt | `git grep -nE "TODO\|FIXME\|HACK\|XXX"` | 10 sites — resolve or convert to issues |
| S4 panic | `git grep -n "panic("` | 1 site — replace with error return |
| S5 Sleep-sync | `git grep -n "time\.Sleep("` | 6 sites — replace with polling/condition |
| S6 Global state | `git grep -nE "^var " -- 'pkg/**/*.go'` | 77 sites — flag mutable package-level state |
| S7 Context coverage | `git grep -l "context\.Context"` | only 18 files — runner/flows/HTTP callers should accept ctx |
| S8 Duplication | `dupl -t 60 .` (if approved) | expect hits in setup installers, notify senders, DB row mappers |
| S9 Dead code | `deadcode ./...` + unused exported symbols | remove or justify |
| S10 Doc comments | `golint`-style pass on exported symbols | all exported types/funcs documented |
| S11 Constants drift | compare literals vs `utils/constants.go` | magic strings for step names, severities, file names |
| S12 Interface sanity | check `runner` fake vs real, notifier impls | consumer-defined interfaces, minimal surface |

**Exit criteria:** every sweep item dispositioned in the findings log (fix / wontfix-with-reason).

---

## Phase 7 — Non-Go artifacts & documentation sync

**Objective:** repo hygiene and `AGENTS.md` meta-rule #7 compliance.

| File | Review focus |
|------|--------------|
| `Makefile` | Targets match AGENTS.md validation baseline; Windows/WSL notes accurate; no dead targets |
| `go.mod` | Minimal direct deps; no replace directives left behind; Go version current |
| `go.sum` | Verify via `go mod tidy` diff = empty |
| `.gitignore` | Covers built `chaathan` binary, `~/.chaathan` artifacts, temp files |
| `README.md` | Flags/commands match `cli/*` `--help` output; scan-step counts match `pkg/scan` |
| `AGENTS.md` | Repo tree matches reality (note: tree says `chaathan-flow/` header, repo is `chaathan`); package list complete (`pkg/tui`, `pkg/update` present in tree? verify) |
| `Fireprox_plan.md` | Stale planning doc? Archive, implement, or delete — decide |
| `.agents/skills/chaathan-architecture-principles/SKILL.md` | Sync with any rule changes found during review |
| `.agents/skills/chaathan-code-review/SKILL.md` | Sync |
| `.agents/skills/chaathan-dev/SKILL.md` | Sync |
| `.agents/skills/chaathan-recon-workflows/SKILL.md` | Step counts/flags match `pkg/wildcard_flow`, `cli/wildcard.go` |
| `.agents/skills/chaathan-reporting-query/SKILL.md` | Match `cli/query.go`, `pkg/database/roi.go` |
| `.agents/skills/chaathan-tooling-setup/SKILL.md` | Match `pkg/setup`, `cli/tools_cmd.go` |

**Exit criteria:** `go mod tidy` clean; every doc claim spot-verified against code; stale docs updated or removed.

---

## Execution order & effort estimate

| Phase | Files | Effort | Depends on |
|-------|-------|--------|------------|
| 0 Baseline | — | 0.5 day | — |
| 1 Foundations | 21 | 1 day | 0 |
| 2 Execution core | 25 | 1.5 days | 1 |
| 3 Data layer | 12 | 1 day | 1 |
| 4 Workflows | 20 | 2 days | 2, 3 |
| 5 Presentation | 25 | 1.5 days | 3, 4 |
| 6 Cross-cutting sweeps | all | 1 day | 1–5 |
| 7 Docs & repo hygiene | 14 | 0.5 day | all |

Rules for execution:
1. **One phase = one review pass = one findings batch.** Don't fix across phases mid-review.
2. Fixes from earlier phases that change an interface require re-checking dependent files in later phases.
3. Every fix must pass the AGENTS.md baseline: `go test ./...`, `go vet ./...`, `go build -buildvcs=false -o chaathan .`.
4. Docs touched by any fix get updated in the same commit (meta-rule #7).

## Findings log template

```
| ID | Phase | File:line | Category | Severity (nit/minor/major) | Finding | Disposition (fix/wontfix) | Commit |
|----|-------|-----------|----------|----------------------------|---------|---------------------------|--------|
| F-001 | 2 | pkg/runner/runner.go:120 | C5 | major | stderr pipe not drained before Wait | fix | abc123 |
```
