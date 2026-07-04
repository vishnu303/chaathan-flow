# Full Codebase Scan Plan — Chaathan

A systematic, phase-wise audit of every source file in the repository. Each phase targets a distinct architectural layer, with specific checklist items based on the [code review skill](file:///c:/Users/vishn/Desktop/chaathan/.agents/skills/chaathan-code-review/SKILL.md) priority matrix.

**Total files: ~60 Go source files + 2 test files + build/config files**

---

## Phase 0 — Entrypoint & Build Infrastructure _(4 files)_

| # | File | What to check |
|---|------|---------------|
| 1 | [main.go](file:///c:/Users/vishn/Desktop/chaathan/main.go) | Init ordering (`paths.Init` → defer `database.Close` → `cli.Execute`), no business logic, no `os.Exit` outside Cobra |
| 2 | [go.mod](file:///c:/Users/vishn/Desktop/chaathan/go.mod) | Dependency freshness, module path correctness, Go version |
| 3 | [go.sum](file:///c:/Users/vishn/Desktop/chaathan/go.sum) | Consistency with go.mod (verify via `go mod verify`) |
| 4 | [Makefile](file:///c:/Users/vishn/Desktop/chaathan/Makefile) | Build targets, `-buildvcs=false` flag, test/vet/install targets |

**Checks:**
- [ ] `paths.Init()` is called before any file I/O
- [ ] `database.Close()` is deferred after open
- [ ] No `os.Exit()` in packages (only main/Cobra)
- [ ] Build commands use correct flags

---

## Phase 1 — CLI Layer _(14 files)_

All files in [cli/](file:///c:/Users/vishn/Desktop/chaathan/cli/).

| # | File | What to check |
|---|------|---------------|
| 1 | [root.go](file:///c:/Users/vishn/Desktop/chaathan/cli/root.go) | Global flags, `PersistentPreRun` init, version string, config binding |
| 2 | [wildcard.go](file:///c:/Users/vishn/Desktop/chaathan/cli/wildcard.go) | 23-step flags, `RunConfig` mapping, skip-flag correctness, flag types |
| 3 | [company.go](file:///c:/Users/vishn/Desktop/chaathan/cli/company.go) | 3-step flags, `RunConfig` mapping, argument validation |
| 4 | [setup.go](file:///c:/Users/vishn/Desktop/chaathan/cli/setup.go) | Tool installation flags, delegation to `pkg/setup` |
| 5 | [scans.go](file:///c:/Users/vishn/Desktop/chaathan/cli/scans.go) | Scan list/show/resume/delete subcommands, argument parsing |
| 6 | [query.go](file:///c:/Users/vishn/Desktop/chaathan/cli/query.go) | Query subcommands (subdomains/vulns/ports/urls/endpoints/roi), filter flags |
| 7 | [report.go](file:///c:/Users/vishn/Desktop/chaathan/cli/report.go) | Report format flags, delegation to `pkg/report` |
| 8 | [export.go](file:///c:/Users/vishn/Desktop/chaathan/cli/export.go) | Export format/path flags, delegation to `utils/export` |
| 9 | [delete.go](file:///c:/Users/vishn/Desktop/chaathan/cli/delete.go) | Data cleanup commands, confirmation prompts, safety checks |
| 10 | [diff.go](file:///c:/Users/vishn/Desktop/chaathan/cli/diff.go) | Scan comparison arguments, output formatting |
| 11 | [status.go](file:///c:/Users/vishn/Desktop/chaathan/cli/status.go) | Dashboard command, data fetch delegation |
| 12 | [config.go](file:///c:/Users/vishn/Desktop/chaathan/cli/config.go) | Config management subcommands, YAML read/write |
| 13 | [tools_cmd.go](file:///c:/Users/vishn/Desktop/chaathan/cli/tools_cmd.go) | Tools list/check subcommands, registry integration |
| 14 | [helpers.go](file:///c:/Users/vishn/Desktop/chaathan/cli/helpers.go) | Shared CLI helpers, input validation |

**Checks:**
- [ ] Every flag has correct type, default, and help text
- [ ] All flags propagated into `RunConfig` (no orphans)
- [ ] No business logic in CLI handlers — pure delegation to `pkg/`
- [ ] `Args` validation on every command (e.g., `cobra.ExactArgs`, `cobra.MinimumNArgs`)
- [ ] Help text accuracy for all commands and subcommands
- [ ] `PersistentPreRun` doesn't collide with subcommand `PreRun`
- [ ] Config overrides don't silently shadow CLI flags

---

## Phase 2 — Orchestration & Scan State Machine _(3 files)_

| # | File | What to check |
|---|------|---------------|
| 1 | [orchestrate.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/orchestrate/orchestrate.go) | Signal traps, context cancellation propagation, toolbox/runner/notifier bootstrap |
| 2 | [scan.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/scan/scan.go) | Step registries (`WildcardSteps`, `CompanySteps`), step count (23/3), resume/state transitions |
| 3 | [runner.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/runner/runner.go) | Command execution, retry logic, proxy injection, `Setpgid`, timeout, PGID cleanup |

**Checks:**
- [ ] Signal handler properly cancels context and kills child processes
- [ ] `WildcardSteps` has exactly 23 entries matching `flow.go` order
- [ ] `CompanySteps` has exactly 3 entries matching company `flow.go` order
- [ ] Step state transitions: no `MarkStepComplete` after `MarkStepFailed`
- [ ] `Setpgid: true` set on all `exec.Command` calls
- [ ] Negative PID kill (`-PID`) on cleanup for process group termination
- [ ] Retry limits enforced; infinite retry loops impossible
- [ ] Context cancellation propagated through the full chain

---

## Phase 3 — Wildcard Recon Workflow _(10 files, ~163KB)_

This is the **largest and most critical** component. All files in [wildcard_flow/](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/).

| # | File | Size | What to check |
|---|------|------|---------------|
| 1 | [flow.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/flow.go) | 26KB | Step execution order, Ctx/Files/RunConfig init, resume logic, main orchestration loop |
| 2 | [asset_discovery.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/asset_discovery.go) | 12KB | Subdomain enum steps, tool invocations, output paths |
| 3 | [validation.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/validation.go) | 20KB | DNS resolution, live host checks, port scans, scope filtering |
| 4 | [content_discovery.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/content_discovery.go) | 51KB | URL crawling, endpoint extraction, JS analysis, secret scanning, parameter mining |
| 5 | [vulnerability_scanning.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/vulnerability_scanning.go) | 21KB | Nuclei, XSS, SQLi, SSRF, template scanning |
| 6 | [fingerprinting.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/fingerprinting.go) | 6KB | Tech stack detection, screenshots, metadata collection |
| 7 | [proxy_scraping.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/proxy_scraping.go) | 5KB | Proxy feed integration, mubeng launch |
| 8 | [helpers.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/helpers.go) | 19KB | Shared workflow utilities, dedup, file merging |
| 9 | [content_discovery_test.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/content_discovery_test.go) | 2KB | Unit test coverage for content discovery |
| 10 | [secret_scan_helpers_test.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/secret_scan_helpers_test.go) | 2KB | Unit test coverage for secret scanning |

**Checks (per step function):**
- [ ] Every step follows the template: `resumeOrSkip` → logic → `markStepCompleteIfNoFailure`
- [ ] No hardcoded `return false` or `return true` — always `c.cancelled()` on error
- [ ] `MarkStepFailed` never followed by `MarkStepComplete` in same path
- [ ] Output file paths match `Ctx.F` fields (no hardcoded paths)
- [ ] Input/output file chaining is correct (step N's output feeds step N+1's input)
- [ ] High-volume data uses `bufio.Scanner` streaming (not full memory load)
- [ ] All tool invocations go through `pkg/tools/` wrappers (no inline `exec.Command`)
- [ ] Skip flags (`SkipAmass`, `SkipSubfinder`, etc.) honored correctly
- [ ] Scope filtering applied where required
- [ ] DB persistence calls have proper error handling

---

## Phase 4 — Company Recon Workflow _(4 files)_

All files in [company_flow/](file:///c:/Users/vishn/Desktop/chaathan/pkg/company_flow/).

| # | File | What to check |
|---|------|---------------|
| 1 | [flow.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/company_flow/flow.go) | Step execution order (3 steps), Ctx init, resume logic |
| 2 | [asn_discovery.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/company_flow/asn_discovery.go) | ASN lookup step, tool invocation, output handling |
| 3 | [cloud_enum.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/company_flow/cloud_enum.go) | Cloud enumeration step, provider coverage |
| 4 | [domain_discovery.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/company_flow/domain_discovery.go) | Domain discovery step, data persistence |

**Checks:**
- [ ] Same step function template validation as Phase 3
- [ ] Step count matches `CompanySteps` registry (exactly 3)
- [ ] Tool wrappers used correctly
- [ ] Output files correctly chained

---

## Phase 5 — Tool Registry & Wrappers _(3 files, ~45KB)_

All files in [tools/](file:///c:/Users/vishn/Desktop/chaathan/pkg/tools/).

| # | File | What to check |
|---|------|---------------|
| 1 | [tools.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/tools/tools.go) | 30 tool wrappers — argument construction, binary path resolution, output parsing |
| 2 | [registry.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/tools/registry.go) | Tool catalog, version checks, binary existence validation |
| 3 | [vulnerability_engine.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/tools/vulnerability_engine.go) | Nuclei template management, custom scanning config |

**Checks:**
- [ ] Every tool wrapper resolves binary via config/registry (not hardcoded paths)
- [ ] Arguments properly escaped/sanitized
- [ ] Stderr/stdout handled correctly for each tool
- [ ] Tool check functions verify actual binary existence (not just `which`)
- [ ] Binary existence check verification handles missing binaries gracefully
- [ ] No duplicate tool logic between wrappers and workflow steps

---

## Phase 6 — Database & Persistence _(3 files, ~75KB)_

All files in [database/](file:///c:/Users/vishn/Desktop/chaathan/pkg/database/).

| # | File | What to check |
|---|------|---------------|
| 1 | [database.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/database/database.go) | Schema creation, CRUD operations, SQL safety, transactions |
| 2 | [metadata.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/database/metadata.go) | Metadata schema, JSON storage, key safety |
| 3 | [roi.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/database/roi.go) | ROI ranking algorithm, scoring queries, priority calculations |

**Checks:**
- [ ] All SQL uses parameterized queries (no string concatenation → SQL injection)
- [ ] `CREATE TABLE IF NOT EXISTS` used consistently
- [ ] Proper transaction blocks (`BEGIN`/`COMMIT`/`ROLLBACK`)
- [ ] SQLite WAL mode or busy timeout configured (prevent locking)
- [ ] Schema migrations are backwards-compatible
- [ ] `database.Close()` properly invoked (checked in `main.go`)
- [ ] NULL handling in queries (no panics on nil scans)
- [ ] Indexes on frequently queried columns

---

## Phase 7 — Reporting & Export _(2 files, ~30KB)_

| # | File | What to check |
|---|------|---------------|
| 1 | [report.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/report/report.go) | Multi-format output (Markdown, HTML, JSON, TXT), template correctness |
| 2 | [export.go](file:///c:/Users/vishn/Desktop/chaathan/utils/export.go) | File export helpers, format conversion |

**Checks:**
- [ ] HTML templates properly escape user-controlled data (XSS prevention)
- [ ] JSON output is valid and complete for all data shapes
- [ ] Markdown formatting handles edge cases (empty data, special chars)
- [ ] File write operations check/create directories
- [ ] Export paths use `pkg/paths` (no hardcoded paths)

---

## Phase 8 — Configuration & Paths _(2 files)_

| # | File | What to check |
|---|------|---------------|
| 1 | [config.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/config/config.go) | YAML loading, default values, validation, rate limit configs |
| 2 | [paths.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/paths/paths.go) | `~/.chaathan` directory structure, path construction |

**Checks:**
- [ ] Config file missing → graceful fallback to defaults
- [ ] Config YAML parsing errors produce clear error messages
- [ ] Paths created with `os.MkdirAll` (not assumed to exist)
- [ ] No hardcoded home directory paths
- [ ] Rate limit defaults are sane (not zero, not unbounded)

---

## Phase 9 — Setup & Installation _(10 files)_

All files in [setup/](file:///c:/Users/vishn/Desktop/chaathan/pkg/setup/).

| # | File | What to check |
|---|------|---------------|
| 1 | [setup.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/setup/setup.go) | Main setup orchestration, tool installation ordering |
| 2 | [prereqs.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/setup/prereqs.go) | Prerequisite checks, OS detection, dependency validation |
| 3 | [go_installer.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/setup/go_installer.go) | Go binary download/install, version verification |
| 4 | [go_tools.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/setup/go_tools.go) | `go install` invocations for Go-based tools |
| 5 | [python_tools.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/setup/python_tools.go) | `pip install` invocations, virtualenv handling |
| 6 | [massdns.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/setup/massdns.go) | MassDNS compilation from source |
| 7 | [x8.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/setup/x8.go) | x8 binary installation |
| 8 | [seclists.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/setup/seclists.go) | SecLists wordlist download |
| 9 | [gf_patterns.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/setup/gf_patterns.go) | GF pattern installation |
| 10 | [log.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/setup/log.go) | Setup logging |

**Checks:**
- [ ] All downloads verify checksums or signatures
- [ ] Installation commands handle failures gracefully (no partial installs)
- [ ] Binary verification checks actual execution (not just file exists)
- [ ] OS/arch detection covers Linux + WSL cases
- [ ] Path updates are persisted correctly
- [ ] Idempotent — re-running setup doesn't break existing installs

---

## Phase 10 — Proxy & Networking _(3 files)_

| # | File | What to check |
|---|------|---------------|
| 1 | [scraping.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/proxy_scraping/scraping.go) | Proxy feed scraping, list deduplication |
| 2 | [rotator.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/proxy_scraping/rotator.go) | Mubeng rotation launch, proxy pool management |
| 3 | [scope.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/scope/scope.go) | Target parsing, in/out-of-scope rules, IP exclusion |

**Checks:**
- [ ] Proxy validation before use (not blindly using dead proxies)
- [ ] Mubeng process properly managed (started/stopped with signals)
- [ ] Scope rules are strict — out-of-scope hosts never scanned
- [ ] IP exclusion lists properly parsed and applied
- [ ] Proxy injection in runner doesn't break tool arguments

---

## Phase 11 — Metadata & Fingerprinting _(1 file)_

| # | File | What to check |
|---|------|---------------|
| 1 | [collector.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/metadata/collector.go) | WAF detection, technology headers, CSP analysis, security headers |

**Checks:**
- [ ] Graceful handling of empty/malformed HTTP responses
- [ ] No panics on nil headers or missing fields
- [ ] JSON metadata serialization is consistent
- [ ] Timeout configuration for HTTP requests

---

## Phase 12 — Notifications _(1 file)_

| # | File | What to check |
|---|------|---------------|
| 1 | [notify.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/notify/notify.go) | Discord, Slack, Telegram webhook implementations |

**Checks:**
- [ ] Webhook failures don't crash the scan
- [ ] Payload size limits respected per platform
- [ ] Rate limiting on notifications (no spam)
- [ ] Sensitive data not leaked in notification payloads
- [ ] Authentication tokens not logged

---

## Phase 13 — Logger, Progress & TUI _(6 files)_

| # | File | What to check |
|---|------|---------------|
| 1 | [logger.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/logger/logger.go) | Log formatting, file redirect, scan UI panels |
| 2 | [colors.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/logger/colors.go) | ANSI color codes, terminal compatibility |
| 3 | [progress.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/progress/progress.go) | Spinner/progress bar lifecycle, concurrent safety |
| 4 | [dashboard.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/tui/dashboard.go) | Terminal dashboard rendering |
| 5 | [query_console.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/tui/query_console.go) | Interactive query console |
| 6 | [logger_internal_test.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/logger/logger_internal_test.go) | Logger test coverage |

**Checks:**
- [ ] Log file redirect works when `--log` flag supplied
- [ ] No data races in concurrent log writes
- [ ] Progress bars cleaned up on cancellation (no terminal corruption)
- [ ] TUI doesn't hang on Ctrl+C

---

## Phase 14 — Utilities _(7 files)_

All files in [utils/](file:///c:/Users/vishn/Desktop/chaathan/utils/).

| # | File | What to check |
|---|------|---------------|
| 1 | [file.go](file:///c:/Users/vishn/Desktop/chaathan/utils/file.go) | File I/O helpers, line reading, file creation |
| 2 | [parser.go](file:///c:/Users/vishn/Desktop/chaathan/utils/parser.go) | Output parsing for various tool formats |
| 3 | [export.go](file:///c:/Users/vishn/Desktop/chaathan/utils/export.go) | Text file export utilities |
| 4 | [constants.go](file:///c:/Users/vishn/Desktop/chaathan/utils/constants.go) | Shared constants, regex patterns |
| 5 | [format.go](file:///c:/Users/vishn/Desktop/chaathan/utils/format.go) | Formatting helpers |
| 6 | [validate.go](file:///c:/Users/vishn/Desktop/chaathan/utils/validate.go) | Input validation utilities |
| 7 | [tls.go](file:///c:/Users/vishn/Desktop/chaathan/utils/tls.go) | TLS configuration helpers |

**Checks:**
- [ ] File operations handle errors (not silently ignoring)
- [ ] Parsers handle malformed input gracefully
- [ ] No unbounded memory allocation in file reading
- [ ] TLS config doesn't disable verification in production
- [ ] Constants are used consistently (no magic strings in other packages)

---

## Phase 15 — Update & Miscellaneous _(1 file)_

| # | File | What to check |
|---|------|---------------|
| 1 | [update.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/update/update.go) | Self-update mechanism, version comparison, binary replacement |

**Checks:**
- [ ] Update downloads verified (checksum/signature)
- [ ] Atomic binary replacement (no partial overwrites)
- [ ] Rollback on failed update

---

## Phase 16 — Test Coverage Audit _(4+ files)_

| # | File | What to check |
|---|------|---------------|
| 1 | [test/cli/cli_test.go](file:///c:/Users/vishn/Desktop/chaathan/test/cli/cli_test.go) | CLI command tests |
| 2 | [test/utils/utils_test.go](file:///c:/Users/vishn/Desktop/chaathan/test/utils/utils_test.go) | Utility function tests |
| 3 | [content_discovery_test.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/content_discovery_test.go) | Content discovery unit tests |
| 4 | [secret_scan_helpers_test.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/secret_scan_helpers_test.go) | Secret scan helper tests |
| 5 | [logger_internal_test.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/logger/logger_internal_test.go) | Logger internal tests |
| 6 | test/pkg/* subdirs | All package-level test files |

**Checks:**
- [ ] Tests actually assert behavior (not just "compiles")
- [ ] Critical paths have test coverage (state machine, resume, DB ops)
- [ ] Tests don't depend on external tools being installed
- [ ] No flaky timing-dependent tests
- [ ] Coverage gaps identified for each package

---

## Phase 17 — Cross-Cutting Concerns

After all phases complete, perform these cross-layer audits:

| # | Concern | What to check |
|---|---------|---------------|
| 1 | **Step Registry ↔ Flow Alignment** | `WildcardSteps` count/order matches `wildcard_flow/flow.go` execution; `CompanySteps` matches `company_flow/flow.go` |
| 2 | **CLI Flags ↔ RunConfig** | Every flag defined in `cli/` has a corresponding `RunConfig` field and is used in workflow |
| 3 | **DB Schema ↔ Report/Query** | All report/query consumers read the same schema that DB writes |
| 4 | **Tool Registry ↔ Setup** | Every tool in registry has a setup path; every setup installs what registry expects |
| 5 | **File Paths ↔ Ctx.F** | All file paths used in workflows come from `Ctx.F` or `pkg/paths`, not hardcoded |
| 6 | **Error Propagation** | Errors bubble up correctly from tool → runner → workflow → CLI → user |
| 7 | **Unused Code** | Dead functions, unreachable steps, unused imports |

---

## Execution Strategy

> [!IMPORTANT]
> Each phase should be reviewed independently and findings documented before moving to the next. This prevents context overload and ensures nothing is missed.

### Priority Order (by risk)
1. **Phase 3** (Wildcard Workflow) — largest, most complex, most bug-prone
2. **Phase 2** (Orchestration & State) — state machine bugs cause silent data loss
3. **Phase 6** (Database) — SQL issues cause data corruption
4. **Phase 1** (CLI) — user-facing, flag mismatches cause UX failures
5. **Phase 5** (Tools) — incorrect tool args cause wrong scan results
6. Phases 4, 7–17 in listed order

### Verification After Each Phase
```bash
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go vet ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go build -buildvcs=false -o chaathan ."
```

> [!NOTE]
> Shall I proceed with executing this scan plan phase by phase? I'll document all findings in a detailed report as I go. I recommend starting with **Phase 3 (Wildcard Workflow)** given its size and criticality, but I can follow the numbered order (Phase 0 → Phase 17) if you prefer a systematic walkthrough.
