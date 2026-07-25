# Phase 2 Findings Report — Execution Core

**Status: scan complete. No fixes applied.** Continues `CODE_REVIEW_PLAN.md` Phase 2; IDs continue from `PHASE1_FINDINGS.md` (F-016…F-051).

| | |
|---|---|
| Date | 2026-07-25 |
| Scope | 28 files: `pkg/runner` (1), `pkg/tools` (5), `pkg/setup` (14); tests: runner (2), tools (3 incl. artifact), setup (4) |
| Method | Full manual read + repo-wide dead-code scan (comment-aware) + targeted verification greps |
| Note | Phase 1 fixes are in the tree (uncommitted); findings are against that state |

---

## 1. Dead code — verified (C10)

| ID | Severity | Location | Finding |
|----|----------|----------|---------|
| F-052 | minor | `pkg/tools/tools.go:723` | `RunNuclei()` ("standard" mode) — **zero callers**. Side effect: `vulnerability_engine.go:95-99` only applies `opts.ExcludeTags` in standard/default mode, so the config option `tools.nuclei.exclude_tags` (default `[dos,fuzz]`, documented) is **silently ignored by every active scan mode** — see F-058/F-059 |
| F-053 | nit | `pkg/runner/runner.go:84` | `WithStdinFactory()` — zero callers (`WithStdin` covers all usage) |
| F-054 | nit | `pkg/tools/export_test.go` | 1-line file containing only `package tools` — no purpose; repo convention is tests under `test/` |
| F-055 | nit | `test/pkg/tools/out.txt` | Stale artifact (`"dummy output"`) — committed to git, never referenced by any test; not a fixture |
| F-056 | nit | `pkg/setup/test_exports.go:7,15` | Redundant duplicate export: `VerifySHA256` var **and** `VerifySHA256Func` both export `verifySHA256`; tests only use `Func`. Keep one |
| F-057 | minor | `test/pkg/setup/setup_test.go:59` | `TestResolveGOPATH` is an **empty test** — sets env, defers unset, zero assertions (comment admits "we don't have to test it directly"). False coverage; also uses `os.Setenv` (F-048 class) |

## 2. Major findings

| ID | Cat | Location | Finding |
|----|-----|----------|---------|
| F-058 | C3/C4 | `pkg/tools/tools.go:272-482` | **Tool defaults live in three places and have already drifted.** ToolBox fallback helpers duplicate `config.DefaultConfig`: `httpxPorts()` fallback `"80,443,8080,8443,8081,8000,8008,8888"` ≠ DefaultConfig `"80,443,8080,8443,8000,8888"` (**8081, 8008 drifted in**); `nucleiMaxTimeout()` fallback `300min` ≠ DefaultConfig `180min`. So `tools.New(r)` without explicit config behaves differently from the documented defaults. Fix direction: single source (read effective config, no local fallbacks). |
| F-059 | C4 | `pkg/tools/tools.go:971-980` + `pkg/tools/vulnerability_engine.go:163` | **Dead config option: `tools.dalfox.max_timeout_min` is never read.** `RunDalfox` passes only `Concurrency` in `ScanOptions`; `DalfoxScanner.Scan` hardcodes `120 * time.Minute` when `MaxTimeout==0`. User config can never reach the engine. |
| F-060 | C3 | `pkg/tools/vulnerability_engine.go:51-109` | Nuclei mode switch repeats `"-timeout","5"`, `"-max-host-error","3"`, `"-retries","0"`, `"-stats","-stats-interval","30"` in 4 of 5 branches; the severity chain has two identical branches (`smart-cve‖takeover` → `critical,high` ≡ final `else` → `critical,high`). Hoist common flags, table-drive per-mode deltas, merge duplicate severity branches. |
| F-061 | C3 | `pkg/setup/go_tools.go:37-53,71-87` | The "find nuclei → `downloadNucleiTemplates`" block is duplicated **verbatim twice** (~18 lines each). Extract `maybeUpdateNucleiTemplates(ctx)`. |
| F-062 | C3 | `pkg/setup/seclists.go:28-37` vs `pkg/config/config.go:705-714` | SecLists candidate-path list duplicated across packages (8 paths, same order, same `Discovery` sentinel check). One canonical `FindSecListsBase()` should be shared (config already owns one). |

## 3. Minor findings

| ID | Cat | Location | Finding |
|----|-----|----------|---------|
| F-063 | C1 | `pkg/runner/runner.go:134` | `retryRun` drops final-attempt output: `return "", lastErr` even though `runOnce` captured stdout — inconsistent with the cancellation path (:114) which returns the output. Partial results are lost exactly when the tool failed N times. |
| F-064 | C1 | `pkg/runner/runner.go:210,303` | Error wrap without `%w`: `fmt.Errorf("%v: %s", err, stderr)` — breaks `errors.Is/As` (e.g. detecting `*exec.ExitError`). Both runners. |
| F-065 | C1 | `pkg/runner/runner.go:74` | `WithStdin` ignores `io.ReadAll` error → silently truncated/empty stdin on read failure. |
| F-066 | C8 | `pkg/setup/go_installer.go:100-124` | `downloadLatestGo` never returns a non-nil error (every failure falls back to `go1.26.0` + nil) — the error return is dead, and `EnsureGoInstalled`'s error branch (:286) is unreachable. Return the error or drop it from the signature. |
| F-067 | C8 | `pkg/runner/runner.go:267-273,405-410` | Dead default-only `switch` around appending `command`; and unknown tools fall back to image `"alpine"` → `docker run alpine <tool>` fails confusingly — log a warning when no image is registered. |
| F-068 | C6 | `pkg/setup/setup.go:44` | `RunCommandInDir` uses `context.Background()` + fixed 10 min — no parent context: **Ctrl+C during setup cannot cancel a running installer** (only the 10-min timeout saves you). Thread the caller's ctx. |
| F-069 | C8 | `pkg/setup/setup.go:88-116` | Section accumulation repeated 6× (`i, s, f = ...; totalInstalled += int32(i)...`). A `[]struct{name string; fn func() (int,int,int)}` table + loop collapses it and makes section order declarative. |
| F-070 | C1 | `pkg/setup/go_installer.go:171,179` | Double close: `defer out.Close()` + explicit `_ = out.Close()` — works (second errors, ignored) but sloppy; pick one. Same class: `x8.go:122` bare `out.Close()` error unchecked. |
| F-071 | C8 | `pkg/tools/tools.go:456-482,818` | Eight one-line `xxxMaxTimeout()` methods returning constants — should be package consts (methods imply config dependence they don't have). `hakrawlerMaxTimeout` TODO (Phase-0 F-007) still open. |
| F-072 | C3 | `pkg/tools/tools.go:1116-1129` | `writeToFile` duplicates `utils.writeLines`/`writeAndSync` — and re-introduces the swallowed `Close()` error fixed in F-034 (`defer f.Close()` after `f.Sync()`). Use the utils helper. |
| F-073 | C8 | `pkg/tools/tools.go:116` | Exported mutable `RealUserAgents` — only consumer is `RandomUA()` (F-038 class): unexport, keep `RandomUA` as the API. |
| F-074 | C9 | `pkg/runner/runner.go` | Exported symbols undocumented: `Runner`, `NativeRunner`, `DockerRunner`, `RunOptions`, `Option`, `WithDir/WithNoRetry/WithTimeout`, `NewWithRetry`, both `Run` methods (Phase-0 doc-gap: 11/25). |
| F-075 | C9 | repo-wide in phase | Internal ticket refs as comments: runner.go `(F30)`, go_tools.go `M8`/`L10`, x8.go `L8`/`L9`/`H5`, massdns.go `L10`, prereqs.go `M1`/`M5` — meaningless to future readers; convert to plain language or drop. |
| F-076 | C8 | `pkg/setup/python_tools.go:24,45` | `pyTools` field named `package_` (keyword workaround) → `pkg`; `skippedCount` shadows named return `skipped` in both go_tools.go:18 and python_tools.go:46 — named returns half-used. |
| F-077 | C8 | `pkg/tools/registry.go:26-69` | `AllTools` uses unkeyed positional struct literals (24 rows × 5 fields) — adding/reordering a `ToolInfo` field silently misaligns every row. Switch to keyed literals. Also `AllTools` is another exported mutable slice (F-038 class). |
| F-078 | C8 | `pkg/setup/x8.go:53,66` | Pinned asset URL `v4.3.0` and magic `500000` size check → named consts (version will age like the UA pool TODO). |
| F-079 | C7 | `pkg/setup/prereqs.go:184-185` | `runSysCmd` mirrors output straight to `os.Stdout`/`os.Stderr` via MultiWriter — interleaves with the live spinner and (unlike F-023's fix) bypasses the logger tee. Setup UX consistency decision needed. |
| F-080 | C8 | `pkg/runner/runner.go:121` | Hardcoded `3 * time.Second` default retry delay duplicates config default `RetryDelaySec: 3` (third-source pattern again — see F-058). |

## 4. Test findings (C11)

| ID | Severity | Location | Finding |
|----|----------|----------|---------|
| F-081 | minor | `test/pkg/setup/setup_test.go:30` | `TestSetupLogger` writes a real `setup_*.log` into `~/.chaathan/logs` (no `CHAATHAN_HOME` isolation) — test pollutes the user's home directory on every run. |
| F-082 | minor | `test/pkg/tools/vulnerability_engine_test.go` | Only `GetScanner` type-checks (27 LOC vs 181-LOC engine). **The mode switch (F-060) has zero per-mode flag tests** — smart-cve/misconfig/dast/takeover arg matrices unverified; `DummyRunner` captures args, so this is easy to add. |
| F-083 | minor | `test/pkg/runner/runnerfaketest/runnerfake.go` | `DummyRunner` always returns nil error — no error injection → zero failure-path coverage for `Run*` methods (e.g. `writeToFile` error propagation, retry behavior through ToolBox). Add `ErrMap`/`Err` field. |
| F-084 | nit | `test/pkg/runner/runner_test.go:24`, `test/pkg/setup/setup_test.go:46`, `test/pkg/tools/vulnerability_engine_test.go:1` | Trailing whitespace (gofmt, part of Phase-0 F-001). `TestParseGoVersion` also locks in accepting `go1.26rc1` as ≥1.26 (rc is pre-release) — verify intent. |
| F-085 | nit | `test/pkg/tools/tools_test.go` | `out.txt`/`in.txt`/`targets.txt` literals as throwaway paths — fine with DummyRunner, but `TestWriteToFileHarden` uses `os.MkdirTemp` instead of `t.TempDir()` (inconsistent with the rest of the suite). |

## 5. Formatting debt in scope (tracked under Phase-0 F-001/F-002)

- **CRLF (F-002):** `pkg/tools/tools.go`, `pkg/setup/{gf_patterns,massdns,prereqs,seclists,x8}.go`
- **gofmt whitespace (F-001):** `pkg/runner/runner.go`, `pkg/setup/go_installer.go`, `pkg/setup/log.go`(?), 3 test files (F-084)

## 6. Phase 2 exit-criteria check (from CODE_REVIEW_PLAN)

| Criterion | Status |
|-----------|--------|
| `tools.go` decomposed or explicitly justified | ❌ still 92 funcs / 1129 LOC — plan decision pending (decomposition is a Phase 4-adjacent refactor; recommend deferring with F-024) |
| All installers share one download/verify helper | ❌ go_installer (tarball+sha256), x8 (gzip+size-check), seclists/gf/massdns (git clone) — `http.go`/`verifySHA256` shared by only 2 of 5 |
| Pipe-draining verified deadlock-free | ✅ `runner.startAndWait` kills process group + 2s bounded wait; stdout/stderr are buffers (no pipes) — no deadlock vector found |

## 7. Suggested fix order (when implementation is approved)

1. **F-058 + F-059** — config-drift bugs with real behavior impact (wrong ports, wrong timeouts, dead config options); add a test pinning ToolBox fallbacks ≡ DefaultConfig
2. **F-052** — delete `RunNuclei` **and** decide the `exclude_tags` story (apply `-etags` from config in all modes, or drop the config key + README note)
3. **F-060/F-061/F-062** — duplication clusters (engine mode switch, nuclei-templates block, seclists path list)
4. Dead-code batch: F-052…F-057 (+F-054/F-055 file deletions)
5. **F-063/F-064/F-065/F-066/F-068** — runner/setup error-handling & cancellation
6. Nits: F-067…F-085 as one cleanup pass (incl. CRLF normalization for the 6 phase-2 files)
7. Re-run gates; update F-log
