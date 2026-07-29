---
name: chaathan-dev
description: Use when making code changes in the Chaathan repository — CLI commands, Go package wiring, build/test flows, or any development task. Provides navigation patterns and project-specific rules.
---

# Chaathan Dev Guide

## When to use

Activate this skill for any normal development, feature addition, bug fixing, or CLI wiring task in this repository.

## Repository Shape

```
main.go              → paths.Init(), defer database.Close(), cli.Execute()
cli/                 → Cobra commands, flag parsing, maps flags to RunConfig
pkg/wildcard_flow/   → 23-step domain recon workflow (6 phases)
pkg/company_flow/    → 3-step company recon workflow
pkg/orchestrate/     → Signal traps, tool-runner bootstrap, notifications wiring
pkg/database/        → SQLite models, ROI priorities, metadata schema, database actions
pkg/ingest/          → Tool-output parsers (Parse*Output) + DB→text exporters (Export*)
                       Extracted from utils/ via §3.4 leaf-package inversion.
pkg/report/          │ Report formatting engine (Markdown, HTML, JSON, TXT)
pkg/scan/            → Scan states, step definitions (WildcardSteps, CompanySteps)
pkg/setup/           → Install scripts (Go, Python, massdns compilation, proxy tools)
pkg/tools/           → Catalog of external tools (30 tools) and execution wrappers
pkg/proxy_scraping/   → Scraping proxy feeds and starting mubeng rotation
pkg/runner/          → Command execution with retry limits, proxy injection, and limits
pkg/config/          → Config YAML loading, parsing logic, rate limits
pkg/metadata/        → WAF detection, technology headers, security parameters
pkg/scope/           → Target parsing, inclusion/exclusion rules
pkg/notify/          → Notifier client implementations (Discord, Slack, Telegram)
pkg/logger/          → Formatted logging layout, UI panels, file logging triggers
pkg/progress/        → Terminal progress animations and bars
pkg/paths/           → Centralized config/data path management (~/.chaathan)
utils/               → Pure leaf package — file IO, string/host normalization, pure
                       helpers only. MUST NOT import pkg/database, pkg/logger,
                       pkg/ingest, or any other internal package. DB-coupled
                       Parse*Output / Export* logic belongs in pkg/ingest.
```

## Standard Development Pattern

```
                       ┌───────────────┐
                       │  cli/*.go     │  Define command flags
                       └───────┬───────┘
                               │ maps to RunConfig
                               ▼
                       ┌───────────────┐
                       │  flow.go      │  Initialize Context (Ctx)
                       └───────┬───────┘
                               │ executes step matching scan.go registry
                               ▼
                       ┌───────────────┐
                       │  phase_*.go   │  Run step function
                       └───────────────┘
```

---

## Standard Workflow Step Function Template

Every step function in a workflow must follow this template strictly to maintain correct logger output, skip/resume logic, context propagation, and state machine consistency:

```go
func stepExampleTool(c *Ctx) bool {
	stepName := "example_step"
	stepHeader := "Phase X: Running Example Step"

	// 1. Check for scan resume state or skip condition
	if resume, skip := c.resumeOrSkip(stepName, stepHeader); skip {
		return resume
	}

	// 2. Initialize step execution
	logger.Info("Starting example tool execution...")
	
	// Prepare input file path
	inputPath := c.F.LiveHosts
	outputPath := c.F.ExampleToolOut

	// 3. Invoke external tool through wrapper
	err := c.Tb.RunExampleTool(c.GoCtx, inputPath, outputPath)
	if err != nil {
		logger.Error("Example tool failed: %v", err)
		c.StateMgr.MarkStepFailed(c.State, stepName, err)
		// Return c.cancelled() instead of hardcoded false to allow graceful exits on signals
		return c.cancelled()
	}

	// 4. Save results to Database if needed
	if err := database.SaveExampleFindings(c.ScanID, outputPath); err != nil {
		logger.Warning("Failed to persist findings: %v", err)
	}

	// 5. Finalize step state (clears failed steps, sets completion flag)
	return c.markStepCompleteIfNoFailure(stepName)
}
```

---

## Technical Development Rules

1. **Step Registries Alignment:** The step list in `pkg/scan/scan.go` (e.g., `WildcardSteps`) must match the execution order in `pkg/wildcard_flow/flow.go` exactly.
2. **Step Counts:**
   - **Wildcard Scan:** Exactly **23 steps across 6 phases (Phases 0 to 5)**.
   - **Company Scan:** Exactly **3 steps**.
3. **No Short-Circuit Returns:** Step functions must never return hardcoded `false` on failure. Always log the error, register the failure via `MarkStepFailed`, and return `c.cancelled()`.
4. **CLI Flag Propagation:**
   - Flags defined in `cli/` are bound to variables.
   - Transfer these variables to `RunConfig` in the `Run` call.
   - Access config parameters within step files via the embedded `Ctx` (e.g., `c.SkipAmass`).
5. **Logs Redirection:** If `--log` is supplied, logs are written to `~/.chaathan/logs/<domain>_<scanID>_<timestamp>.log`. Ensure any custom logs redirect through `logger.Info` or `logger.Write` to mirror them correctly.
6. **Test Locations:** All test files (`*_test.go`) and test support/mock utilities must reside strictly within the `test/` folder hierarchy. No tests are allowed to remain in the `pkg/` or `utils/` production packages.
7. **Config Defaults Single Source of Truth:** `config.DefaultConfig()` is the only source of defaults. Never re-introduce a second `applyDefaults`-style helper — `DefaultConfig()` is pre-seeded before YAML decode in `Load`, so sparse configs inherit defaults automatically. The `TestLoadMatchesDefaultConfig` test (in `test/pkg/config/config_test.go`) pins this invariant and must keep passing.
8. **API Key Dispatch (`config.Config.GetAPIKey`):** Email-style engines (FOFA, Quake, ZoomEye) require both a `key` and an `*_email` half. The switch returns a combined `"<key>:<email>"` shorthand when both are set, and falls back to bare `key` if only the key is configured. The env fallback list (`apiKeyEnvMap`) must include `*_email` names for these engines so `FOFA_EMAIL` / `QUAKE_EMAIL` / `ZOOMEYE_EMAIL` work without a YAML file. `pkg/tools` uncover wiring only selects an email-style engine when both halves are present (mirrors Censys `id:secret` handling).
9. **`utils` is a Leaf Package (§3.4 inversion):** `utils/` MUST NOT import any `pkg/*` package — no `pkg/database`, no `pkg/logger`, no `pkg/ingest`. It contains only stdlib-facing helpers (file IO, string/URL/host normalization, validation, file-name constants, severity ordering). All DB-coupled parse and export logic (`Parse*Output`, `Export*`, result structs like `HttpxResult`, `NucleiResult`, `DalfoxResult`) lives in `pkg/ingest/`. Adding a back-compat shim in `utils/` that calls `pkg/ingest` would create an import cycle — do not do it; migrate callers to `pkg/ingest` directly instead.
10. **Context Propagation Audit (§3.8):** Any function that calls a tool, performs HTTP via `net/http`, performs DNS via `net.Lookup*`, or runs an external command MUST accept `ctx context.Context` as its first parameter. Callers MUST propagate `c.GoCtx` (the scan-side context) — never invent `context.Background()` at an internal boundary to silence the linter. Use `http.NewRequestWithContext(ctx, ...)` (not bare `http.NewRequest`) whenever `ctx` is in scope. The `contextcheck` linter (enabled in `.golangci.yml`) enforces this at CI time. Pure helpers that perform only CPU work or file IO on a local path MAY omit `ctx`.

---

## Validation Procedures

Run all tests, lints, and builds inside the WSL environment if developing on a Windows machine.

### WSL Test Pipeline:
```bash
# Format Go code after making changes
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && gofmt -w ."

# Verify unit tests with race detector and coverage package mapping
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test -race -count=1 -coverpkg=github.com/vishnu303/chaathan/pkg/...,github.com/vishnu303/chaathan/utils/... -coverprofile=coverage.out ./..."

# Run linter & static analysis
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && golangci-lint run ./..."

# Build application binary
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go build -buildvcs=false -o chaathan ."
```

### Manual CLI Verification:
```bash
# Check syntax / help texts
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan --help"
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan wildcard --help"
```

## Anti-patterns to Avoid

- Writing inline bash or python runner scripts inside `cli/` or workflows.
- Bypassing the `paths` package to hardcode `/home/user/` or `C:\` configurations.
- Using `os.Exit()` inside packages. Only `main.go` and Cobra commands may call `os.Exit()`.
- Mutating public API schemas in `pkg/database/` without validating report engines.
