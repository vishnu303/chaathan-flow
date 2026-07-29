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
utils/               → File utilities, parse maps, text writers
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

---

## Validation Procedures

Run all tests, lints, and builds inside the WSL environment if developing on a Windows machine.

### WSL Test Pipeline:
```bash
# Format Go code after making changes
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && gofmt -w ."

# Verify unit tests with race detector and coverage package mapping
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test -race -count=1 -coverpkg=github.com/vishnu303/chaathan/pkg/...,github.com/vishnu303/chaathan/utils/... -coverprofile=coverage.out ./..."

# Run static checks
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go vet ./..."

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
