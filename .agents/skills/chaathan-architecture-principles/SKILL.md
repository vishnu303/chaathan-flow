---
name: chaathan-architecture-principles
description: Use when making structural decisions in the Chaathan repository or when a task risks crossing package boundaries. Codifies ownership boundaries, extension patterns, and architectural invariants.
---

# Chaathan Architecture Principles

## When to use

Activate this skill when deciding where code should live, how to introduce new behavior, or whether a change fits the project's structure.

## Architectural Topology

The flow of data and control in Chaathan is structured to maintain isolated, modular concerns:

```
                  ┌───────────────────────┐
                  │       CLI Layer       │
                  │      (cli/*.go)       │
                  └───────────┬───────────┘
                              │ Parses flags & maps options
                              ▼
                  ┌───────────────────────┐
                  │    Workflow Config    │
                  │ (RunConfig / Files)   │
                  └───────────┬───────────┘
                              │ Injects into Context
                              ▼
                  ┌───────────────────────┐
                  │   Workflow Runner     │
                  │ (wildcard/company)    │
                  └──────┬─────────┬──────┘
                         │         │
      Delegates steps    │         │ Queries/Updates State
      to tool registry   ▼         ▼
  ┌───────────────────────┐   ┌───────────────────────┐
  │     Tool Registry     │   │     Scan Manager      │
  │     (pkg/tools/)      │   │     (pkg/scan/)       │
  └───────────┬───────────┘   └──────────┬────────────┘
│                          │
              │ Runs external commands   │
              ▼                          │ Persists to DB
   ┌───────────────────────┐              │
   │    Central Runner     │              │
   │     (pkg/runner/)     │              │
   └───────────┬───────────┘              │
               │                          ▼
               │ Writes outputs           ┌───────────────────────┐
               ├─────────────────────────►│     Database Layer    │
               │                          │    (pkg/database/)    │
               ▼                          └───────────┬───────────┘
   ┌───────────────────────┐                          │ Retrieves data
   │ Ingest + Export layer │                          │
   │    (pkg/ingest/)      │◄─────────────────────────┘
   └───────────┬───────────┘
               │ Pure helpers (file IO, host/url
               │ normalization, file-name constants)
               ▼
   ┌───────────────────────┐
   │     utils (leaf)      │
   │     utils/            │
   └───────────────────────┘
```

## Package Ownership Map

| Concern | Owner | Forbidden in this package |
|:---|:---|:---|
| **Command UX, flags, arg parsing** | `cli/` | Workflow execution, DB SQL queries, raw domain regexes |
| **Wildcard scan orchestration** | `pkg/wildcard_flow/` | Direct CLI flags, other workflows, SQL queries |
| **Company scan orchestration** | `pkg/company_flow/` | Direct CLI flags, other workflows, SQL queries |
| **Signal handling, infra bootstrap** | `pkg/orchestrate/` | CLI commands, workflow files |
| **Tool execution, retry, docker** | `pkg/runner/` | CLI wrappers, setup logic |
| **Tool registry, wrappers** | `pkg/tools/` | CLI commands, report rendering |
| **Persistence, queries, ROI** | `pkg/database/` | CLI commands, report templates |
| **Tool-output ingest + DB→file exporters** | `pkg/ingest/` | CLI commands, workflow logic |
| **Report assembly, format export**| `pkg/report/` | Database accessors (use database layer queries only) |
| **Scan state, resume, step defs** | `pkg/scan/` | CLI logic |
| **External tool installation** | `pkg/setup/` | Runtime scan wrappers |
| **YAML config loading** | `pkg/config/` | CLI flag wiring beyond basic mapping |
| **Host metadata (CSP, WAF, headers)**| `pkg/metadata/` | Report templates, CLI formatting |
| **Scope filtering** | `pkg/scope/` | Database model changes, CLI commands |
| **Notifications** | `pkg/notify/` | CLI commands |
| **Terminal output, colors** | `pkg/logger/` | Business logic |
| **Spinners, progress bars** | `pkg/progress/` | Business logic |
| **`~/.chaathan` directory paths** | `pkg/paths/` | Hardcoded strings and configurations elsewhere |
| **File I/O, string/url/host normalization, file-name + severity constants** | `utils/` (leaf package) | Any `pkg/*` import (no `pkg/database`, `pkg/logger`, `pkg/ingest`), DB access, `logger.*` calls, scan / workflow logic |

## Core Architecture Rules

> **Canonical source:** The seven numbered architecture rules live in [`AGENTS.md`](../../../AGENTS.md) under "Core architecture rules". Always treat that file as authoritative. Do not restate or re-number them here.

The following supplementary principles expand on those rules with implementation-specific guidance not covered in AGENTS.md:

- **Database Isolation.** No SQL queries, database handles, or transaction scopes may leak outside of `pkg/database/`. All operations—including findings insertion, host-metadata storage, and scan metrics accumulation—must be exposed as clean, typed Go APIs in `pkg/database/database.go` or dedicated models.
- **External Tools Remain External.** Chaathan orchestrates third-party recon utilities. Never silently replace external-tool execution with in-process logic unless explicitly requested. Prefer clear setup/install paths, predictable command-line arguments, and process isolation.
- **Fail Soft in Scans, Fail Loud at Boundaries.** Within multi-step scans, individual tool failures log and continue. At command boundaries, bad input or broken setup returns explicit errors.

---

## Preferred Extension Patterns

- **New CLI option:**
  1. Add flag to `cli/` file.
  2. Map the flag to a new field in `wildcard_flow.RunConfig` or `company_flow.RunConfig`.
  3. Propagate and consume the config option in `pkg/wildcard_flow/` or `pkg/company_flow/`.
- **New scan artifact:**
  1. Add absolute output path to `Files` struct in `pkg/wildcard_flow/flow.go`.
  2. Implement/adjust step function to write to this file path.
  3. Integrate into DB or report generation downstream if needed.
- **New ranking signal:**
  1. Capture metadata in step functions $\rightarrow$ call `pkg/database/` to persist.
  2. Incorporate key in `pkg/database/roi.go` for priority scores.
  3. Render the updated metrics in CLI queries and exported reports.

### Interface-Driven Scanner Decoupling (Factory Pattern)

Vulnerability engines (like Nuclei, Dalfox, etc.) are structured using decoupled scanner interfaces to avoid monolithic growth in `pkg/tools/tools.go`.
- Define engines by implementing the `VulnScanner` interface:
  ```go
  type VulnScanner interface {
      Scan(ctx context.Context, target string, opts ScanOptions) (*ScanResult, error)
  }
  ```
- Modular scanner structs (e.g., `NucleiScanner`, `DalfoxScanner` in `pkg/tools/vulnerability_engine.go`) encapsulate argument formulation, command assembly, and parser logic.
- Avoid writing raw command execution args inside the generic `tools.go` wrapper. Instead, retrieve scanner instances via `GetScanner(name)` and delegate execution:
  ```go
  scanner, err := tools.GetScanner("nuclei")
  if err == nil {
      scanner.Scan(...)
  }
  ```

---

## Code Smell Signals & Anti-patterns

- **Wrong-place signals:**
  - SQL strings or database queries written in `cli/` or `pkg/wildcard_flow/*.go`.
  - Cobra handlers reading raw JSON scan files or formatting terminal report tables.
  - Step functions writing directly to database connections without passing through the database API layer.
  - Setup routines calling scan runners or config parsing code directly.
- **Anti-patterns:**
  - Collapsing package boundaries to bypass Go import loops (restructure packages instead).
  - Writing raw system command executions bypassing the central `pkg/runner/` package.
  - Speculative code refactoring that breaks backwards compatibility with previous scan databases.
