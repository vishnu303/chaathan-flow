# Chaathan Agent Guide

Chaathan is a Go CLI pentesting orchestration framework.

Use this file as the primary entrypoint for any code agent.

## Repository overview

```
chaathan-flow/
├── main.go                    Entry point — init paths, defer DB close, run CLI
├── Makefile                   Build, install, setup, test, vet targets
├── cli/                       Cobra commands, flags, argument parsing
│   ├── root.go                Global flags, version, PersistentPreRun init
│   ├── wildcard.go            22-step domain recon command
│   ├── company.go             3-step company recon command
│   ├── setup.go               Tool installation entry
│   ├── scans.go               Scan list/show/resume/delete
│   ├── query.go               Query subdomains/vulns/ports/urls/endpoints/roi
│   ├── report.go              Report generation command
│   ├── export.go              Text file export command
│   ├── delete.go              Data cleanup commands
│   ├── diff.go                Scan comparison command
│   ├── status.go              Dashboard command
│   ├── config.go              Config management commands
│   └── tools_cmd.go           Tools list/check commands
├── pkg/
│   ├── wildcard_flow/         22-step domain recon workflow (6 phase files)
│   ├── company_flow/          3-step company recon workflow
│   ├── orchestrate/           Signal handling, infra bootstrap (runner/toolbox/notifier)
│   ├── database/              SQLite persistence, queries, ROI ranking, metadata
│   ├── report/                Report assembly and multi-format export
│   ├── scan/                  Scan state, resume, step definitions
│   ├── setup/                 External tool installation and verification
│   ├── tools/                 Tool registry and wrappers (27 tools)
│   ├── proxy_scraping/         Automated proxy scraping and IP rotation (mubeng)
│   ├── runner/                External command execution, retry, docker mode
│   ├── config/                YAML config loading and defaults
│   ├── metadata/              Host metadata collection (CSP, headers, tech)
│   ├── scope/                 Scope filtering (in/out-of-scope, IP exclusion)
│   ├── notify/                Discord, Slack, Telegram notifications
│   ├── logger/                Styled terminal output, colors, scan UI
│   ├── progress/              Spinners and progress bars
│   └── paths/                 Centralised ~/.chaathan directory paths
├── utils/                     File I/O, parsers, export helpers, validation
```

## Core architecture rules

1. **Thin CLI, thick packages.** Cobra handlers parse flags and delegate to `pkg/`. No business logic in `cli/`.
2. **Workflow packages own orchestration.** Scan step logic lives in `pkg/wildcard_flow/` and `pkg/company_flow/`, not in Cobra commands.
3. **One owner per concern.** Persistence → `pkg/database/`. Reports → `pkg/report/`. Setup → `pkg/setup/`. Tools → `pkg/tools/` + `pkg/runner/`.
4. **Extend, don't scatter.** Add fields to `RunConfig`, `Ctx`, or `Files` instead of threading long parameter lists.
5. **Stable interfaces.** DB rows, output files, and JSON output are product surfaces — check all readers before changing shapes.
6. **Step functions return `c.cancelled()`.** Never hard-code `return false`. Never call `MarkStepComplete` after `MarkStepFailed` in the same error path.
7. **Documentation Sync (Meta-Rule).** Every time you make changes to the codebase (e.g., CLI options, scan steps, tool integrations), you **must** update the corresponding `.agents/skills/*.md` files and the root `README.md` to ensure documentation is always in sync with implementation (only if necessary).

## Validation baseline

```bash
gofmt -w .
go test ./...
golangci-lint run ./...
go build -buildvcs=false -o chaathan .
```

If developing on Windows, use WSL for all commands at the `/mnt/c/Users/vishn/desktop/chaathan` path (using interactive shell `-i` to source your Go environment):
```bash
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && gofmt -w ."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && golangci-lint run ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go build -buildvcs=false -o chaathan ."
```

If a change affects CLI behavior, also inspect the relevant `--help` output.
```bash
./chaathan --help
# On Windows: wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan --help"
```
## Agent-specific notes

- Antigravity and Codex agents: deep-dive skills are in `.agents/skills/`.
- Other agents (Cursor, Claude, etc.): read this file and the relevant `SKILL.md` directly from `.agents/skills/<skill-name>/SKILL.md`.
- Do not invent a second source of truth — this file is the canonical agent guide.
