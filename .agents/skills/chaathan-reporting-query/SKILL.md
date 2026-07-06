---
name: chaathan-reporting-query
description: Use when changing query commands, ROI ranking, report generation, export formatting, or the database-to-CLI/report presentation path.
---

# Chaathan Reporting & Query

## When to use

Activate this skill when modifying the query command logic, terminal layout presentation, reporting engines (Markdown, HTML, JSON, TXT), ROI calculations, and export helper functions.

---

## DB / Presentation Separation (The Architecture Boundary)

To ensure consistency across CLI outputs and report outputs, maintain a strict boundary between database queries and output formatting:

```
┌──────────────────────────┐
│      cli/query.go        │  ◄── Exposes commands & flags (e.g. --json)
└────────────┬─────────────┘
             │ Calls API methods only
             ▼
┌──────────────────────────┐
│    pkg/database/db.go    │  ◄── Executes SQLite queries & ROI logic (No Console prints)
└──────────────────────────┘
```

### Invariants:
1. **No direct DB connections:** Cobra commands in `cli/` and export scripts in `pkg/report/` must never instantiate direct connections to SQLite or execute inline SQL strings.
2. **Graceful Degradation:** Query commands must output clean `"no results found"` errors or empty lists rather than formatting broken tables or returning null pointer exceptions when records are missing.
3. **JSON Stability:** CLI json outputs (e.g. `--json`) and generated JSON reports are automation surface interfaces. Never change field name casings or types unless explicitly requested.

---

## Interactive TUI Query Console

To allow manual findings exploration, the top-level command `chaathan query` launches a full-screen interactive TUI dashboard.
- **Rules:**
  1. **Dual Execution Modes:** The parent command `chaathan query [scan_id]` defaults to launching the interactive TUI dashboard (implemented in `pkg/tui/query_console.go`), while explicit subcommands (e.g. `chaathan query subdomains`) run in standard non-interactive terminal print mode.
  2. **Filter and Search:** The TUI table views must dynamically search and filter rows in memory based on user input in the filter field.
  3. **Detail Popup Overlay:** Keyboard `Enter` triggers a center-aligned details pop-up modal showing all structured fields, ensuring long strings are properly wrapped.

---

## ROI Ranking Calculation Heuristics

The Return on Investment (ROI) score helps prioritize targets by analyzing crawled metadata.
- **Signals:** The score is determined by matching crawled parameters and headers stored in the database:
  - **Vulnerabilities:** Weighted by severity (Critical = 10, High = 8, Medium = 5, Low = 2).
  - **Technology:** Bypassed WAFs or exposed administrative portals add weight.
  - **Parameters:** URL query arguments containing dangerous variables (e.g., `redirect`, `url`, `file`, `id`, `admin`) boost the priority rank.
  - **Security Headers:** Missing CSP, HSTS, or anti-clickjacking headers adjust scores.
- **Rules:** When editing ranking formulas in `pkg/database/roi.go`, you must update the descriptive array of `Reasons` returned in the ROI record alongside the score so that operators understand the score attribution.

---

## Report Generation Safety

- **Formats:** The reporting engine produces identical findings summaries across Markdown, JSON, and HTML.
- **HTML Layouts:** The HTML report must compile as a completely self-contained, standalone offline file (all CSS/JS styles inline, no external network requests).
- **Template Safety:** When rendering evidence payloads and URLs within templates, use proper sanitization (e.g., HTML escaping) to prevent HTML/XSS injection vulnerabilities in generated reports.
- **Error Handling:** If database reads fail during report generation, the program must return a descriptive error and abort rather than writing a partially empty or corrupt document.

---

## Validation Procedures

### Verification Pipeline:
```bash
# Validate database compilation
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./test/pkg/database/..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./test/pkg/report/..."
```

### Dry-run Command Checks (using a local database):
```bash
# Verify CLI table formats and TUI console
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan query subdomains 1"
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan query roi 1 --json"
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan query"

# Check report compilation outputs
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan report generate 1 --format markdown"
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan report generate 1 --format html"
```
