---
name: chaathan-tooling-setup
description: Use when changing external tool installation, setup flows, tool checks, config-driven parameters, or failures involving host-installed recon utilities.
---

# Chaathan Tooling & Setup

## When to use

Activate this skill when adding or updating external command dependencies, editing installer modules inside `pkg/setup/`, modifying setup parameters, or fixing runner execution issues.

---

## Tool Registry Structure

All external tools configured in the application are cataloged in the static registry `pkg/tools/registry.go`.
- **Install Verification:** The system uses `ToolInfo.CheckStatus() (bool, string)` to determine if a tool is active, rather than executing raw `exec.LookPath` searches.
- **Categorization Mapping:**
  - **Subdomain Discovery:** subfinder, assetfinder, sublist3r, amass, github-subdomains.
  - **DNS Engines:** dnsx, shuffledns, massdns.
  - **Probing & Ports:** httpx, tlsx, naabu.
  - **URL Gatherers:** waybackurls, gau, x8.
  - **Crawlers:** katana, gospider, hakrawler.
  - **Security Audits:** nuclei, dalfox.
  - **Helpers:** anew, gf, proxy-scraper-checker, mubeng.

---

## Setup Execution Engine Rules

All installers within `pkg/setup/` (e.g., `go_tools.go`, `python_tools.go`, `massdns.go`) must obey these execution standards:
1. **Piped Output Wrappers:** Run command executions inside setup routines via `SetupContext.RunCommand` or `SetupContext.RunCommandInDir`. These helpers automatically capture standard output/error, writing them to `~/.chaathan/setup.log`.
2. **Never hardcode paths:** Install Go tools via `go install <url>@latest`, letting Go resolve path environments. Install Python utilities via custom cloned directories or pip installations matching config paths.
3. **Prerequisite Checkers:** System utilities (such as Python pip, git, make, gcc compiler tools) must be checked in `prereqs.go` before beginning binary compilations.
4. **Go Runtime Provisioning:** If the host Go version is missing or older than 1.26, the setup package automatically installs Go to `~/.local/go` (no `sudo` required), validates the download archive using its official SHA256 checksum file, and registers the local path. The setup process returns a non-zero exit code on terminal failures.

---

## Process Group Isolation (PGID Execution Invariants)

External processes launched by workflow runners can spawn multi-tiered child processes (e.g., subprocess shells, secondary scrapers). To prevent orphan zombie processes when scans cancel or time out:
- **Set PGID:** Standard external commands executed outside the `pkg/runner` package (e.g., custom scripts, raw command calls) must be group-isolated. Ensure you configure `Setpgid: true` inside the system attributes (`SysProcAttr`):
  ```go
  cmd := exec.CommandContext(ctx, name, args...)
  cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
  ```
- **Process Group Termination:** If a cancel signal is caught or a timeout is reached, kill the entire process group by sending `syscall.SIGKILL` targeting the negative Process ID (`-Pid`):
  ```go
  if cmd.Process != nil {
      _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
  }
  ```

---

## Setup Failure Diagnostic Guidelines

If an external installation fails:
1. Log an explicit, actionable error explaining the missing environment requirement (e.g., `"golang is missing; install version 1.21+ manually"`).
2. Never prompt for sudo access or attempt root execution commands.
3. Do not treat optional utility install issues (e.g., a secondary scraper failing to download) as terminal errors. Let the setup run continue, logging the dependency as missing.

---

## Validation Procedures

### Verification Pipeline:
```bash
# Validate installer packages
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./pkg/setup/..."

# Compile binary verification
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go build -buildvcs=false -o chaathan ."
```

### Dry-run Command Checks:
```bash
# Run tool diagnostics checks
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan tools check"
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan setup --help"
```
