# Architectural Blueprint: Fireprox (AWS API Gateway IP Rotator) Integration

This plan outlines the finalized technical architecture for integrating **Fireprox** (AWS API Gateway IP Rotation) into the **Chaathan** CLI recon and pentesting framework using **Native Go AWS SDK (`aws-sdk-go-v2`)**.

When implemented, Fireprox will allow Chaathan target-facing HTTP tools (such as `httpx`, `ffuf`, `nuclei`, `katana`, `dalfox`, `x8`, `arjun`) to transparently route HTTP requests through dynamically created AWS API Gateway endpoints. Each outbound request will originate from a different AWS IP address, effectively neutralizing IP-based rate limiting, Cloudflare IP blocks, and WAF bans while preserving 2-way payload and response body inspection.

---

## User Review & Prerequisites

> [!IMPORTANT]
> **AWS Account Credentials Required**: Fireprox requires valid AWS API Access Keys (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`) with permissions to create and destroy API Gateway resources (`apigateway:*` or `AmazonAPIGatewayAdministrator`).
>
> **AWS Free Tier & Billing Safeguards**: AWS provides **1,000,000 free API Gateway calls/month**. Usage exceeding 1M calls is billed at ~$1.00 - $3.50 per million calls. Chaathan includes built-in max-request hard-stops and rate limiting to keep scans within free-tier limits and prevent account suspensions.

---

## Finalized Architectural Decisions

### 1. Selected Approach: Native Go AWS SDK (`aws-sdk-go-v2`)
* **Decision**: Instead of invoking outdated 4-year-old Python CLI wrappers (`fireprox`), Chaathan will use **`aws-sdk-go-v2`** natively inside a new `pkg/proxy_scraping/fireprox.go` package.
* **Benefits**:
  * **Zero Python / PIP Dependencies**: Single self-contained Go binary with no external interpreter requirements.
  * **Reliable Lifecycle Management**: Uses Go `defer` and signal hooks (`SIGINT`/`SIGTERM`) to guarantee temporary API Gateway resources are deleted immediately upon scan completion or cancellation.
  * **High Performance**: Native Go API calls directly to AWS endpoints.

### 2. Supported Tool Matrix
* **HTTP Tools Routed Through Fireprox**:
  * `httpx` (HTTP Probing & Tech Detection)
  * `ffuf`, `x8`, `arjun` (Directory, File & Parameter Fuzzing)
  * `katana`, `gospider`, `hakrawler` (Web Crawling & Endpoint Scraping)
  * `nuclei`, `dalfox` (Vulnerability & XSS Scanning)
* **Non-HTTP Tools (Excluded)**:
  * DNS tools (`subfinder`, `dnsx`) and TCP port scanners (`naabu`, `nmap`) run directly because API Gateway only proxies Layer 7 HTTP/HTTPS traffic.

### 3. Automatic URL Normalization & Sanitization
* **Clean Data Guarantees**: Tool outputs containing temporary AWS API Gateway URLs (e.g. `https://<id>.execute-api.us-east-1.amazonaws.com/fireprox/admin`) are automatically sanitized by Chaathan's parser layer (`pkg/database` and output handlers).
* **Output Integrity**: The SQLite database, `endpoints.txt`, and generated HTML/Markdown reports will exclusively display the clean target URL (`https://target.com/admin`).

### 4. OpSec, Compliance & Rate Control
* **Global Rate Limit Integration**: Rate limits are controlled via Chaathan's global `--rate` / tool-level rate configurations, allowing flexible speed controls during scans.
* **Max Request Safeguard**: Hard-stop threshold (`--fireprox-max-requests 500000`) to halt the scan and tear down the gateway if request caps are reached.

---

## Proposed Code Changes

The changes span configuration, tool registry, proxy management, workflow context, and CLI flags.

### Configuration Layer

#### [MODIFY] [config.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/config/config.go)
- Add `AWSConfig` struct under `Config` to store AWS credentials and default region (`us-east-1`):
  ```go
  type AWSConfig struct {
      AccessKeyID        string `yaml:"key_id"`
      SecretAccessKey    string `yaml:"secret_key"`
      Region             string `yaml:"region"`
      EnableFireprox     bool   `yaml:"enable_fireprox"`
      MaxRequests        int    `yaml:"max_requests"`        // Default: 500000
  }
  ```

---

### Tools & Dependency Layer

#### [MODIFY] [registry.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/tools/registry.go)
- Add `fireprox` to `AllTools` catalogue under the `"Proxy"` category:
  ```go
  {"fireprox", "Proxy", "AWS API Gateway IP rotator for WAF/rate-limit bypass (Native Go)", false, ""}
  ```

---

### Fireprox Orchestration Package

#### [NEW] [fireprox.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/proxy_scraping/fireprox.go)
Create `pkg/proxy_scraping/fireprox.go` using `aws-sdk-go-v2/service/apigateway`:
- **`CreateGateway(ctx, targetURL) (proxyURL string, gatewayID string, err error)`**: Provisions an API Gateway pass-through proxy pointing to `targetURL` and deploys it to the `fireprox` stage.
- **`DeleteGateway(ctx, gatewayID) error`**: Deallocates the API Gateway resource upon scan completion or signal cancellation (`SIGINT`/`SIGTERM`) to avoid AWS orphan resources.
- **`SanitizeURL(rawURL, gatewayURL, targetURL string) string`**: Strips temporary AWS gateway prefixes and returns clean `targetURL` strings for database persistence and report generation.

---

### Workflow Orchestration & Cleanup

#### [MODIFY] [flow.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/flow.go)
- Add `UseFireprox`, `FireproxMaxReq` to `RunConfig`.
- In `Run()`, during scan context initialization:
  - If `UseFireprox` is enabled, invoke `fireprox.CreateGateway()` for the target domain.
  - Inject the returned Fireprox endpoint URL into `c.Files.FireproxURL` and pass it to downstream steps (`probing`, `crawling`, `fuzzing`, `nuclei`).
  - Register cleanup hooks in defer / cancellation handlers to ensure `DeleteGateway()` is always invoked on exit.

---

### CLI Layer

#### [MODIFY] [wildcard.go](file:///c:/Users/vishn/Desktop/chaathan/cli/wildcard.go)
- Add `--fireprox` flag (boolean, default: `false`).
- Add `--aws-region` flag (string, default: `us-east-1`).
- Add `--fireprox-max-requests` flag (int, default: `500000`).
- Wire flags to `wildcard_flow.RunConfig`.

#### [MODIFY] [config.go](file:///c:/Users/vishn/Desktop/chaathan/cli/config.go)
- Add CLI commands to set/verify AWS keys: `chaathan config set aws.key_id <key>` and `chaathan config set aws.secret_key <secret>`.

---

## Verification Plan

### Automated Tests
- **Unit Tests**:
  - Run `go test ./pkg/proxy_scraping/...` to test API Gateway URL parsing, `SanitizeURL` output cleaning, and error handling for missing AWS credentials.
  - Run `go test ./...` and `go vet ./...` to verify zero regressions.
- **Build Verification**:
  - Execute `go build -buildvcs=false -o chaathan .` to verify successful compilation.

### Manual Verification
1. **Mock Gateway Provisioning**: Run `chaathan config set aws.key_id TEST` and test credentials validation.
2. **End-to-End Test Scan**:
   - Run `chaathan wildcard example.com --fireprox --skip-nuclei --skip-naabu` with a test AWS account.
   - Inspect output logs to confirm requests to `example.com` are dispatched through `https://<id>.execute-api.us-east-1.amazonaws.com/fireprox/`.
   - Verify origin IP changes on every HTTP request by checking target web server access logs or `httpbin.org/ip`.
   - Confirm automatic URL sanitization in SQLite DB and generated reports (showing `example.com` instead of AWS URLs).
   - Confirm automatic destruction of the AWS API Gateway resource when the scan finishes or is interrupted via `Ctrl+C`.
