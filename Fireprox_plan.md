# Architectural Blueprint: Fireprox (AWS API Gateway IP Rotator) Integration

This plan outlines the future technical architecture for integrating **Fireprox** (AWS API Gateway IP Rotation) into the **Chaathan** CLI recon and pentesting framework.

When implemented, Fireprox will allow Chaathan target-facing tools (such as `httpx`, `ffuf`, `nuclei`, `katana`, `dalfox`) to transparently route HTTP requests through dynamically created AWS API Gateway endpoints. Each outbound request will originate from a different AWS IP address, effectively neutralizing IP-based rate limiting, Cloudflare IP blocks, and WAF bans.

---

## User Review Required

> [!IMPORTANT]
> **AWS Account Credentials Required**: Fireprox requires valid AWS API Access Keys (`AWS_ACC_KEY_ID` and `AWS_SEC_ACCESS_KEY`) with permissions to create and destroy API Gateway resources (`apigateway:*`).
>
> **AWS Free Tier / Cost Considerations**: AWS provides **1,000,000 free API Gateway calls/month**. Usage exceeding 1M calls is billed at ~$1.00 - $3.50 per million calls. The implementation will include a configurable max-request safeguard.

---

## Open Questions for Future Implementation

1. **Native Go AWS SDK vs. Python Fireprox CLI Wrapper**:
   - *Option A (CLI Wrapper):* Depend on the Python `fireprox` utility listed in `pkg/tools/registry.go` and invoke it via `pkg/runner`.
   - *Option B (Native Go Integration - Recommended):* Use `aws-sdk-go-v2` directly inside a new `pkg/fireprox/` package to create/destroy API Gateway endpoints natively without requiring Python or external binary dependencies.

2. **Target Scope (Single Host vs. Multi-Domain)**:
   - AWS API Gateway pass-through proxies map 1-to-1 to a target base URL (e.g. `https://target.com`). Should Chaathan automatically spawn temporary Fireprox gateways per discovered live HTTP host or create a central multi-tenant gateway?

---

## Proposed Changes

The changes span configuration, tool registry, proxy management, workflow context, and CLI flags.

### Configuration Layer

#### [MODIFY] [config.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/config/config.go)
- Add `AWSConfig` struct under `Config` to store AWS credentials and default region (`us-east-1`):
  ```go
  type AWSConfig struct {
      AccessKeyID     string `yaml:"key_id"`
      SecretAccessKey string `yaml:"secret_key"`
      Region          string `yaml:"region"`
      EnableFireprox  bool   `yaml:"enable_fireprox"`
  }
  ```
- Extend `ProxyScrapingConfig` or general `Proxy` settings to support Fireprox dynamic endpoint URLs.

---

### Tools & Dependency Layer

#### [MODIFY] [registry.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/tools/registry.go)
- Add `fireprox` to `AllTools` catalogue under the `"Proxy"` category:
  ```go
  {"fireprox", "Proxy", "AWS API Gateway IP rotator for WAF/rate-limit bypass", false, ""}
  ```

---

### Fireprox Orchestration Package

#### [NEW] [fireprox.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/proxy_scraping/fireprox.go)
Create `pkg/proxy_scraping/fireprox.go` (or a dedicated `pkg/fireprox/` package) to manage the AWS API Gateway lifecycle:
- **`CreateGateway(ctx, targetURL) (proxyURL string, gatewayID string, err error)`**: Provisions an API Gateway pass-through proxy pointing to `targetURL` and deploys it to the `fireprox` stage.
- **`DeleteGateway(ctx, gatewayID) error`**: Deallocates the API Gateway resource upon scan completion or signal cancellation (`SIGINT`/`SIGTERM`) to avoid AWS orphan resources.
- **`GetRotatorProxy()`**: Returns the API Gateway endpoint for tools (`httpx`, `ffuf`, `nuclei`) to target.

---

### Workflow Orchestration & Cleanup

#### [MODIFY] [flow.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/flow.go)
- Add `UseFireprox` boolean to `RunConfig`.
- In `Run()`, during scan context initialization:
  - If `UseFireprox` is enabled, invoke `fireprox.CreateGateway()` for the target domain.
  - Inject the returned Fireprox endpoint URL into `c.Files.FireproxURL` and pass it to down-stream steps (`probing`, `crawling`, `fuzzing`, `nuclei`).
  - Register cleanup hooks in defer / cancellation handlers to ensure `DeleteGateway()` is always invoked.

---

### CLI Layer

#### [MODIFY] [wildcard.go](file:///c:/Users/vishn/Desktop/chaathan/cli/wildcard.go)
- Add `--fireprox` flag (boolean, default: `false`).
- Add `--aws-region` flag (string, default: `us-east-1`).
- Wire flags to `wildcard_flow.RunConfig`.

#### [MODIFY] [config.go](file:///c:/Users/vishn/Desktop/chaathan/cli/config.go)
- Add CLI commands to set/verify AWS keys: `chaathan config set aws.key_id <key>` and `chaathan config set aws.secret_key <secret>`.

---

## Verification Plan

### Automated Tests
- **Unit Tests**:
  - Run `go test ./pkg/proxy_scraping/...` to test API Gateway URL parsing, header rewrite logic, and error handling for missing AWS credentials.
  - Run `go test ./...` and `go vet ./...` to verify zero regressions.
- **Build Verification**:
  - Execute `go build -buildvcs=false -o chaathan .` to verify successful compilation.

### Manual Verification
1. **Mock Gateway Provisioning**: Run `chaathan config set aws.key_id TEST` and test credentials validation.
2. **End-to-End Test Scan**:
   - Run `chaathan wildcard example.com --fireprox --skip-nuclei --skip-naabu` with a test AWS account.
   - Inspect output logs to confirm requests to `example.com` are dispatched through `https://<id>.execute-api.us-east-1.amazonaws.com/fireprox/`.
   - Verify origin IP changes on every HTTP request by checking target web server access logs or `httpbin.org/ip`.
   - Confirm automatic destruction of the AWS API Gateway resource when the scan finishes or is interrupted via `Ctrl+C`.
