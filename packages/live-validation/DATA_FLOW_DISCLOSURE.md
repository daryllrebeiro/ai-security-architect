# Data Flow Disclosure: Continuous Live Validation (@ai-security-architect/live-validation)

## 1. Boundary & Network Egress Overview
The `live-validation` module performs empirical, non-destructive reachability and security guardrail verification against external and internal customer-owned endpoints to detect drift between declared IaC/Kubernetes graph models and active runtime behavior.

## 2. Specific Data Leaving the Environment
| Transmission Type | Data Contents | Confidentiality Risk |
| :--- | :--- | :--- |
| **HTTP Handshake** | Standard `GET` or `HEAD` request line, `User-Agent: ai-security-architect-live-probe/1.0`, `Accept: */*`. No credentials, cookies, tokens, or business payloads are transmitted. | **None / Zero Payload** |
| **TLS Probing** | Standard TLS `ClientHello` handshake message. Queries server certificate chain, expiration date, and cipher suites. | **None / Public Metadata** |
| **Auth Verification** | Unauthenticated probe request to sensitive endpoint path (e.g. `/api/v1/admin`) to confirm rejection with HTTP 401/403. | **None / Unauthenticated Request** |

## 3. Destination Endpoints
- Probes are strictly restricted to the customer's explicitly pre-approved `allowedEndpoints` list configured in `sec-arch.config.yaml`.
- **Hard Guardrail**: Under no circumstances does the probe engine auto-discover, crawl, or send packets to any endpoint not present in `allowedEndpoints`. Attempting to probe an unlisted endpoint immediately throws `DisallowedEndpointError`.

## 4. Default Configuration & Opt-In Safeguards
- **Default State**: `enabled: false`.
- **Required Opt-In**:
  ```yaml
  liveValidation:
    enabled: true
    rateLimitPerSecond: 2
    timeoutMs: 5000
    allowedEndpoints:
      - "https://api.example.com/health"
      - "https://internal.example.com/metrics"
  ```
- **Execution Mode**: Out-of-band scheduled job only (never triggered within per-PR CI scans to prevent unauthorized probing from untrusted pull requests).
