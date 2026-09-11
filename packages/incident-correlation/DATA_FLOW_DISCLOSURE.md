# Data Flow Disclosure: Live Incident Response Correlation (@ai-security-architect/incident-correlation)

## 1. Boundary & Ingestion Overview
The Incident Correlation Bridge ingests real-time alert webhooks from third-party SIEM and EDR platforms (e.g. CrowdStrike Falcon, Datadog Security Signals, AWS GuardDuty, Splunk). It resolves compromised assets against the active graph inventory and performs immediate in-memory blast radius and ingress path calculations.

## 2. Specific Data Flow Details
| Direction | Data Type | Contents |
| :--- | :--- | :--- |
| **Inbound Webhook** | Ingestion Payload | Third-party alert metadata: `alertId`, `sourceSystem`, `alertTitle`, `severity`, and concrete target `assetIdentifier` (ARN, instance ID, or exact pod name). |
| **Internal Egress** | Incident Response Dispatch | Blast-radius and min-cut mitigation summary dispatched internally to authorized incident channels (e.g. Slack via `@ai-security-architect/chatops` or internal webhook). |
| **External Egress** | Zero External Transmission | No internal graph topology, code repositories, or customer findings are ever transmitted back to third-party SIEM/EDR providers. |

## 3. Strict Identity Matching Policy
- Matching is deterministic and exact: checks `cloudArnOrId`, canonical `asset.id`, or exact unique `name`.
- **Fuzzy Matching Prohibition**: If an asset identifier cannot be resolved with 100% confidence, or if multiple assets match ambiguously, the correlator immediately returns `REJECTED_AMBIGUOUS`. It never guesses during an active incident.

## 4. Default Configuration & Opt-In Safeguards
- **Default State**: `enabled: false`.
- **Configuration Block**:
  ```yaml
  incidentCorrelation:
    enabled: true
    sourceAllowlist:
      - "crowdstrike"
      - "datadog"
      - "guardduty"
    webhookSecret: "${INCIDENT_WEBHOOK_SECRET}"
    maxTraversalHops: 8
  ```
- **Context Labeling**: Results are structured and persisted exclusively as `LiveIncidentContext`, clearly distinguished from static findings or hypothetical purple team simulations.
