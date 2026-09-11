# Data Flow Disclosure: Third-Party & Vendor Risk Graph Layer (@ai-security-architect/graph)

## 1. Boundary & External Network Egress Overview
The Vendor Risk Graph Layer correlates outbound data flows with third-party SaaS vendors and external API integrations. When an organization configures external vendor risk intelligence, public risk indicators (certifications, breach alerts) are correlated against identified vendor entities.

## 2. Specific Data Leaving the Environment
| Transmission Type | Data Contents | Confidentiality Risk |
| :--- | :--- | :--- |
| **Vendor Metadata Lookup** | Exact external domain or vendor name query (e.g. `api.stripe.com`, `datadoghq.com`, `sendgrid.com`). Zero internal code, zero customer PII, and zero graph topology are transmitted. | **Low / Public Domain Identity Only** |
| **Questionnaire Ingestion** | Internal/local ingestion of vendor questionnaire scores from internal security GRC exports. No data leaves the environment. | **Zero / Local Ingestion Only** |

## 3. Destination Services
- Public certification registries or vendor security intelligence endpoints (e.g. SOC2 attestation registries, CISA advisory databases) explicitly configured by the organization.

## 4. Default Configuration & Opt-In Safeguards
- **Default State**: `enabled: false`.
- **Labeling Standard**: All vendor risk findings and metrics are explicitly labeled with the visible provenance banner:
  `"(Externally-Sourced Vendor Assessment, not an empirical topology finding)"`
- This ensures external vendor questionnaire claims or lower-confidence public indicators are never conflated with deterministic, IaC-proven graph attack paths.
