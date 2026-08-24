# ADR-007: Closed-Loop Remediation Verification & PR Engine

## Status
Accepted

## Context
Standard automated security PR tools generate code fixes blindly. Often, a code patch fixes a localized linter warning or CVE but leaves the overall multi-step attack path viable through alternative routes or introduces new misconfigurations.

## Decision
We enforce a **Closed-Loop Remediation Verification** pipeline:
1. The AI generates candidate remediation patches targeting the computed min-cut choke point.
2. In an isolated ephemeral branch, the patch is applied.
3. The platform re-runs the discovery and deterministic security analyzers.
4. The Security Graph and Attack Path Engine recalculate all exploit chains.
5. If and only if the critical attack path is proven eliminated (`SECURITY_REMEDIATION_RESOLVED`), the PR is approved and opened on GitHub with cryptographic verification proofs attached.
6. If the path remains or regressions occur, the status is marked `SECURITY_REMEDIATION_FAILED` and escalated for human architect review.

## Consequences
* **Positive**: Guarantees that opened pull requests genuinely eliminate the architectural security threat.
* **Negative**: Incurs re-scan and graph recalculation computation for proposed fixes.
