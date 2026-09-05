# Phase 17 — Policy-Aware Remediation & Security Command Center

## Status
Completed

## Objective
Turn the platform into a full security operations workflow by adding policy-aware remediation decisions and a concise operator command-center summary.

## What was implemented
- Added `PolicyAwareRemediationPlanner` to reject unsafe or policy-violating patch candidates before they can be applied.
- Added `SecurityCommandCenter` to summarize tenant risk posture, critical issues, and remediation throughput.
- Exported the new planner and command-center modules from the remediation package.
- Added tests covering policy denial for unsafe production changes and concise operator summary output.

## Files changed
- `packages/remediation/src/policy-aware-remediation-planner.ts`
- `packages/remediation/src/security-command-center.ts`
- `packages/remediation/src/index.ts`
- `packages/remediation/src/types.ts`
- `packages/remediation/test/remediation.test.ts`

## Verification
- `npx vitest run packages/remediation/test/remediation.test.ts`
- Result: 5/5 tests passed

## Notes
This phase adds the product-level governance layer needed for safe remediation approvals and operator decision support.
