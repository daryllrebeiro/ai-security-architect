# Phase 13 — Production API & External Observability

## Status
Completed

## Objective
Establish the first production service boundary for the platform and expose scan health, metrics, and lifecycle data to external systems.

## What was implemented
- Added a framework-neutral `ScanJobApi` for job creation, tenant-scoped listing, job lookup, health checks, and Prometheus metrics export.
- Exported the API from the ingestion package so it is available as part of the public package surface.
- Added runtime support for Prometheus text output from `ScanJobMetrics`.
- Added tests validating:
  - health endpoint behavior
  - tenant-scoped job access
  - metrics export payload content
  - API request validation for invalid tenants and paths

## Files changed
- `packages/ingestion/src/scan-job-api.ts`
- `packages/ingestion/src/index.ts`
- `packages/ingestion/src/scan-job-metrics.ts`
- `packages/ingestion/test/ingestion.test.ts`

## Verification
- `npx vitest run packages/ingestion/test/ingestion.test.ts`
- Result: 14/14 tests passed

## Notes
This phase creates the operational boundary needed for future production workflows, dashboards, and CI/CD integration.
