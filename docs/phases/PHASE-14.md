# Phase 14 — Durable Execution & Persistent State

## Status
Completed

## Objective
Move the platform from transient in-memory execution to durable, restart-safe job execution with explicit recovery semantics.

## What was implemented
- Added a repository-backed restore flow to `ScanJobCoordinator` so jobs can be rehydrated from disk after process restarts.
- Added `listJobs()` support to the repository for durable state restoration.
- Enabled dependency injection of a custom repository in the coordinator for testable recovery and persistence flows.
- Added a regression test covering job restoration and safe resume from an incomplete execution state.

## Files changed
- `packages/ingestion/src/job-coordinator.ts`
- `packages/ingestion/src/scan-job-repository.ts`
- `packages/ingestion/test/ingestion.test.ts`

## Verification
- `npx vitest run packages/ingestion/test/ingestion.test.ts`
- Result: 15/15 tests passed

## Notes
This phase strengthens the platform for restart recovery, partial progress restoration, and production-grade operational resilience.
