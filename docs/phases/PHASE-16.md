# Phase 16 — Real-Time Graph & Async Event Pipeline

## Status
Completed

## Objective
Move the graph layer toward incremental, event-driven security state updates so change consumers can process diffs without full recomputation.

## What was implemented
- Added `createIncrementalDelta()` to `SecurityGraphEngine` to compute graph deltas relative to a previous engine state.
- Extended `GraphSnapshotRepository` with snapshot listing support for diff consumers and live graph change tracking.
- Added regression tests validating:
  - incremental graph changes are detected correctly
  - saved snapshot metadata is listable by tenant
  - stale version invalidation still works with the repository

## Files changed
- `packages/graph/src/security-graph-engine.ts`
- `packages/graph/src/graph-snapshot-repository.ts`
- `packages/graph/test/graph.test.ts`

## Verification
- `npx vitest run packages/graph/test/graph.test.ts`
- Result: 6/6 tests passed

## Notes
This phase establishes the graph delta primitives needed for future async event propagation and near real-time risk updates.
