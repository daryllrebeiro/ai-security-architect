# ADR-002: Relational Graph Engine & Adjacency Representation

## Status
Accepted

## Context
The platform requires graph modeling of code components, endpoints, containers, cloud resources, permissions, and vulnerabilities. While dedicated graph databases (like Neo4j) offer native cypher queries, introducing a separate graph database in early milestones complicates multi-tenancy, ACID transactions, backup operations, and local developer setups.

## Decision
We represent the Security Graph using an adjacency-backed relational model (Assets, Relationships, Findings, Evidence) in PostgreSQL / in-memory graph index, utilizing recursive CTEs and indexed adjacency lookups for BFS/DFS and shortest-path/min-cut traversals.

The graph engine is designed behind a clean `SecurityGraphEngine` interface so dedicated graph backends (e.g. Apache AGE, Neo4j) can be swapped in without modifying domain callers.

## Consequences
* **Positive**: Unified relational transactions, simple Row-Level Security (RLS) for multi-tenancy, no second database engine required for MVP.
* **Negative**: Extremely deep graph traversals (>10 hops across 1M nodes) may require optimization or future migration to a specialized graph store.
