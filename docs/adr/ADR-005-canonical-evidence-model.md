# ADR-005: Canonical Immutable Evidence Architecture

## Status
Accepted

## Context
When an attack path is presented, security and development teams require clear proof of every premise in the exploit chain. Storing raw scanner output logs is inefficient and unmanageable.

## Decision
Every `Finding` and `Relationship` requiring proof must reference an immutable `Evidence` entity.
An Evidence entity consists of:
* `id` & `tenantId`
* `sourceType` (SOURCE_CODE, TERRAFORM, KUBERNETES, DOCKERFILE, etc.)
* `repository`, `filePath`, `lineStart`, `lineEnd`
* `snippet` & cryptographic `snippetSha256` hash
* `scanner` and creation `timestamp`

Evidence records are append-only and cannot be altered by AI or application mutations.

## Consequences
* **Positive**: Complete traceability, tamper resistance, and easy auditability.
* **Negative**: Requires rigorous line-number tracking across file transformations.
