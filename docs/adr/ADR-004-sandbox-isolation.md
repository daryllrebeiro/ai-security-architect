# ADR-004: Zero-Trust Sandboxed Workspace Isolation

## Status
Accepted

## Context
Analyzing customer source code and executing scanners is equivalent to processing untrusted input and running third-party code. Malicious repositories can include malicious build scripts, symlink attacks, or prompt injection payloads.

## Decision
All repository acquisition and scanning operations must execute inside an ephemeral, resource-constrained sandbox:
* Read-only root filesystem with dedicated ephemeral scratch space.
* Dropped Linux capabilities (`CAP_DROP=ALL`).
* Disabled egress network connectivity during analysis.
* Hard limits on CPU, Memory, File Descriptors, and Process IDs.
* Automatic cleanup and secure shredding of ephemeral workspace directories after scan completion.

## Consequences
* **Positive**: Immune to remote code execution and data exfiltration from analyzed repositories.
* **Negative**: Scanners requiring internet access (e.g. dynamic vulnerability database downloads) must use pre-seeded local databases.
