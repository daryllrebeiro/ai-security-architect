# ADR-001: Modular Monolith Architecture

## Status
Accepted

## Context
AI Security Architect coordinates multiple distinct sub-domains:
1. Repository Acquisition & Sandboxing
2. Discovery & AST Analysis (Code, K8s, Terraform)
3. Deterministic Scanners (Gitleaks, Trivy, Checkov)
4. Security Graph & Entity Resolution
5. Attack Path Engine & Min-Cut Optimization
6. AI Context Builder & Reasoning Engine
7. Closed-Loop Remediation & PR Automation

Splitting these prematurely into independent microservices adds significant network latency, distributed transaction complexity, deployment overhead, and serialization costs during graph construction and traversal.

## Decision
We will build AI Security Architect as a **Modular Monolith** organized into strictly isolated packages under `packages/` with clear public domain APIs. Internal communication happens via in-process typed interfaces.

As operational boundaries dictate (e.g., untrusted worker execution or heavy LLM pipelines), specific modules can be extracted into dedicated worker services without altering core domain semantics.

## Consequences
* **Positive**: Rapid iteration, low latency for graph traversals, single deployable artifact for MVP, simpler integration testing.
* **Negative**: Requires strict discipline to prevent domain coupling across package boundaries.
