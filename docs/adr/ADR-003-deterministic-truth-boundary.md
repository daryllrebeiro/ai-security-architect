# ADR-003: Deterministic Truth Boundary & AI Grounding

## Status
Accepted

## Context
LLMs frequently hallucinate security findings, miss syntactic nuances, or misinterpret reachability when given unbounded context. In security, false positives cause alert fatigue, while hallucinated attack paths undermine developer trust.

## Decision
We enforce a strict **Deterministic Truth Boundary**:
1. All security findings, AST nodes, permissions, and network topologies must be discovered deterministically by code parsers, IaC analyzers, and scanners (Semgrep, Trivy, Gitleaks, Checkov).
2. The Security Graph deterministically calculates reachability, attack paths, and min-cut choke points.
3. The LLM functions strictly as a **reasoning and synthesis layer** over verified graph chains. The LLM cannot create assets, invent vulnerabilities, or modify calculated risk scores.
4. Every security claim presented to the user must link directly to an immutable, cryptographically hashed `Evidence` record.

## Consequences
* **Positive**: 0% hallucinated vulnerabilities, completely auditable risk scoring, explainable attack paths.
* **Negative**: Requires robust deterministic analyzers and entity resolution logic upfront.
