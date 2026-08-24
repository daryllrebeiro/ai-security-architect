# ADR-006: Constrained AI Context Handoff & Schema Enforcement

## Status
Accepted

## Context
Passing full unredacted source repositories to an LLM exposes proprietary secrets, violates data privacy controls, and introduces excessive token noise that degrades reasoning performance.

## Decision
1. **Context Redaction Boundary**: Before handoff to the AI, all secrets, auth tokens, and sensitive customer identifiers are scrubbed.
2. **Deterministic Context Assembly**: The LLM receives only the deterministic metrics, the specific graph chain (nodes, edges), the relevant evidence snippets, and the min-cut choke point recommendation.
3. **Strict Structured Output**: The AI response must conform to `AIReasoningOutputSchema` (root cause, business impact, and concrete patch diffs). Invalid schemas are rejected and re-prompted.

## Consequences
* **Positive**: Maximum privacy, zero secret leakage to LLM providers, focused reasoning on small high-signal context windows.
* **Negative**: The context builder must carefully select only the necessary supporting snippets for the graph chain.
