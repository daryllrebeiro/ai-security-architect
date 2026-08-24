# AI Security Architect

[![Node.js](https://img.shields.io/badge/Node.js-v24%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-v5.5-blue.svg)](https://www.typescriptlang.org/)
[![Vitest](https://img.shields.io/badge/Tested%20with-Vitest-yellow.svg)](https://vitest.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **"Deterministic systems establish security facts. The graph establishes relationships. The AI reasons over those facts."**

**AI Security Architect** is an enterprise security reasoning platform that constructs a queryable, multi-layer security graph connecting source code ASTs, REST APIs, containers, Kubernetes clusters, Infrastructure-as-Code (Terraform), IAM permissions, and sensitive cloud data assets.

---

## 🌟 Key Differentiators

1. **Deterministic Truth Boundary**: The LLM never hallucinates security findings or assets. All facts are discovered deterministically by parsers and static analyzers.
2. **Cross-Layer Entity Resolution**: Connects application code endpoints through Kubernetes pods and IAM role assumptions to cloud storage buckets.
3. **Attack Path Engine**: Computes reachable exploit chains from public internet entry points to critical business assets with explainable risk scores.
4. **Min-Cut Choke-Point Remediation**: Mathematically computes the highest-leverage single change that breaks the maximum number of critical attack paths with minimal blast radius.
5. **Closed-Loop Verification**: Re-scans proposed fixes in an ephemeral sandbox to prove attack path elimination before creating Pull Requests.

---

## 🏗️ Architecture Overview

```text
                         ┌─────────────────────────────────────────┐
                         │         Web Dashboard / UI             │
                         │ Interactive Canvas • Graph • Risk • AI │
                         └────────────────────┬────────────────────┘
                                              │ API / WebSocket
                         ┌────────────────────▼────────────────────┐
                         │              Control Plane              │
                         │    Multi-Tenant • RBAC • Audit • API   │
                         └────────────────────┬────────────────────┘
                                              │
             ┌────────────────────────────────┼────────────────────────────────┐
             │                                │                                │
             ▼                                ▼                                ▼
    Discovery Engine                 Security Analyzers                Reasoning & AI
(AST, IaC, K8s, Container)        (Gitleaks, Trivy, Checkov)        (Context Builder, Schema)
             │                                │                                │
             └────────────────────────────────┼────────────────────────────────┘
                                              ▼
                                   ┌────────────────────┐
                                   │   Security Graph   │
                                   │ Adjacency • Relational │
                                   └──────────┬─────────┘
                                              │
                                              ▼
                                   ┌────────────────────┐
                                   │ Attack Path Engine │
                                   │ Traversal • Scoring│
                                   └──────────┬─────────┘
                                              │
                                              ▼
                                   ┌────────────────────┐
                                   │ Min-Cut Optimizer  │
                                   │ Choke-Point Engine │
                                   └──────────┬─────────┘
                                              │
                                              ▼
                                   ┌────────────────────┐
                                   │ AI Security        │
                                   │ Architect Agent    │
                                   └──────────┬─────────┘
                                              │
                                              ▼
                                   ┌────────────────────┐
                                   │ Remediation        │
                                   │ Verification Loop  │
                                   └────────────────────┘
```

---

## 📦 Workspace Package Structure

| Package | Purpose | Status |
| :--- | :--- | :--- |
| **[`@ai-security-architect/core`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/core)** | Canonical domain models (`Asset`, `Relationship`, `Finding`, `Evidence`, `AttackPath`, `AIContract`) and Zod schemas. | ✅ Phase 0 Complete |
| **[`@ai-security-architect/ingestion`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/ingestion)** | Ephemeral workspace manager, zero-trust path sandboxing, process runner with credential scrubbing, and scan job coordinator. | ✅ Phase 1 Complete |
| **[`@ai-security-architect/discovery`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/discovery)** | AST parsers for Spring Boot controllers, Kubernetes manifests, Terraform IaC, Dockerfiles, and dependencies. | ✅ Phase 2 Complete |
| **[`@ai-security-architect/analyzers`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/analyzers)** | Deterministic security analyzers: Secret scanner, SAST SSRF/SQLi detector, IaC overprivilege analyzer, and SCA CVE matcher. | ✅ Phase 3 Complete |
| **`@ai-security-architect/graph`** | Security Graph Engine, relational adjacency store, and cross-layer entity resolution. | 🚧 Phase 4 Next |
| **`@ai-security-architect/attackpath`** | Graph traversal, explainable risk scoring, and weighted min-cut choke-point optimizer. | 🚧 Phase 5 |
| **`@ai-security-architect/ai`** | Constrained AI Security Architect reasoning engine, context builder, and patch generator. | 🚧 Phase 7 |
| **`@ai-security-architect/web`** | React + React Flow interactive security graph canvas and attack path explorer. | 🚧 Phase 6 |

---

## 🚀 Quickstart & Development

### Prerequisites
* Node.js v20+ or v24+
* npm v10+

### Setup
```bash
# Clone the repository
git clone https://github.com/daryllrebeiro/ai-security-architect.git
cd ai-security-architect

# Install all workspace dependencies
npm install

# Run the test suite
npm test

# Run TypeScript compiler check
npx tsc --noEmit
```

---

## 📚 Detailed Documentation

* [Master Implementation Roadmap (`InitialPlan.md`)](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/InitialPlan.md): Complete 12-phase specification across 4 milestones.
* [Feature Matrix & Future Plans (`FEATURES.md`)](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/FEATURES.md): Deep-dive into current capabilities, upcoming features, and future horizons.
* [Architecture Decision Records (`docs/adr/`)](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/docs/adr):
  * [ADR-001: Modular Monolith Architecture](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/docs/adr/ADR-001-modular-monolith.md)
  * [ADR-002: Relational Graph Engine & Adjacency Representation](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/docs/adr/ADR-002-relational-graph-engine.md)
  * [ADR-003: Deterministic Truth Boundary & AI Grounding](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/docs/adr/ADR-003-deterministic-truth-boundary.md)
  * [ADR-004: Zero-Trust Sandboxed Workspace Isolation](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/docs/adr/ADR-004-sandbox-isolation.md)
  * [ADR-005: Canonical Immutable Evidence Architecture](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/docs/adr/ADR-005-canonical-evidence-model.md)
  * [ADR-006: Constrained AI Context Handoff & Schema Enforcement](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/docs/adr/ADR-006-constrained-ai-contract.md)
  * [ADR-007: Closed-Loop Remediation Verification & PR Engine](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/docs/adr/ADR-007-closed-loop-remediation-verification.md)
* [Reference Security Benchmark (`fixtures/001-ssrf-iam-s3/`)](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/fixtures/001-ssrf-iam-s3): End-to-end vulnerable microservice architecture fixture.