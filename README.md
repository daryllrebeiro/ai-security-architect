# AI Security Architect

[![Node.js](https://img.shields.io/badge/Node.js-v24%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-v5.5-blue.svg)](https://www.typescriptlang.org/)
[![Vitest](https://img.shields.io/badge/Tested%20with-Vitest-yellow.svg)](https://vitest.dev/)
[![Tests](https://img.shields.io/badge/Tests-54%2F54%20Passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **"Deterministic systems establish security facts. The graph establishes relationships. The AI reasons over those facts."**

**AI Security Architect** is an enterprise security reasoning platform that constructs a queryable, multi-layer security graph connecting source code ASTs, REST APIs, containers, Kubernetes clusters, Infrastructure-as-Code (Terraform), IAM permissions, and sensitive cloud data assets.

---

## 🌟 Core Capabilities

1. **Deterministic Truth Boundary**: The LLM never hallucinates security findings or assets. All facts are discovered deterministically by parsers and static analyzers.
2. **Cross-Layer Entity Resolution**: Connects application code endpoints through Kubernetes pods and IAM role assumptions to cloud storage buckets.
3. **Attack Path Engine**: Computes reachable exploit chains from public internet entry points to critical business assets with explainable risk scores.
4. **Min-Cut Choke-Point Remediation**: Mathematically computes the highest-leverage single change that breaks the maximum number of critical attack paths with minimal blast radius.
5. **Closed-Loop Verification**: Re-scans proposed fixes in an ephemeral sandbox to prove attack path elimination before creating Pull Requests.
6. **Interactive Canvas Visualizer**: React Flow UI with real-time choke-point severing simulator.
7. **Unified `sec-arch` CLI & CI/CD Gate**: Terminal scanner, SARIF 2.1.0 exporter, and GitHub Action pull request gate.
8. **Enterprise Governance**: Multi-Tenancy RLS, fine-grained RBAC matrix, and append-only cryptographic WORM audit logger.

---

## 🏗️ Architecture Overview

```text
                         ┌─────────────────────────────────────────┐
                         │         Web Dashboard / UI              │
                         │ Interactive Canvas • Graph • Risk • AI  │
                         └────────────────────┬────────────────────┘
                                              │ API / WebSocket
                         ┌────────────────────▼────────────────────┐
                         │              Control Plane              │
                         │    Multi-Tenant • RBAC • WORM Audit     │
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

## 📦 Workspace Packages

All 12 workspace packages are fully implemented, typed, and tested:

| Package | Purpose | Status |
| :--- | :--- | :--- |
| **[`@ai-security-architect/core`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/core)** | Canonical domain models (`Asset`, `Relationship`, `Finding`, `Evidence`, `AttackPath`, `AIContract`) and Zod schemas. | ✅ Phase 0 Complete |
| **[`@ai-security-architect/ingestion`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/ingestion)** | Ephemeral workspace manager, zero-trust path sandboxing, process runner with credential scrubbing, and scan job coordinator. | ✅ Phase 1 Complete |
| **[`@ai-security-architect/discovery`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/discovery)** | AST parsers for Spring Boot controllers, Kubernetes manifests, Terraform IaC, Dockerfiles, and dependencies. | ✅ Phase 2 Complete |
| **[`@ai-security-architect/analyzers`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/analyzers)** | Deterministic security analyzers: Secret scanner, SAST SSRF detector, and IaC overprivilege analyzer. | ✅ Phase 3 Complete |
| **[`@ai-security-architect/graph`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/graph)** | Security Graph Engine, relational adjacency store, and cross-layer entity resolution. | ✅ Phase 4 Complete |
| **[`@ai-security-architect/attackpath`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/attackpath)** | Graph traversal, explainable risk scoring, and weighted min-cut choke-point optimizer. | ✅ Phase 5 Complete |
| **[`@ai-security-architect/web`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/web)** | React + React Flow interactive security graph canvas and attack path explorer. | ✅ Phase 6 Complete |
| **[`@ai-security-architect/ai`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/ai)** | Constrained AI Security Architect reasoning engine, context builder, and patch generator. | ✅ Phase 7 Complete |
| **[`@ai-security-architect/remediation`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/remediation)** | Closed-loop verification runner, sandbox patch applier, and PR markdown generator. | ✅ Phase 8 Complete |
| **[`@ai-security-architect/enterprise`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/enterprise)** | Multi-Tenancy RLS guard, 5-role RBAC matrix, and cryptographic WORM audit logger. | ✅ Phase 9 Complete |
| **[`@ai-security-architect/cache`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/cache)** | AST content-hash caching, incremental graph delta engine, and concurrency worker pool. | ✅ Phase 10 Complete |
| **[`@ai-security-architect/cli`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/cli)** | Unified `sec-arch` CLI binary, SARIF 2.1.0 report exporter, and GitHub Actions workflow. | ✅ Phase 11 & 12 Complete |

---

## 🚀 Quickstart & Development

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/daryllrebeiro/ai-security-architect.git
cd ai-security-architect

# Install all workspace dependencies
npm install

# Run the complete test suite across all 12 packages
npm test

# Run TypeScript compiler check
npx tsc --noEmit
```

### 2. Local Repository Scan (`sec-arch`)
```bash
# Terminal table output
npx sec-arch scan ./fixtures/001-ssrf-iam-s3

# Export to OASIS SARIF 2.1.0 format
npx sec-arch scan ./fixtures/001-ssrf-iam-s3 --format=sarif

# Interactive AI Remediation with Closed-Loop Verification
npx sec-arch remediate ./fixtures/001-ssrf-iam-s3 --path=path-001
```

### 3. Launch Interactive Web Visualizer
```bash
cd packages/web
npm run dev
```
Open `http://localhost:5173` to explore the interactive canvas, sever choke points, and observe real-time risk reduction.

---

## 🏆 Enterprise Security Benchmark Suite

The platform includes 3 automated golden reference architectures:

1. **Scenario 001 (`fixtures/001-ssrf-iam-s3`)**:
   - **Vector**: Public ALB $\to$ Spring Boot SSRF $\to$ IMDS $\to$ Wildcard IAM Role $\to$ Sensitive S3 PII Exfiltration.
   - **Remediation**: Re-scoped IAM policy in ephemeral sandbox eliminates path (100% risk reduction).
2. **Scenario 002 (`fixtures/002-k8s-rbac-secrets`)**:
   - **Vector**: Public Ingress $\to$ Payment Service $\to$ K8s ServiceAccount $\to$ Overprivileged IAM Role $\to$ Financial Vault S3 Bucket.
3. **Scenario 003 (`fixtures/003-cicd-supply-chain`)**:
   - **Vector**: GitHub Actions Script Injection $\to$ Hardcoded AWS Credentials $\to$ Production Artifact Release Bucket.

---

## 📚 Documentation

* [Master Implementation Roadmap (`InitialPlan.md`)](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/InitialPlan.md)
* [Feature Matrix & Phase Specifications (`FEATURES.md`)](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/FEATURES.md)
* [Implementation Walkthrough (`walkthrough.md`)](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/walkthrough.md)
* [GitHub Action Definition (`action.yml`)](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/action.yml)