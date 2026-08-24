# AI Security Architect — Feature Matrix & Roadmap

> **"Deterministic systems establish security facts. The graph establishes relationships. The AI reasons over those facts."**

---

## 🧭 Executive Overview

**AI Security Architect** is an enterprise-grade security reasoning and attack-path analysis platform. It moves beyond disconnected, noisy alert lists by constructing a queryable, multi-layer security graph connecting code, APIs, container manifests, Kubernetes clusters, Terraform infrastructure, IAM identities, and cloud data assets.

---

## 🚀 1. What It Does (Current Capabilities — Milestone 1)

### 🛡️ Core Foundations & Domain Model (`@ai-security-architect/core`)
* **Strict Type Safety & Schemas**: Comprehensive domain models powered by Zod (`Asset`, `Relationship`, `Finding`, `Evidence`, `AttackPath`, `AIContract`).
* **Cryptographic Evidence Generator**: Every security finding and relationship is bound to an immutable `Evidence` record with line-level bounds and SHA-256 snippet hashing.
* **Explainable Risk Formulation**: Transparent risk scoring:
  $$\text{Risk} = (\text{Impact} \times 0.3 + \text{Exploitability} \times 0.3 + \text{Asset Criticality} \times 0.4) \times \text{Reachability} \times \text{Confidence}$$

### 🔒 Zero-Trust Ingestion & Sandboxing (`@ai-security-architect/ingestion`)
* **Ephemeral Workspaces**: Isolated scan directories created on-demand and securely shredded after execution.
* **Directory Traversal & Symlink Defense**: Path normalization blocks `../` directory escapes; symlink targets are inspected to prevent escapes outside the workspace.
* **Child Process Isolation & Secret Scrubbing**: Host credentials (`AWS_*`, `GITHUB_*`, `SSH_*`, API keys, and passwords) are sanitized before executing sub-processes.
* **Execution Guardrails**: Enforces PID timeouts with `SIGTERM` $\to$ `SIGKILL` escalation and maximum buffer caps to prevent resource exhaustion attacks.
* **Asynchronous Scan Coordinator**: State machine managing `QUEUED` $\to$ `ACQUIRING` $\to$ `SANDBOXING` $\to$ `ANALYZING` $\to$ `COMPLETED` / `FAILED`.

### 🔍 Discovery Engine & Code/IaC AST Extraction (`@ai-security-architect/discovery`)
* **Java / Spring Boot Extractor**: Discovers `@RestController` and `@Controller` classes, mapping `@RequestMapping`, `@GetMapping`, `@PostMapping`, etc. into `SERVICE`, `API_CONTROLLER`, and `ENDPOINT` assets.
* **Kubernetes Manifest Extractor**: Parses multi-manifest YAMLs (`Deployment`, `Pod`, `Service`, `ServiceAccount`), extracting container configurations, ports, and EKS IAM role annotations (`eks.amazonaws.com/role-arn`).
* **Terraform IaC Extractor**: Extracts public vs. internal Application Load Balancers (`aws_lb`), IAM roles (`aws_iam_role`), policies (`aws_iam_role_policy`), and S3 buckets (`aws_s3_bucket`) with classification tags.
* **Dockerfile & Dependency Extractors**: Analyzes container base images, exposed ports, root user flags, and dependencies from Maven (`pom.xml`) and NPM (`package.json`).
* **Cross-Layer Topology Linker**: Automatically infers cross-layer architectural relationships:
  * `LOAD_BALANCER` $\to$ `SERVICE` (`ROUTES_TO`)
  * `SERVICE` $\to$ `POD` (`DEPLOYED_TO`)
  * `KUBERNETES_SERVICE_ACCOUNT` $\to$ `IAM_ROLE` (`ASSUMES_ROLE`)
  * `IAM_ROLE` $\to$ `BUCKET` (`CAN_READ`)

### ⚡ Deterministic Security Analyzers (`@ai-security-architect/analyzers`)
* **Secret Analyzer**: Regex and pattern scanner identifying AWS keys, GitHub personal access tokens, and private keys.
* **SAST Code Analyzer**: Detects critical application flaws such as Server-Side Request Forgery (`SSRF-SPRING-URL-CONNECTION` / CWE-918) and SQL Injection (`SQLI-RAW-CONCATENATION` / CWE-89).
* **IaC Terraform Analyzer**: Flags critical cloud misconfigurations, including wildcard IAM permissions (`IAM-WILDCARD-S3-PERMISSION`, `s3:*` on `*`) and unencrypted public HTTP listeners.
* **SCA Dependency Analyzer**: Evaluates third-party dependencies against known CVEs (Log4Shell, Spring4Shell, Axios SSRF).
* **Analyzer Runner**: Concurrent scanner runner that enforces strict Zod schema validation across all findings.

---

## 🔮 2. What It Is Going To Do (Immediate Roadmap — Milestones 2 & 3)

### 🕸️ Phase 4 — Security Graph Engine & Entity Resolution (Weeks 5–6)
* **Adjacency & Relational Graph Store**: High-performance in-memory graph index and PostgreSQL relational schema with recursive adjacency queries.
* **Cross-Layer Entity Resolution**: Advanced heuristic matching connecting code controllers to Kubernetes pods, IAM roles, and cloud data resources via configuration signals, labels, and ARNs.
* **Relationship Typing**: Explicit separation between `DECLARED`, `OBSERVED`, and `INFERRED` graph edges with individual confidence weights.

### 🎯 Phase 5 — Attack Path Traversal & Min-Cut Remediation Engine (Weeks 7–8)
* **Entry-to-Crown-Jewel Traversal**: Breadth-First & Dijkstra shortest-path algorithms computing complete exploit paths from public entry points (`INTERNET`, `PUBLIC_API`) to sensitive targets (`PII`, `SECRETS`, `DB`).
* **Weighted Min-Cut / Choke-Point Optimizer**: Graph-cut algorithms that identify the single highest-leverage edge whose removal eliminates the maximum number of critical attack paths with minimal operational blast radius.

### 📊 Phase 6 — Interactive Graph & Attack Path Visualizer UI (Week 8)
* **React + React Flow Canvas**: Modern, high-performance web canvas supporting zooming, panning, node filtering, and search.
* **Exploit Path Highlighting**: Visual glowing paths indicating attack vectors and pulsating choke-point markers.
* **Asset & Finding Inspector**: Slide-out drawer displaying asset metadata, technology stack, associated findings, and cryptographic evidence snippets.

### 🧠 Phase 7 — Constrained AI Security Architect (Weeks 9–10)
* **Context Redaction Boundary**: Automatic redaction of secrets, tokens, and proprietary identifiers before LLM prompts.
* **Strict JSON Schema Contracts**: Structured AI outputs for root-cause analysis, business impact, and concrete patch diffs.
* **Hallucination-Free Reasoning**: The AI is strictly constrained to synthesize verified graph facts and immutable evidence.

### 🔄 Phase 8 — Closed-Loop Remediation Verification & Automated PRs (Weeks 10–11)
* **Ephemeral Patch Verification**: Generates code/IaC patches, applies them in an isolated workspace, and re-executes discovery and analyzers.
* **Graph Recalculation**: Verifies that the attack path is mathematically broken (`SECURITY_REMEDIATION_RESOLVED`) before opening a pull request.
* **GitHub PR Automation**: Opens automated PRs with attached verification badges and evidence proofs.

### 🏢 Phase 9 — Enterprise Governance & Evaluation Suite (Weeks 11–12)
* **Multi-Tenancy with RLS**: PostgreSQL Row-Level Security isolating organizations and projects.
* **Resource-Scoped RBAC**: Fine-grained role permissions (`Organization Admin`, `Security Analyst`, `Developer`, `Auditor`).
* **WORM Audit Trail**: Immutable append-only audit event logging for all actions.
* **50+ Benchmark Scenario Suite**: Automated CI evaluation testing against a suite of real-world vulnerable architecture fixtures.

---

## 🌌 3. Future Planned Horizons (Post-MVP — Milestone 4)

### ☁️ Phase 10 — Cloud Connectors & Runtime Drift Detection
* **Multi-Cloud Ingestion**: Real-time connectors for AWS (IAM, CloudTrail, S3, ALB), Azure, and GCP.
* **Infrastructure Drift Detection**: Compares static Terraform declarations against active cloud runtime configurations to surface unmanaged exposure.
* **Runtime Telemetry Overlay**: Ingests eBPF and OpenTelemetry network flows to promote relationships from `DECLARED` to `OBSERVED`.

### 🤖 Phase 11 — AI Systems Security (OWASP Top 10 for LLMs)
* **AI Agent Topology Scanning**: Discovers LangChain, LlamaIndex, and Semantic Kernel agent architectures.
* **Agentic Threat Detection**: Maps prompt injection paths, unsafe tool invocation permissions, vector database data leaks, and excessive agency.
