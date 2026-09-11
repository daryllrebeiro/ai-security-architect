# Phase 4 Walkthrough: Enterprise Governance, Risk Quantification & Unified CLI Operations

## Executive Overview
Phase 4 completes the transition of `ai-security-architect` into a full-lifecycle enterprise cyber architecture reasoning platform. It unifies advanced enterprise capabilities—regulatory compliance mapping, FAIR financial risk quantification, automated incident response runbooks, natural language graph querying, purple team attack simulation, policy-as-code security budgets, historical MTTR dashboards, and multi-repo graph federation—under the cohesive `sec-arch` CLI interface and declarative configuration.

---

## Key Capabilities & Implementation Architecture

### 1. Unified CLI Interface (`@ai-security-architect/cli`)
The platform CLI has been expanded to expose 11 dedicated commands organized into Core Operations and Enterprise Governance:

```
sec-arch <command> [path] [options]
```

| Category | Command | Underlying Package | Description |
| :--- | :--- | :--- | :--- |
| **Core** | `scan <path>` | `@ai-security-architect/graph`, `attackpath` | Ingests repo, builds security graph, traverses multi-hop attack paths, and computes min-cut choke points. |
| **Core** | `remediate <path>` | `@ai-security-architect/remediation` | Closed-loop AI remediation with dry-run sandbox verification. |
| **Core** | `agent <path>` | `@ai-security-architect/agent` | Autonomous iterative multi-model agent with rollback and human approval gates. |
| **Core** | `lsp` | `@ai-security-architect/lsp-server` | Real-time IDE Language Server Protocol for in-editor diagnostic squiggles. |
| **Enterprise** | `compliance <path>` | `@ai-security-architect/compliance` | Evaluates attack paths against SOC2, PCI-DSS, ISO27001, HIPAA, and NIST controls. |
| **Enterprise** | `fair <path>` | `@ai-security-architect/risk-quant` | FAIR cyber risk model calculating Annualized Loss Expectancy (ALE) and Single Loss (SLE). |
| **Enterprise** | `runbook <path>` | `@ai-security-architect/runbooks` | Generates step-by-step incident response playbook with preflight, execution, and rollback. |
| **Enterprise** | `query <path> "<q>"` | `@ai-security-architect/nl-query` | Natural language questions answered with deterministic graph grounding and evidence links. |
| **Enterprise** | `simulate <path>` | `@ai-security-architect/attackpath` | Purple Team threat modeling simulating lateral movement from assumed breached assets. |
| **Enterprise** | `policy <path>` | `@ai-security-architect/policy` | Policy-as-code enforcement evaluating security budgets (PR thresholds, max risk scores). |
| **Enterprise** | `dashboard <path>` | `@ai-security-architect/dashboard` | Generates historical risk trend burndown and MTTR tracking HTML report. |

---

### 2. Deep Dive: Enterprise Capabilities

#### Task B.1: Compliance Framework Mapping (`@ai-security-architect/compliance`)
- Evaluates declared architecture against regulatory frameworks: SOC2 (CC6.1, CC6.6), PCI-DSS (Req 1.3, 7.1), ISO 27001 (A.9.1, A.13.1), HIPAA (§164.312), and NIST CSF (PR.AC-4, PR.DS-5).
- Output: Structured markdown compliance posture report or machine-readable JSON.

#### Task B.2: FAIR-Aligned Cyber Risk Financial Quantification (`@ai-security-architect/risk-quant`)
- Computes Threat Event Frequency (TEF), Vulnerability Probability ($V_P$), Loss Event Frequency (LEF), Primary Response Loss, and Secondary Data Breach/Regulatory Losses.
- Quantifies overall portfolio financial risk in Annualized Loss Expectancy (`ALE = LEF * SLE`).

#### Task B.3: Historical MTTR & Risk Burndown Dashboard (`@ai-security-architect/dashboard`)
- Uses SQLite persistent history store (`.sec-arch/history.db`).
- Tracks Mean Time To Remediation (MTTR) strictly for genuinely remediated paths (excluding decommissioned/asset-removed paths to prevent metric tampering).
- Generates interactive self-contained HTML dashboards with embedded SVG risk trend charts.

#### Task B.4: Automated Remediation Runbooks (`@ai-security-architect/runbooks`)
- Generates operational playbooks for breaking optimal min-cut choke points.
- 4-phase standard operating procedure: Pre-Flight Verification Checks, IaC/CLI Execution Steps, Rollback Procedure, and Post-Remediation Verification query.

#### Task A.2: Natural Language Graph Query Interface (`@ai-security-architect/nl-query`)
- Translates conversational questions into structured AST graph queries.
- Executes against the in-memory Security Graph Engine and grounds answers with exact file/line evidence citations and hop-by-hop traversal proofs.

#### Task A.3: Purple Team Threat Modeling & Simulation (`@ai-security-architect/attackpath`)
- Simulates hypothetical adversary breaches at internal compute/service nodes (`assumedBreachedAssetId`).
- Calculates bidirectional blast radius: forward reachability to crown jewels and upstream ingress exposure paths.

#### Task A.4: Policy-as-Code Security Budgets (`@ai-security-architect/policy`)
- Evaluates attack path diffs against organizational error budgets (`maxNewPathsPerPR: 0`, `maxRiskScorePerPath: 8.5`, `maxCriticalPaths: 0`).
- Fails CI/CD pipelines via `--fail` / `--enforce` when architectural drift introduces unbudgeted risk.

---

## Verification & Test Results

### 1. Full Monorepo Vitest Suite: 149 / 149 Passing (37 Suites)
```bash
npx vitest run
```
```
Test Files  37 passed (37)
     Tests  149 passed (149)
  Duration  9.55s
```

### 2. TypeScript Static Typecheck: 0 Errors
```bash
npx tsc --noEmit
```
Exited with code 0 across all 19 workspace packages.

### 3. Frontend Dashboard Build: Clean Compilation
```bash
npm run --workspace=@ai-security-architect/web build
```
```
vite v5.4.21 building for production...
✓ 1725 modules transformed.
dist/index.html                   1.09 kB
dist/assets/index-BLcLyhSB.css   17.94 kB
dist/assets/index-s9gmKJi8.js   369.47 kB
✓ built in 6.14s
```

### 4. Phase 4 CLI Integration Test Matrix
| Command Tested | Test File | Status |
| :--- | :--- | :---: |
| `sec-arch compliance` | [`packages/cli/test/phase4-cli.test.ts`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/cli/test/phase4-cli.test.ts) | ✅ PASS |
| `sec-arch fair` | [`packages/cli/test/phase4-cli.test.ts`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/cli/test/phase4-cli.test.ts) | ✅ PASS |
| `sec-arch runbook` | [`packages/cli/test/phase4-cli.test.ts`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/cli/test/phase4-cli.test.ts) | ✅ PASS |
| `sec-arch query` | [`packages/cli/test/phase4-cli.test.ts`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/cli/test/phase4-cli.test.ts) | ✅ PASS |
| `sec-arch simulate` | [`packages/cli/test/phase4-cli.test.ts`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/cli/test/phase4-cli.test.ts) | ✅ PASS |
| `sec-arch policy` | [`packages/cli/test/phase4-cli.test.ts`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/cli/test/phase4-cli.test.ts) | ✅ PASS |
| `sec-arch dashboard` | [`packages/cli/test/phase4-cli.test.ts`](file:///c:/Users/Lenovo%20Laptop/dev/ai-security-architect/packages/cli/test/phase4-cli.test.ts) | ✅ PASS |

---

## Configuration Reference (`sec-arch.config.yaml`)

```yaml
version: "1.0"
tenantId: "default-tenant"

features:
  cloudConnectors:
    enabled: false
    provider: "AWS"
    region: "us-east-1"
    cacheTtlMinutes: 15

  autonomousAgent:
    enabled: false
    maxIterations: 5
    timeoutSeconds: 120
    maxLlmCalls: 10
    autoApprove: false

  realTimeLsp:
    enabled: false
    debounceMs: 500
    offlineMode: false

  compliance:
    enabled: true
    defaultFrameworks: ["SOC2", "PCI-DSS", "ISO27001", "HIPAA", "NIST"]

  policy:
    enabled: true
    maxNewPathsPerPR: 0
    maxRiskScorePerPath: 8.5
    maxCriticalPaths: 0
    grandfatherExisting: true

  riskQuant:
    enabled: true
    currency: "USD"
    baseForensicCost: 50000
    baseDowntimeCost: 100000
    costPerRecord: 180
    defaultRecordsEstimate: 50000

  dashboard:
    enabled: true
    historyDatabase: ".sec-arch/history.db"

  purpleTeam:
    enabled: true
    maxHops: 10
    defaultMode: "BIDIRECTIONAL"
```
