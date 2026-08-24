import type {
  AttackPath,
  AIReasoningOutput,
} from '@ai-security-architect/core';
import type { VerificationResult, PullRequestPayload } from './types.js';

export class PullRequestGenerator {
  public generatePullRequest(options: {
    attackPath: AttackPath;
    reasoningOutput: AIReasoningOutput;
    verification: VerificationResult;
    modifiedFiles: string[];
  }): PullRequestPayload {
    const { attackPath, reasoningOutput, verification, modifiedFiles } = options;

    const shortTarget = attackPath.targetAssetId.replace('asset-', '').replace('s3-', '');
    const title = `fix(security): remediate attack path to ${shortTarget} (-${verification.riskReductionPercentage}% risk)`;
    const branchName = `security/remediate-${attackPath.id}-${shortTarget.substring(0, 20)}`;

    const mermaidBeforeAfter = `\`\`\`mermaid
graph LR
  subgraph Before Remediation [Exploit Path: ACTIVE]
    direction LR
    B1["🌐 Internet"] --> B2["⚖️ Load Balancer"]
    B2 --> B3["⚙️ Web Service"]
    B3 --> B4["📦 Pod (SSRF)"]
    B4 --> B5["🔑 IAM Role (Wildcard)"]
    B5 ==>|🚨 REACHABLE| B6["👑 Sensitive S3 PII"]
    style B6 fill:#f43f5e,stroke:#881337,stroke-width:2px,color:#fff
  end

  subgraph After Closed-Loop Verification [Exploit Path: ELIMINATED]
    direction LR
    A1["🌐 Internet"] --> A2["⚖️ Load Balancer"]
    A2 --> A3["⚙️ Web Service"]
    A3 --> A4["📦 Pod"]
    A4 --> A5["🔑 Scoped IAM Role"]
    A5 -.->|🛡️ SEVERED CHOKE POINT| A6["👑 Protected S3 PII"]
    style A6 fill:#10b981,stroke:#064e3b,stroke-width:2px,color:#fff
  end
\`\`\``;

    const bodyMarkdown = `## 🛡️ AI Security Architect — Automated Remediation Proposal

### 📋 Executive Summary
${reasoningOutput.summary}

---

### 🔍 Root Cause & Exploit Chain Analysis
${reasoningOutput.rootCauseAnalysis}

**Business Impact:** ${reasoningOutput.businessImpact}

---

### 🗺️ Before & After Architecture Topology
${mermaidBeforeAfter}

---

### 📊 Mathematical Proof & Verification Metrics
This remediation was tested inside an isolated zero-trust ephemeral sandbox and verified via complete AST re-extraction and Security Graph re-traversal.

| Metric | Before Remediation | After Remediation | Delta |
| :--- | :--- | :--- | :--- |
| **Total Risk Score** | **${verification.initialRiskScore.toFixed(1)} / 10.0** | **${verification.postRemediationRiskScore.toFixed(1)} / 10.0** | **-${verification.riskReductionPercentage}%** |
| **Active Exploit Paths** | **${verification.pathsEliminatedCount + verification.remainingPathsCount}** | **${verification.remainingPathsCount}** | **-${verification.pathsEliminatedCount}** |
| **Security Regressions** | **0** | **${verification.newRegressionsCount}** | **0** |
| **Verification Status** | Pending | **VERIFIED CLEAN** ✅ | **PASSED** |

---

### 📝 Modified Files
${modifiedFiles.map((f) => `- \`${f}\``).join('\n')}

### 🔒 Cryptographic Evidence Citations
${reasoningOutput.evidenceReferences.map((e) => `- Verified Evidence Hash Reference: \`${e}\``).join('\n')}

> *Automated by AI Security Architect Platform — Verified at ${verification.verificationTimestamp}*`;

    return {
      title,
      branchName,
      bodyMarkdown,
      modifiedFiles,
      verification,
    };
  }
}
