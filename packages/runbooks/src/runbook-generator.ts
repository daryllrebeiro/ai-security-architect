import type { AttackPath } from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';
import type {
  RemediationPlaybook,
  ChokePointDetail,
  RunbookStep,
  RemediationCategory,
  PlaybookClassificationSummary,
  VerificationChecklistItem,
} from './types.js';

export class RunbookGenerator {
  public classifyPath(path: AttackPath): RemediationCategory {
    // If the attack path is a direct hop (or 2 hops) with a clear, low-effort choke point,
    // it can be safely remediated via automatic IaC patching.
    // Otherwise, complex multi-hop or high blast-radius paths require a coordinated human runbook.
    const isShort = path.pathLength <= 2;
    const isLowEffort =
      !path.recommendedChokePoint ||
      (path.recommendedChokePoint.engineeringEffort === 'LOW' &&
        path.recommendedChokePoint.blastRadius === 'LOW');

    return isShort && isLowEffort ? 'auto-patchable' : 'requires-runbook';
  }

  public classifyPaths(paths: AttackPath[]): PlaybookClassificationSummary {
    const autoPatchable: string[] = [];
    const requiresRunbook: string[] = [];

    for (const p of paths) {
      if (this.classifyPath(p) === 'auto-patchable') {
        autoPatchable.push(p.id);
      } else {
        requiresRunbook.push(p.id);
      }
    }

    return { autoPatchable, requiresRunbook };
  }

  public generatePlaybook(path: AttackPath, graph: SecurityGraphEngine): RemediationPlaybook {
    const chokePoint = this.resolveChokePoint(path, graph);
    const category = this.classifyPath(path);
    const owningTeam = this.resolveOwningTeam(chokePoint.relationshipType);

    const severity =
      path.riskScore.totalRisk >= 9.0
        ? 'CRITICAL'
        : path.riskScore.totalRisk >= 7.0
          ? 'HIGH'
          : path.riskScore.totalRisk >= 4.0
            ? 'MEDIUM'
            : 'LOW';

    const preFlightChecks: string[] = [
      `git status --porcelain  # Ensure working directory is clean before applying fixes`,
      `aws sts get-caller-identity  # Verify deployment identity has admin/security permissions`,
      `# Verify current state of target asset '${chokePoint.targetAssetName}'`,
    ];

    const executionSteps: RunbookStep[] = this.buildExecutionSteps(chokePoint, path);

    const rollbackSteps: string[] = [
      `git checkout HEAD~1 -- terraform/  # Restore previous infrastructure code`,
      `terraform apply -auto-approve  # Rollback changes to previous known stable state`,
      `# Verify application telemetry and alert channels for unintended traffic disruption`,
    ];

    const postVerificationQuery = `sec-arch scan --verify-closed ${path.id}  # Confirms choke point is severed and path is eliminated`;

    const fingerprint = path.fingerprint ?? `fp-${path.id}`;
    const verificationChecklist: VerificationChecklistItem[] = [
      {
        fingerprint,
        description: `Verify attack path '${path.id}' is eliminated in subsequent scan`,
        verificationCommand: `sec-arch scan . --verify-closed ${path.id}`,
      },
      {
        fingerprint,
        description: `Verify no regression on upstream node '${chokePoint.sourceAssetName}' connectivity`,
        verificationCommand: `sec-arch query . --prompt "Show active paths through ${chokePoint.sourceAssetName}"`,
      },
    ];

    return {
      id: `playbook-${path.id}`,
      title: `Remediation Runbook for Attack Path ${path.id}: Sever ${chokePoint.relationshipType} between ${chokePoint.sourceAssetName} and ${chokePoint.targetAssetName}`,
      attackPathId: path.id,
      fingerprint,
      severity,
      riskScore: path.riskScore.totalRisk,
      category,
      owningTeam,
      chokePoint,
      preFlightChecks,
      executionSteps,
      rollbackSteps,
      postVerificationQuery,
      verificationChecklist,
      disclaimer:
        'DISCLAIMER: Runbook commands and IaC snippets must be verified in a staging environment prior to production execution.',
    };
  }

  public formatMarkdown(playbook: RemediationPlaybook): string {
    const lines: string[] = [
      `# ${playbook.title}`,
      `**Path ID:** \`${playbook.attackPathId}\` | **Severity:** ${playbook.severity} (${playbook.riskScore}/10)`,
      `**Classification:** \`${playbook.category}\` | **Owning Team:** ${playbook.owningTeam}`,
      `**Optimal Choke Point:** \`${chokePointSummary(playbook.chokePoint)}\``,
      ...(playbook.fingerprint ? [`**Path Fingerprint:** \`${playbook.fingerprint}\``] : []),
      ``,
      `> ⚠️ **Notice**: ${playbook.disclaimer}`,
      ``,
      `## 1. Pre-Flight Verification Checks`,
      `Run these diagnostic checks to ensure environment readiness before proceeding:`,
      `\`\`\`bash`,
      playbook.preFlightChecks.join('\n'),
      `\`\`\``,
      ``,
      `## 2. Step-by-Step Remediation Execution`,
    ];

    for (const step of playbook.executionSteps) {
      lines.push(`### Step ${step.stepNumber}: ${step.title}`);
      lines.push(`${step.description}`);
      lines.push(``);
      lines.push(`\`\`\`${step.actionType === 'IAC_PATCH' ? 'hcl' : 'bash'}`);
      lines.push(step.commandOrSnippet);
      lines.push(`\`\`\``);
      lines.push(``);
    }

    lines.push(`## 3. Rollback Procedure`);
    lines.push(`If service disruption occurs, execute the following commands immediately:`);
    lines.push(`\`\`\`bash`);
    lines.push(playbook.rollbackSteps.join('\n'));
    lines.push(`\`\`\``);
    lines.push(``);
    lines.push(`## 4. Post-Remediation Verification Checklist`);
    for (const item of playbook.verificationChecklist) {
      lines.push(`- [ ] **${item.description}** (Fingerprint: \`${item.fingerprint}\`)`);
      lines.push(`  \`\`\`bash`);
      lines.push(`  ${item.verificationCommand}`);
      lines.push(`  \`\`\``);
    }

    return lines.join('\n');
  }

  public formatConfluence(playbook: RemediationPlaybook): string {
    const lines: string[] = [
      `h1. ${playbook.title}`,
      `*Path ID:* \`${playbook.attackPathId}\` | *Severity:* ${playbook.severity} (${playbook.riskScore}/10)`,
      `*Classification:* ${playbook.category} | *Owning Team:* ${playbook.owningTeam}`,
      `*Optimal Choke Point:* ${chokePointSummary(playbook.chokePoint)}`,
      ...(playbook.fingerprint ? [`*Path Fingerprint:* \`${playbook.fingerprint}\``] : []),
      ``,
      `{panel:title=Notice|borderColor=#d29922|bgColor=#fff8e5}`,
      playbook.disclaimer,
      `{panel}`,
      ``,
      `h2. 1. Pre-Flight Verification Checks`,
      `{code:bash}`,
      playbook.preFlightChecks.join('\n'),
      `{code}`,
      ``,
      `h2. 2. Step-by-Step Remediation Execution`,
    ];

    for (const step of playbook.executionSteps) {
      lines.push(`h3. Step ${step.stepNumber}: ${step.title}`);
      lines.push(step.description);
      lines.push(`{code:${step.actionType === 'IAC_PATCH' ? 'hcl' : 'bash'}}`);
      lines.push(step.commandOrSnippet);
      lines.push(`{code}`);
    }

    lines.push(`h2. 3. Rollback Procedure`);
    lines.push(`{code:bash}`);
    lines.push(playbook.rollbackSteps.join('\n'));
    lines.push(`{code}`);
    lines.push(``);
    lines.push(`h2. 4. Post-Remediation Verification Checklist`);
    for (const item of playbook.verificationChecklist) {
      lines.push(`* [ ] *${item.description}* (Fingerprint: \`${item.fingerprint}\`)`);
      lines.push(`{code:bash}`);
      lines.push(item.verificationCommand);
      lines.push(`{code}`);
    }

    return lines.join('\n');
  }

  private resolveOwningTeam(relationshipType: string): string {
    switch (relationshipType) {
      case 'ASSUMES_ROLE':
        return 'IAM Administration / Platform Security';
      case 'CAN_READ':
      case 'CAN_WRITE':
        return 'Data Infrastructure / Cloud Platform';
      case 'EXPOSES_HTTP':
      case 'PEERED_TO':
      case 'ROUTES_TRAFFIC':
        return 'Cloud Network Engineering';
      default:
        return 'DevOps / Platform Security';
    }
  }

  private resolveChokePoint(path: AttackPath, graph: SecurityGraphEngine): ChokePointDetail {
    if (path.recommendedChokePoint) {
      const cp = path.recommendedChokePoint;
      const src = graph.getNode(cp.sourceAssetId);
      const tgt = graph.getNode(cp.targetAssetId);
      return {
        edgeId: cp.edgeId,
        relationshipType: cp.relationshipType,
        sourceAssetId: cp.sourceAssetId,
        sourceAssetName: src?.asset.name ?? cp.sourceAssetId,
        targetAssetId: cp.targetAssetId,
        targetAssetName: tgt?.asset.name ?? cp.targetAssetId,
        actionDescription: cp.actionDescription,
      };
    }

    const step = path.steps[path.steps.length - 1];
    const src = graph.getNode(step.sourceAssetId);
    const tgt = graph.getNode(step.targetAssetId);
    return {
      edgeId: `edge-${step.stepNumber}`,
      relationshipType: step.relationshipType,
      sourceAssetId: step.sourceAssetId,
      sourceAssetName: src?.asset.name ?? step.sourceAssetId,
      targetAssetId: step.targetAssetId,
      targetAssetName: tgt?.asset.name ?? step.targetAssetId,
      actionDescription: `Sever ${step.relationshipType} connection between ${src?.asset.name ?? step.sourceAssetId} and ${tgt?.asset.name ?? step.targetAssetId}`,
    };
  }

  private buildExecutionSteps(cp: ChokePointDetail, _path: AttackPath): RunbookStep[] {
    const steps: RunbookStep[] = [];

    if (cp.relationshipType === 'ASSUMES_ROLE') {
      steps.push({
        stepNumber: 1,
        title: 'Scope IAM AssumeRole Trust Policy',
        actionType: 'IAC_PATCH',
        commandOrSnippet: `data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    # Enforce strict condition to prevent cross-service assumption
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
  }
}`,
        description: `Restrict trust relationship on role '${cp.targetAssetName}' to prevent arbitrary workload assumption.`,
      });
      steps.push({
        stepNumber: 2,
        title: 'Apply Terraform Configuration & Reload Workload',
        actionType: 'CLI_COMMAND',
        commandOrSnippet: `terraform plan -out=tfplan && terraform apply tfplan`,
        description: 'Safely plan and apply the scoped trust policy.',
      });
    } else if (cp.relationshipType === 'CAN_READ' || cp.relationshipType === 'CAN_WRITE') {
      steps.push({
        stepNumber: 1,
        title: 'Tighten Resource-Based Policy to Enforce Least-Privilege Access',
        actionType: 'IAC_PATCH',
        commandOrSnippet: `resource "aws_s3_bucket_policy" "restrict_access" {
  bucket = "${cp.targetAssetName}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnintendedAccess"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["arn:aws:s3:::${cp.targetAssetName}", "arn:aws:s3:::${cp.targetAssetName}/*"]
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::\${var.aws_account_id}:role/authorized-role"
          }
        }
      }
    ]
  })
}`,
        description: `Enforce explicit denial on bucket '${cp.targetAssetName}' for any caller not strictly authorized.`,
      });
      steps.push({
        stepNumber: 2,
        title: 'Apply Infrastructure Policy',
        actionType: 'CLI_COMMAND',
        commandOrSnippet: `terraform apply -target=aws_s3_bucket_policy.restrict_access -auto-approve`,
        description: 'Apply bucket policy changes directly to block unauthorized reads.',
      });
    } else {
      steps.push({
        stepNumber: 1,
        title: `Sever ${cp.relationshipType} Route via Network Policy / Ingress Rule`,
        actionType: 'IAC_PATCH',
        commandOrSnippet: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-${cp.targetAssetName}
spec:
  podSelector:
    matchLabels:
      app: ${cp.targetAssetName}
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: authorized-client`,
        description: `Deploy Kubernetes NetworkPolicy blocking unauthorized traffic from '${cp.sourceAssetName}' to '${cp.targetAssetName}'.`,
      });
      steps.push({
        stepNumber: 2,
        title: 'Deploy Kubernetes Manifest',
        actionType: 'CLI_COMMAND',
        commandOrSnippet: `kubectl apply -f network-policy.yaml`,
        description: 'Enforce network isolation at the container network fabric level.',
      });
    }

    return steps;
  }
}

function chokePointSummary(cp: ChokePointDetail): string {
  return `${cp.sourceAssetName} -(${cp.relationshipType})-> ${cp.targetAssetName}`;
}
