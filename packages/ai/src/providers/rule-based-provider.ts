import type { LLMProvider } from '../types.js';
import type { AIContextHandoff, AIReasoningOutput } from '@ai-security-architect/core';

export class RuleBasedLLMProvider implements LLMProvider {
  public readonly name = 'RuleBasedReasoningEngine';

  public async generateCompletion(prompt: string, _systemPrompt: string): Promise<string> {
    // Extract JSON payload from prompt
    const jsonMatch = prompt.match(/DETERMINISTIC CONTEXT HANDOFF:\s*([\s\S]*?)\s*Provide your analysis/);
    if (!jsonMatch) {
      throw new Error('Unable to extract context handoff from prompt');
    }

    const handoff: AIContextHandoff = JSON.parse(jsonMatch[1]);
    const evidenceIds = handoff.evidenceReferences.map((e) => e.evidenceId);

    const hasSSRF = handoff.findingsSummary.some((f) => f.category === 'SSRF');
    const hasWildcardIAM = handoff.findingsSummary.some((f) => f.category === 'IAM_OVERPRIVILEGE');

    let output: AIReasoningOutput;

    if (hasSSRF && hasWildcardIAM) {
      output = {
        summary:
          'Publicly exposed Application Load Balancer routes traffic to order-service possessing an SSRF vulnerability. Exploitation allows cloud metadata access (IMDS) to assume an overprivileged IAM role with wildcard access to sensitive customer PII S3 bucket.',
        rootCauseAnalysis:
          'The vulnerability chain consists of two compounding weaknesses: 1) Application layer: /webhook-callback in OrderController.java directly opens HttpURLConnection on user-supplied URLs without IP sanitization. 2) Cloud Infrastructure layer: The order_service_role IAM policy in terraform/iam.tf grants wildcard "s3:*" permissions across all resources instead of restricting access to the specific needed bucket.',
        businessImpact:
          'Complete unauthorized exfiltration of confidential customer PII data stored in enterprise-production-customer-pii bucket, violating GDPR and PCI-DSS compliance requirements.',
        evidenceReferences: evidenceIds,
        recommendedRemediation: {
          description:
            'Constrain the IAM policy in terraform/iam.tf to only allow read operations on necessary buckets, severing the attacker reachability to sensitive customer PII.',
          targetChokePoint: `${handoff.deterministicMetrics.optimalChokePointEdge.source} -> ${handoff.deterministicMetrics.optimalChokePointEdge.target}`,
          expectedRiskReductionPercentage: 100,
          engineeringEffort: 'LOW',
          patches: [
            {
              filePath: 'terraform/iam.tf',
              action: 'MODIFY',
              diff: `-      Action   = "s3:*"
-      Resource = "*"
+      Action   = [
+        "s3:GetObject",
+        "s3:ListBucket"
+      ]
+      Resource = [
+        "arn:aws:s3:::enterprise-production-customer-pii",
+        "arn:aws:s3:::enterprise-production-customer-pii/*"
+      ]`,
              description: 'Replace wildcard s3:* action with scoped least-privilege read permissions',
            },
          ],
        },
        alternativeRemediations: [
          {
            description: 'Enforce IMDSv2 (HttpTokens=required, HopLimit=1) on EKS nodes and pods',
            tradeoff:
              'Blocks SSRF-based metadata credential exfiltration from inside the pod, but does not remediate the overprivileged IAM role if assumed via other mechanisms.',
          },
          {
            description: 'Validate and allowlist outbound webhook destinations in OrderController.java',
            tradeoff:
              'Remediates the application-level SSRF entry point but leaves IAM overprivilege intact.',
          },
        ],
        confidence: 'VERY_HIGH',
      };
    } else {
      output = {
        summary: `Attack path detected from ${handoff.deterministicMetrics.entryNode} to ${handoff.deterministicMetrics.targetNode}.`,
        rootCauseAnalysis: 'Architectural connectivity allows lateral privilege escalation to sensitive target assets.',
        businessImpact: 'Unauthorized data access and lateral movement risk within cloud infrastructure.',
        evidenceReferences: evidenceIds,
        recommendedRemediation: {
          description: `Sever choke point edge ${handoff.deterministicMetrics.optimalChokePointEdge.source} -> ${handoff.deterministicMetrics.optimalChokePointEdge.target}`,
          targetChokePoint: `${handoff.deterministicMetrics.optimalChokePointEdge.source} -> ${handoff.deterministicMetrics.optimalChokePointEdge.target}`,
          expectedRiskReductionPercentage: 90,
          engineeringEffort: 'MEDIUM',
          patches: [],
        },
        alternativeRemediations: [],
        confidence: 'HIGH',
      };
    }

    return JSON.stringify(output, null, 2);
  }
}
