import {
  createEvidence,
  type Finding,
  type Evidence,
} from '@ai-security-architect/core';
import type { AnalyzerContext, SecurityAnalyzer, AnalyzerResult } from '../types.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

export class IacTerraformAnalyzer implements SecurityAnalyzer {
  public readonly name = 'IacTerraformAnalyzer';

  public async supports(_workspace: EphemeralWorkspace, fileList: string[]): Promise<boolean> {
    return fileList.some((f) => f.endsWith('.tf') || f.endsWith('.tf.json'));
  }

  public async analyze(context: AnalyzerContext, fileList: string[]): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    const evidenceList: Evidence[] = [];

    const tfFiles = fileList.filter((f) => f.endsWith('.tf'));

    for (const filePath of tfFiles) {
      let content: string;
      try {
        content = await context.workspace.readSafeFile(filePath);
      } catch {
        continue;
      }

      const lines = content.split('\n');

      // Rule: Wildcard S3 IAM Permission
      const wildcardS3Regex = /resource\s+["']aws_iam_role_policy["']\s+["']([^"']+)["']\s*\{([\s\S]*?Action\s*=\s*["']s3:\*["'][\s\S]*?)\}/g;
      let match: RegExpExecArray | null;

      while ((match = wildcardS3Regex.exec(content)) !== null) {
        const policyLabel = match[1];
        const blockContent = match[0];
        const lineStart = content.substring(0, match.index).split('\n').length;
        const lineEnd = lineStart + blockContent.split('\n').length - 1;

        const evidence = createEvidence({
          id: `ev-iac-wildcard-s3-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}-${lineStart}`,
          tenantId: context.tenantId,
          sourceType: 'TERRAFORM',
          repository: context.repository,
          filePath,
          lineStart,
          lineEnd,
          snippet: blockContent,
          scanner: 'IacTerraformAnalyzer',
        });
        evidenceList.push(evidence);

        const iamRoleAsset =
          context.discoveredAssets.find((a) => a.type === 'IAM_ROLE') ||
          context.discoveredAssets[0];

        findings.push({
          id: `finding-iac-iam-wildcard-s3-${policyLabel}`,
          tenantId: context.tenantId,
          assetId: iamRoleAsset?.id || 'asset-iam-role',
          category: 'IAM_OVERPRIVILEGE',
          ruleId: 'IAM-WILDCARD-S3-PERMISSION',
          title: 'Wildcard Action s3:* on IAM Role Policy',
          description:
            'The IAM policy grants unrestricted wildcard permissions ("s3:*") on resources. Any workload assuming this role gains complete administrative control, data exfiltration, and deletion capabilities across all S3 buckets in the AWS account.',
          severity: 'CRITICAL',
          confidence: 'CERTAIN',
          scanner: 'IacTerraformAnalyzer',
          evidence,
          remediationRecommendation:
            'Follow the principle of least privilege: restrict actions to specific API operations (e.g. s3:GetObject, s3:PutObject) and scope the Resource ARN to the exact target bucket(s).',
          metadata: { policyLabel, filePath, lineStart },
        });
      }

      // Rule: Public Unencrypted HTTP ALB Listener
      const httpAlbRegex = /resource\s+["']aws_lb_listener["'][\s\S]*?protocol\s*=\s*["']HTTP["'][\s\S]*?port\s*=\s*80/g;
      let httpMatch: RegExpExecArray | null;

      while ((httpMatch = httpAlbRegex.exec(content)) !== null) {
        const blockContent = httpMatch[0];
        const lineStart = content.substring(0, httpMatch.index).split('\n').length;
        const lineEnd = lineStart + blockContent.split('\n').length - 1;

        const evidence = createEvidence({
          id: `ev-iac-alb-http-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}-${lineStart}`,
          tenantId: context.tenantId,
          sourceType: 'TERRAFORM',
          repository: context.repository,
          filePath,
          lineStart,
          lineEnd,
          snippet: blockContent,
          scanner: 'IacTerraformAnalyzer',
        });
        evidenceList.push(evidence);

        const albAsset = context.discoveredAssets.find((a) => a.type === 'LOAD_BALANCER');

        findings.push({
          id: `finding-iac-alb-http-${lineStart}`,
          tenantId: context.tenantId,
          assetId: albAsset?.id || 'asset-alb',
          category: 'PUBLIC_EXPOSURE',
          ruleId: 'ALB-INSECURE-HTTP-LISTENER',
          title: 'Application Load Balancer Insecure HTTP Listener (Port 80)',
          description: 'The load balancer listener accepts unencrypted plaintext HTTP traffic on port 80 without automatic TLS redirection.',
          severity: 'MEDIUM',
          confidence: 'HIGH',
          scanner: 'IacTerraformAnalyzer',
          evidence,
          remediationRecommendation: 'Configure an HTTPS listener on port 443 with a valid certificate and set port 80 to redirect to HTTPS.',
          metadata: { filePath, lineStart },
        });
      }
    }

    return { findings, evidence: evidenceList };
  }
}
