import {
  createEvidence,
  type Asset,
  type Relationship,
  type Evidence,
} from '@ai-security-architect/core';
import type { DiscoveryContext, DiscoveryExtractor, DiscoveryResult } from '../types.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

export class TerraformExtractor implements DiscoveryExtractor {
  public readonly name = 'TerraformExtractor';

  public async supports(_workspace: EphemeralWorkspace, fileList: string[]): Promise<boolean> {
    return fileList.some((f) => f.endsWith('.tf') || f.endsWith('.tf.json'));
  }

  public async extract(context: DiscoveryContext, fileList: string[]): Promise<DiscoveryResult> {
    const assets: Asset[] = [];
    const relationships: Relationship[] = [];
    const evidenceList: Evidence[] = [];

    const tfFiles = fileList.filter((f) => f.endsWith('.tf'));

    let hasInternetNode = false;

    const ensureInternetNode = () => {
      if (!hasInternetNode) {
        assets.push({
          id: 'asset-internet',
          tenantId: context.tenantId,
          type: 'INTERNET',
          name: 'Public Internet',
          environment: 'external',
          isPublic: true,
          isSensitiveData: false,
          criticality: 'LOW',
          metadata: {},
          tags: ['entry-point', 'public'],
        });
        hasInternetNode = true;
      }
    };

    for (const filePath of tfFiles) {
      let content: string;
      try {
        content = await context.workspace.readSafeFile(filePath);
      } catch {
        continue;
      }

      // Regex parser for Terraform HCL resource blocks
      const resourceBlockRegex = /resource\s+["']([^"']+)["']\s+["']([^"']+)["']\s*\{([\s\S]*?)\n\}/g;
      let match: RegExpExecArray | null;

      while ((match = resourceBlockRegex.exec(content)) !== null) {
        const resourceType = match[1];
        const resourceLabel = match[2];
        const blockBody = match[3];

        const lineStart = content.substring(0, match.index).split('\n').length;
        const lineEnd = lineStart + match[0].split('\n').length - 1;

        const evidence = createEvidence({
          id: `ev-tf-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}-${lineStart}`,
          tenantId: context.tenantId,
          sourceType: 'TERRAFORM',
          repository: context.repository,
          filePath,
          lineStart,
          lineEnd,
          snippet: match[0],
          scanner: 'TerraformExtractor',
        });
        evidenceList.push(evidence);

        if (resourceType === 'aws_lb' || resourceType === 'aws_alb') {
          const isInternal = /internal\s*=\s*true/i.test(blockBody);
          const isPublic = !isInternal;
          const nameMatch = blockBody.match(/name\s*=\s*["']([^"']+)["']/);
          const lbName = nameMatch ? nameMatch[1] : resourceLabel;
          const lbAssetId = `asset-alb-${lbName}`;

          assets.push({
            id: lbAssetId,
            tenantId: context.tenantId,
            type: 'LOAD_BALANCER',
            name: lbName,
            environment: 'production',
            isPublic,
            isSensitiveData: false,
            criticality: isPublic ? 'HIGH' : 'MEDIUM',
            metadata: {
              resourceType,
              resourceLabel,
              filePath,
            },
            tags: ['aws', 'load-balancer', isPublic ? 'public-ingress' : 'internal'],
          });

          if (isPublic) {
            ensureInternetNode();
            relationships.push({
              id: `rel-internet-${lbAssetId}`,
              tenantId: context.tenantId,
              sourceAssetId: 'asset-internet',
              targetAssetId: lbAssetId,
              type: 'EXPOSES_HTTP',
              nature: 'DECLARED',
              confidence: 1.0,
              evidenceRef: evidence.id,
              metadata: { port: 80, protocol: 'HTTP' },
            });
          }
        } else if (resourceType === 'aws_iam_role') {
          const nameMatch = blockBody.match(/name\s*=\s*["']([^"']+)["']/);
          const roleName = nameMatch ? nameMatch[1] : resourceLabel;
          const roleAssetId = `asset-iam-role-${roleName}`;

          assets.push({
            id: roleAssetId,
            tenantId: context.tenantId,
            type: 'IAM_ROLE',
            name: roleName,
            environment: 'cloud',
            isPublic: false,
            isSensitiveData: false,
            criticality: 'HIGH',
            metadata: {
              resourceLabel,
              filePath,
            },
            tags: ['aws', 'iam'],
          });
        } else if (resourceType === 'aws_iam_role_policy' || resourceType === 'aws_iam_policy') {
          const roleMatch = blockBody.match(/role\s*=\s*(?:aws_iam_role\.)?([a-zA-Z0-9_\-\.]+)/);
          const roleName = roleMatch ? roleMatch[1].replace('.id', '').replace('.name', '') : 'iam-role';
          const roleAssetId = `asset-iam-role-${roleName}`;

          const isWildcardS3 = /s3:\*/i.test(blockBody) || /Action\s*=\s*"\*"/i.test(blockBody);
          const isWildcardResource = /Resource\s*=\s*"\*"/i.test(blockBody);

          if (isWildcardS3 || isWildcardResource) {
            // Relates role to any S3 bucket or sensitive data
            relationships.push({
              id: `rel-${roleAssetId}-s3-wildcard`,
              tenantId: context.tenantId,
              sourceAssetId: roleAssetId,
              targetAssetId: 'asset-s3-pii-target', // Dynamic link resolved later or mapped to discovered S3 assets
              type: 'CAN_READ',
              nature: 'DECLARED',
              confidence: 0.9,
              evidenceRef: evidence.id,
              metadata: {
                policyType: 'wildcard-s3-access',
                wildcardAction: isWildcardS3,
                wildcardResource: isWildcardResource,
              },
            });
          }
        } else if (resourceType === 'aws_s3_bucket') {
          const bucketMatch = blockBody.match(/bucket\s*=\s*["']([^"']+)["']/);
          const bucketName = bucketMatch ? bucketMatch[1] : resourceLabel;
          const bucketAssetId = `asset-s3-${bucketName}`;

          const isPII =
            /PII|customer|financial|vault|secret|credential|payment/i.test(bucketName) ||
            /CONFIDENTIAL|RESTRICTED/i.test(blockBody) ||
            /ContainsSensitive\s*=\s*["']?true["']?/i.test(blockBody);

          assets.push({
            id: bucketAssetId,
            tenantId: context.tenantId,
            type: 'BUCKET',
            name: bucketName,
            environment: 'production',
            isPublic: false,
            isSensitiveData: isPII,
            criticality: isPII ? 'CRITICAL' : 'HIGH',
            metadata: {
              resourceLabel,
              filePath,
              containsPII: isPII,
            },
            tags: ['aws', 's3', isPII ? 'sensitive-data' : 'storage'],
          });
        }
      }
    }

    return { assets, relationships, evidence: evidenceList };
  }
}
