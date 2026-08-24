import * as yaml from 'yaml';
import {
  createEvidence,
  type Asset,
  type Relationship,
  type Evidence,
} from '@ai-security-architect/core';
import type { DiscoveryContext, DiscoveryExtractor, DiscoveryResult } from '../types.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

export class KubernetesExtractor implements DiscoveryExtractor {
  public readonly name = 'KubernetesExtractor';

  public async supports(_workspace: EphemeralWorkspace, fileList: string[]): Promise<boolean> {
    return fileList.some((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  }

  public async extract(context: DiscoveryContext, fileList: string[]): Promise<DiscoveryResult> {
    const assets: Asset[] = [];
    const relationships: Relationship[] = [];
    const evidenceList: Evidence[] = [];

    const yamlFiles = fileList.filter(
      (f) => (f.endsWith('.yaml') || f.endsWith('.yml')) && !f.includes('.github/')
    );

    for (const filePath of yamlFiles) {
      let content: string;
      try {
        content = await context.workspace.readSafeFile(filePath);
      } catch {
        continue;
      }

      let documents: yaml.Document[];
      try {
        documents = yaml.parseAllDocuments(content);
      } catch {
        continue;
      }

      for (let docIndex = 0; docIndex < documents.length; docIndex++) {
        const doc = documents[docIndex];
        const json = doc.toJSON() as Record<string, any>;
        if (!json || typeof json !== 'object' || !json.kind || !json.apiVersion) {
          continue;
        }

        const kind = String(json.kind);
        const meta = json.metadata || {};
        const name = String(meta.name || 'unnamed');
        const namespace = String(meta.namespace || 'default');
        const snippet = doc.toString();

        const evidence = createEvidence({
          id: `ev-k8s-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}-${docIndex}`,
          tenantId: context.tenantId,
          sourceType: 'KUBERNETES',
          repository: context.repository,
          filePath,
          lineStart: 1,
          lineEnd: Math.min(100, snippet.split('\n').length),
          snippet,
          scanner: 'KubernetesExtractor',
        });
        evidenceList.push(evidence);

        if (['Deployment', 'StatefulSet', 'DaemonSet', 'Pod'].includes(kind)) {
          const podSpec = kind === 'Pod' ? json.spec : json.spec?.template?.spec;
          const podAssetId = `asset-k8s-pod-${name}`;
          const serviceAccountName = podSpec?.serviceAccountName || podSpec?.serviceAccount || 'default';
          const containers = (podSpec?.containers || []).map((c: any) => ({
            name: c.name,
            image: c.image,
            ports: c.ports,
          }));

          assets.push({
            id: podAssetId,
            tenantId: context.tenantId,
            type: 'POD',
            name: `${name}-pod`,
            environment: namespace,
            isPublic: false,
            isSensitiveData: false,
            criticality: 'MEDIUM',
            metadata: {
              kind,
              namespace,
              serviceAccountName,
              containers,
              labels: meta.labels || {},
            },
            tags: ['kubernetes', kind.toLowerCase(), namespace],
          });

          // Link Pod to ServiceAccount
          if (serviceAccountName) {
            const saAssetId = `asset-k8s-sa-${serviceAccountName}`;
            relationships.push({
              id: `rel-${podAssetId}-${saAssetId}`,
              tenantId: context.tenantId,
              sourceAssetId: podAssetId,
              targetAssetId: saAssetId,
              type: 'RUNS_AS',
              nature: 'DECLARED',
              confidence: 1.0,
              evidenceRef: evidence.id,
              metadata: { serviceAccountName },
            });
          }
        } else if (kind === 'ServiceAccount') {
          const saAssetId = `asset-k8s-sa-${name}`;
          const annotations = meta.annotations || {};
          const awsRoleArn =
            annotations['eks.amazonaws.com/role-arn'] ||
            annotations['iam.amazonaws.com/role'];

          assets.push({
            id: saAssetId,
            tenantId: context.tenantId,
            type: 'KUBERNETES_SERVICE_ACCOUNT',
            name,
            environment: namespace,
            isPublic: false,
            isSensitiveData: false,
            criticality: 'MEDIUM',
            metadata: {
              namespace,
              annotations,
              awsRoleArn,
            },
            tags: ['kubernetes', 'service-account', namespace],
          });

          if (awsRoleArn) {
            const roleName = String(awsRoleArn).split('/').pop() || 'iam-role';
            const iamRoleAssetId = `asset-iam-role-${roleName}`;

            // Create stub IAM role asset if not already discovered
            assets.push({
              id: iamRoleAssetId,
              tenantId: context.tenantId,
              type: 'IAM_ROLE',
              name: roleName,
              environment: 'cloud',
              isPublic: false,
              isSensitiveData: false,
              criticality: 'HIGH',
              metadata: {
                arn: awsRoleArn,
                federatedSource: 'eks-pod-identity',
              },
              tags: ['iam', 'aws'],
            });

            // Relationship ServiceAccount -> IAM Role
            relationships.push({
              id: `rel-${saAssetId}-${iamRoleAssetId}`,
              tenantId: context.tenantId,
              sourceAssetId: saAssetId,
              targetAssetId: iamRoleAssetId,
              type: 'ASSUMES_ROLE',
              nature: 'DECLARED',
              confidence: 1.0,
              evidenceRef: evidence.id,
              metadata: { roleArn: awsRoleArn },
            });
          }
        } else if (kind === 'Service') {
          const svcAssetId = `asset-k8s-svc-${name}`;
          const svcType = json.spec?.type || 'ClusterIP';
          const isPublic = svcType === 'LoadBalancer' || svcType === 'NodePort';

          assets.push({
            id: svcAssetId,
            tenantId: context.tenantId,
            type: 'KUBERNETES_SERVICE',
            name,
            environment: namespace,
            isPublic,
            isSensitiveData: false,
            criticality: 'MEDIUM',
            metadata: {
              serviceType: svcType,
              selector: json.spec?.selector || {},
              ports: json.spec?.ports || [],
            },
            tags: ['kubernetes', 'service', namespace],
          });

          // Link to matching Pod
          const targetPodId = `asset-k8s-pod-${name}`;
          relationships.push({
            id: `rel-${svcAssetId}-${targetPodId}`,
            tenantId: context.tenantId,
            sourceAssetId: svcAssetId,
            targetAssetId: targetPodId,
            type: 'ROUTES_TO',
            nature: 'DECLARED',
            confidence: 0.95,
            evidenceRef: evidence.id,
            metadata: {},
          });
        }
      }
    }

    return { assets, relationships, evidence: evidenceList };
  }
}
