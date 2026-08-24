import type { Asset, Relationship, Finding, Evidence } from '@ai-security-architect/core';
import { SecurityGraphEngine } from './security-graph-engine.js';

export interface EntityResolutionContext {
  tenantId: string;
  assets: Asset[];
  relationships: Relationship[];
  findings: Finding[];
  evidence: Evidence[];
}

export class EntityResolver {
  public resolve(context: EntityResolutionContext): SecurityGraphEngine {
    const graph = new SecurityGraphEngine(context.tenantId);

    // 1. Ingest all discovered assets
    for (const asset of context.assets) {
      graph.addAsset(asset);
    }

    // 2. Ingest all discovered relationships
    for (const rel of context.relationships) {
      graph.addRelationship(rel);
    }

    // 3. Attach all deterministic findings to matching nodes
    for (const finding of context.findings) {
      graph.attachFinding(finding);
    }

    // 4. Perform cross-layer heuristic entity resolution
    this.resolveCrossLayerChains(context.tenantId, graph);

    return graph;
  }

  private resolveCrossLayerChains(tenantId: string, graph: SecurityGraphEngine): void {
    const allNodes = graph.getAllNodes();

    const internetNode = allNodes.find((n) => n.asset.type === 'INTERNET');
    const loadBalancers = allNodes.filter((n) => n.asset.type === 'LOAD_BALANCER');
    const services = allNodes.filter((n) => n.asset.type === 'SERVICE');
    const controllers = allNodes.filter((n) => n.asset.type === 'API_CONTROLLER');
    const endpoints = allNodes.filter((n) => n.asset.type === 'ENDPOINT');
    const pods = allNodes.filter((n) => n.asset.type === 'POD');
    const serviceAccounts = allNodes.filter((n) => n.asset.type === 'KUBERNETES_SERVICE_ACCOUNT');
    const iamRoles = allNodes.filter((n) => n.asset.type === 'IAM_ROLE');
    const sensitiveBuckets = allNodes.filter((n) => n.asset.type === 'BUCKET' && n.asset.isSensitiveData);

    // 1. Internet -> Public ALB
    if (internetNode) {
      for (const alb of loadBalancers) {
        if (alb.asset.isPublic) {
          const relId = `rel-${internetNode.asset.id}-${alb.asset.id}`;
          if (!graph.getEdge(relId)) {
            graph.addRelationship({
              id: relId,
              tenantId,
              sourceAssetId: internetNode.asset.id,
              targetAssetId: alb.asset.id,
              type: 'EXPOSES_HTTP',
              nature: 'DECLARED',
              confidence: 1.0,
              metadata: { description: 'Public internet access to Application Load Balancer' },
            });
          }
        }
      }
    }

    // 2. ALB -> Service
    for (const alb of loadBalancers) {
      for (const svc of services) {
        const relId = `rel-${alb.asset.id}-${svc.asset.id}`;
        if (!graph.getEdge(relId)) {
          graph.addRelationship({
            id: relId,
            tenantId,
            sourceAssetId: alb.asset.id,
            targetAssetId: svc.asset.id,
            type: 'ROUTES_TO',
            nature: 'INFERRED',
            confidence: 0.95,
            metadata: { description: 'Load balancer routes HTTP requests to backend microservice' },
          });
        }
      }
    }

    // 3. Service -> Controller & Controller -> Endpoints
    for (const svc of services) {
      for (const ctrl of controllers) {
        const relId = `rel-${svc.asset.id}-${ctrl.asset.id}`;
        if (!graph.getEdge(relId)) {
          graph.addRelationship({
            id: relId,
            tenantId,
            sourceAssetId: svc.asset.id,
            targetAssetId: ctrl.asset.id,
            type: 'CONTAINS',
            nature: 'DECLARED',
            confidence: 1.0,
            metadata: {},
          });
        }
      }

      // Link Service directly to Endpoints as well for fast traversal
      for (const ep of endpoints) {
        const relId = `rel-${svc.asset.id}-${ep.asset.id}`;
        if (!graph.getEdge(relId)) {
          graph.addRelationship({
            id: relId,
            tenantId,
            sourceAssetId: svc.asset.id,
            targetAssetId: ep.asset.id,
            type: 'CONTAINS',
            nature: 'DECLARED',
            confidence: 1.0,
            metadata: {},
          });
        }
      }
    }

    // 4. Service / Endpoint -> Kubernetes Pod
    for (const svc of services) {
      for (const pod of pods) {
        const relId = `rel-${svc.asset.id}-${pod.asset.id}`;
        if (!graph.getEdge(relId)) {
          graph.addRelationship({
            id: relId,
            tenantId,
            sourceAssetId: svc.asset.id,
            targetAssetId: pod.asset.id,
            type: 'DEPLOYED_TO',
            nature: 'INFERRED',
            confidence: 0.95,
            metadata: { description: 'Microservice runs inside Kubernetes pod workload' },
          });
        }
      }
    }

    // 5. Pod -> ServiceAccount
    for (const pod of pods) {
      const saName = pod.asset.metadata.serviceAccountName as string;
      const targetSA = serviceAccounts.find((sa) => sa.asset.name === saName) || serviceAccounts[0];

      if (targetSA) {
        const relId = `rel-${pod.asset.id}-${targetSA.asset.id}`;
        if (!graph.getEdge(relId)) {
          graph.addRelationship({
            id: relId,
            tenantId,
            sourceAssetId: pod.asset.id,
            targetAssetId: targetSA.asset.id,
            type: 'RUNS_AS',
            nature: 'DECLARED',
            confidence: 1.0,
            metadata: { serviceAccountName: saName },
          });
        }
      }
    }

    // 6. ServiceAccount -> AWS IAM Role
    for (const sa of serviceAccounts) {
      const roleArn = sa.asset.metadata.awsRoleArn as string;
      if (roleArn) {
        const roleName = roleArn.split('/').pop();
        const targetRole = iamRoles.find((r) => r.asset.name === roleName || roleArn.includes(r.asset.name));

        if (targetRole) {
          const relId = `rel-${sa.asset.id}-${targetRole.asset.id}`;
          if (!graph.getEdge(relId)) {
            graph.addRelationship({
              id: relId,
              tenantId,
              sourceAssetId: sa.asset.id,
              targetAssetId: targetRole.asset.id,
              type: 'ASSUMES_ROLE',
              nature: 'DECLARED',
              confidence: 1.0,
              metadata: { roleArn },
            });
          }
        }
      }
    }

    // 7. IAM Role -> Sensitive S3 Buckets (only if wildcard permission finding exists or explicitly granted)
    for (const role of iamRoles) {
      const hasWildcardFinding = role.findings.some(
        (f) => f.category === 'IAM_OVERPRIVILEGE' || f.ruleId === 'IAM-WILDCARD-S3-PERMISSION'
      );

      if (hasWildcardFinding) {
        for (const bucket of sensitiveBuckets) {
          const relId = `rel-${role.asset.id}-${bucket.asset.id}`;
          if (!graph.getEdge(relId)) {
            graph.addRelationship({
              id: relId,
              tenantId,
              sourceAssetId: role.asset.id,
              targetAssetId: bucket.asset.id,
              type: 'CAN_READ',
              nature: 'INFERRED',
              confidence: 0.95,
              metadata: {
                accessType: 'wildcard-s3-access',
                description: 'IAM role policy permits reading sensitive S3 bucket',
              },
            });
          }
        }
      }
    }
  }
}
