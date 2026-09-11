import { createEvidence, type Asset, type Relationship, type Finding, type Evidence } from '@ai-security-architect/core';
import { SecurityGraphEngine } from './security-graph-engine.js';
import type { GraphNode } from './types.js';

export interface EntityResolutionContext {
  tenantId: string;
  assets: Asset[];
  relationships: Relationship[];
  findings: Finding[];
  evidence: Evidence[];
}

export class DeterministicEntityResolver {
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

    // 4. Perform deterministic cross-layer entity resolution
    this.resolveCrossLayerChains(context.tenantId, graph);

    return graph;
  }

  public resolveCrossLayerChains(tenantId: string, graph: SecurityGraphEngine): void {
    const allNodes = graph.getAllNodes();

    const internetNode = allNodes.find((n) => n.asset.type === 'INTERNET');
    const loadBalancers = allNodes.filter((n) => n.asset.type === 'LOAD_BALANCER');
    const k8sServices = allNodes.filter((n) => n.asset.type === 'KUBERNETES_SERVICE');
    const appServices = allNodes.filter((n) => n.asset.type === 'SERVICE');
    const controllers = allNodes.filter((n) => n.asset.type === 'API_CONTROLLER');
    const endpoints = allNodes.filter((n) => n.asset.type === 'ENDPOINT');
    const pods = allNodes.filter((n) => n.asset.type === 'POD');
    const serviceAccounts = allNodes.filter((n) => n.asset.type === 'KUBERNETES_SERVICE_ACCOUNT');
    const iamRoles = allNodes.filter((n) => n.asset.type === 'IAM_ROLE');
    const sensitiveBuckets = allNodes.filter((n) => n.asset.type === 'BUCKET' && n.asset.isSensitiveData);

    // 1. Internet -> Public Load Balancers
    this.linkInternetToLoadBalancers(internetNode, loadBalancers, graph, tenantId);

    // 2. Load Balancers -> Services (Explicit match by name tokens or target group reference)
    this.linkLoadBalancersToServices(loadBalancers, [...k8sServices, ...appServices], graph, tenantId);

    // 3. Application Services -> Controllers & Endpoints
    this.linkServicesToControllersAndEndpoints(appServices, controllers, endpoints, graph, tenantId);

    // 4. Services (K8s & App) -> Kubernetes Pods (Strict label-selector and namespace matching)
    this.linkServicesToPods([...k8sServices, ...appServices], pods, graph, tenantId);

    // 5. Pods -> ServiceAccounts (Strict namespace matching, NO greedy fallbacks)
    this.linkPodsToServiceAccounts(pods, serviceAccounts, graph, tenantId);

    // 6. ServiceAccounts -> Cloud IAM Roles
    this.linkServiceAccountsToIamRoles(serviceAccounts, iamRoles, graph, tenantId);

    // 7. IAM Roles -> Sensitive Buckets
    this.linkIamRolesToBuckets(iamRoles, sensitiveBuckets, graph, tenantId);
  }

  public linkInternetToLoadBalancers(
    internetNode: GraphNode | undefined,
    loadBalancers: GraphNode[],
    graph: SecurityGraphEngine,
    tenantId: string
  ): void {
    if (!internetNode) return;

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

  public linkLoadBalancersToServices(
    loadBalancers: GraphNode[],
    services: GraphNode[],
    graph: SecurityGraphEngine,
    tenantId: string
  ): void {
    if (loadBalancers.length === 0 || services.length === 0) return;

    for (const alb of loadBalancers) {
      const albName = alb.asset.name.toLowerCase();
      const albTokens = albName.split(/[-_]/).filter((t) => t && t !== 'public' && t !== 'alb' && t !== 'lb' && t !== 'asset');

      for (const svc of services) {
        const svcName = svc.asset.name.toLowerCase();
        const svcTokens = svcName.split(/[-_]/).filter((t) => t && t !== 'service' && t !== 'svc' && t !== 'asset');

        // Explicit match: shared domain prefix/token or exact reference
        const hasTokenMatch = albTokens.some((t) => svcTokens.includes(t) || svcName.includes(t));
        const isOnlyOnePair = loadBalancers.length === 1 && services.length === 1;

        if (hasTokenMatch || isOnlyOnePair) {
          const relId = `rel-${alb.asset.id}-${svc.asset.id}`;
          if (!graph.getEdge(relId)) {
            graph.addRelationship({
              id: relId,
              tenantId,
              sourceAssetId: alb.asset.id,
              targetAssetId: svc.asset.id,
              type: 'ROUTES_TO',
              nature: hasTokenMatch ? 'DECLARED' : 'INFERRED',
              confidence: hasTokenMatch ? 1.0 : 0.85,
              metadata: {
                matchReason: hasTokenMatch ? 'token-match' : 'single-service-topology',
                description: 'Load balancer routes HTTP requests to backend microservice',
              },
            });
          }
        }
      }
    }
  }

  public linkServicesToControllersAndEndpoints(
    services: GraphNode[],
    controllers: GraphNode[],
    endpoints: GraphNode[],
    graph: SecurityGraphEngine,
    tenantId: string
  ): void {
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
  }

  public linkServicesToPods(
    services: GraphNode[],
    pods: GraphNode[],
    graph: SecurityGraphEngine,
    tenantId: string
  ): void {
    if (services.length === 0 || pods.length === 0) return;

    // Index pods by namespace for sub-linear lookups: Map<namespace, Pod[]>
    const podsByNamespace = new Map<string, GraphNode[]>();
    for (const pod of pods) {
      const ns = (pod.asset.metadata.namespace as string) || pod.asset.environment || 'default';
      if (!podsByNamespace.has(ns)) {
        podsByNamespace.set(ns, []);
      }
      podsByNamespace.get(ns)!.push(pod);
    }

    for (const svc of services) {
      const svcNamespace = (svc.asset.metadata.namespace as string) || svc.asset.environment || 'default';
      const namespacePods = podsByNamespace.get(svcNamespace) || [];

      if (svc.asset.type === 'KUBERNETES_SERVICE') {
        const selector = (svc.asset.metadata.selector as Record<string, string>) || {};
        const selectorEntries = Object.entries(selector);

        if (selectorEntries.length > 0) {
          // Exact selector matching within the same namespace
          for (const pod of namespacePods) {
            const podLabels = (pod.asset.metadata.labels as Record<string, string>) || {};
            const matchesAll = selectorEntries.every(([k, v]) => podLabels[k] === v);

            if (matchesAll) {
              const relId = `rel-${svc.asset.id}-${pod.asset.id}`;
              if (!graph.getEdge(relId)) {
                graph.addRelationship({
                  id: relId,
                  tenantId,
                  sourceAssetId: svc.asset.id,
                  targetAssetId: pod.asset.id,
                  type: 'ROUTES_TO',
                  nature: 'DECLARED',
                  confidence: 1.0,
                  metadata: {
                    matchedSelector: selector,
                    namespace: svcNamespace,
                    description: 'Kubernetes Service routes traffic to Pod matching label selector',
                  },
                });
              }
            }
          }
        }
      } else if (svc.asset.type === 'SERVICE') {
        // Application service matching to container / pod workload
        const svcTokens = svc.asset.name.toLowerCase().split(/[-_]/).filter((t) => t && t !== 'service' && t !== 'svc');

        for (const pod of namespacePods) {
          const podName = pod.asset.name.toLowerCase();
          const containers = (pod.asset.metadata.containers as Array<{ name?: string; image?: string }>) || [];

          const matchesContainer = containers.some((c) => {
            const cName = (c.name || '').toLowerCase();
            const cImg = (c.image || '').toLowerCase();
            return svcTokens.some((t) => cName.includes(t) || cImg.includes(t));
          });

          const matchesPodName = svcTokens.some((t) => podName.includes(t));
          const isSinglePair = services.length === 1 && pods.length === 1;

          if (matchesContainer || matchesPodName || isSinglePair) {
            const relId = `rel-${svc.asset.id}-${pod.asset.id}`;
            if (!graph.getEdge(relId)) {
              graph.addRelationship({
                id: relId,
                tenantId,
                sourceAssetId: svc.asset.id,
                targetAssetId: pod.asset.id,
                type: 'DEPLOYED_TO',
                nature: (matchesContainer || matchesPodName) ? 'DECLARED' : 'INFERRED',
                confidence: (matchesContainer || matchesPodName) ? 1.0 : 0.85,
                metadata: {
                  matchReason: matchesContainer ? 'container-match' : matchesPodName ? 'pod-name-match' : 'single-pair',
                  namespace: svcNamespace,
                  description: 'Microservice runs inside Kubernetes pod workload',
                },
              });
            }
          }
        }
      }
    }
  }

  public linkPodsToServiceAccounts(
    pods: GraphNode[],
    serviceAccounts: GraphNode[],
    graph: SecurityGraphEngine,
    tenantId: string
  ): void {
    // Index SAs by "namespace:name" for O(1) lookup
    const saMap = new Map<string, GraphNode>();
    for (const sa of serviceAccounts) {
      const ns = (sa.asset.metadata.namespace as string) || sa.asset.environment || 'default';
      saMap.set(`${ns}:${sa.asset.name}`, sa);
    }

    for (const pod of pods) {
      const podNamespace = (pod.asset.metadata.namespace as string) || pod.asset.environment || 'default';
      const saName = (pod.asset.metadata.serviceAccountName as string) || 'default';
      const lookupKey = `${podNamespace}:${saName}`;

      const matchedSA = saMap.get(lookupKey);

      if (matchedSA) {
        const relId = `rel-${pod.asset.id}-${matchedSA.asset.id}`;
        if (!graph.getEdge(relId)) {
          graph.addRelationship({
            id: relId,
            tenantId,
            sourceAssetId: pod.asset.id,
            targetAssetId: matchedSA.asset.id,
            type: 'RUNS_AS',
            nature: 'DECLARED',
            confidence: 1.0,
            metadata: {
              serviceAccountName: saName,
              namespace: podNamespace,
            },
          });
        }
      } else {
        // DO NOT fall back to arbitrary array index!
        // Emit an UNRESOLVED_REFERENCE finding attached to the Pod
        const findingId = `finding-unresolved-sa-${pod.asset.id}-${saName}`;
        if (!pod.findings.some((f) => f.id === findingId)) {
          graph.attachFinding({
            id: findingId,
            tenantId,
            assetId: pod.asset.id,
            category: 'UNRESOLVED_REFERENCE',
            ruleId: 'K8S-UNRESOLVED-SERVICE-ACCOUNT',
            title: `Unresolved Kubernetes ServiceAccount: ${saName}`,
            description: `Pod "${pod.asset.name}" references ServiceAccount "${saName}" in namespace "${podNamespace}", but no matching ServiceAccount definition exists in the workspace.`,
            severity: 'MEDIUM',
            confidence: 'HIGH',
            scanner: 'DeterministicEntityResolver',
            evidence: createEvidence({
              id: `ev-unresolved-sa-${pod.asset.id}`,
              tenantId,
              sourceType: 'KUBERNETES',
              repository: 'workspace',
              filePath: (pod.asset.metadata.filePath as string) || 'k8s/deployment.yaml',
              lineStart: 1,
              lineEnd: 1,
              snippet: `serviceAccountName: ${saName}`,
              scanner: 'DeterministicEntityResolver',
            }),
            metadata: {
              podId: pod.asset.id,
              requestedServiceAccount: saName,
              namespace: podNamespace,
            },
          });
        }
      }
    }
  }

  public linkServiceAccountsToIamRoles(
    serviceAccounts: GraphNode[],
    iamRoles: GraphNode[],
    graph: SecurityGraphEngine,
    tenantId: string
  ): void {
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
  }

  public linkIamRolesToBuckets(
    iamRoles: GraphNode[],
    sensitiveBuckets: GraphNode[],
    graph: SecurityGraphEngine,
    tenantId: string
  ): void {
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

// 100% Backward compatibility alias
export const EntityResolver = DeterministicEntityResolver;
