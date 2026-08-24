import {
  AttackPathSchema,
  calculateRiskScore,
  type AttackPath,
  type AttackStep,
  type Asset,
} from '@ai-security-architect/core';
import type { SecurityGraphEngine, GraphEdge } from '@ai-security-architect/graph';
import type { AttackPathAnalysisOptions } from './types.js';

export class AttackPathEngine {
  public findEntryPoints(graph: SecurityGraphEngine): Asset[] {
    return graph
      .getAllNodes()
      .filter((n) => n.asset.type === 'INTERNET' || n.asset.isPublic === true)
      .map((n) => n.asset);
  }

  public findSensitiveTargets(graph: SecurityGraphEngine): Asset[] {
    return graph
      .getAllNodes()
      .filter(
        (n) =>
          n.asset.isSensitiveData === true ||
          n.asset.type === 'BUCKET' ||
          n.asset.type === 'DATABASE' ||
          n.asset.type === 'SECRET'
      )
      .map((n) => n.asset);
  }

  public analyzePaths(
    graph: SecurityGraphEngine,
    options: AttackPathAnalysisOptions = {}
  ): AttackPath[] {
    const entryPoints = this.findEntryPoints(graph);
    const targets = this.findSensitiveTargets(graph);
    const maxDepth = options.maxPathLength ?? 10;

    const attackPaths: AttackPath[] = [];
    let pathCounter = 1;

    for (const entry of entryPoints) {
      for (const target of targets) {
        if (entry.id === target.id) continue;

        const rawPaths = graph.findAllPaths(entry.id, target.id, { maxDepth });

        for (const rawEdges of rawPaths) {
          if (rawEdges.length === 0) continue;

          const steps = this.buildAttackSteps(graph, rawEdges);
          const riskScore = this.calculatePathRisk(graph, rawEdges, entry, target);

          const attackPath: AttackPath = {
            id: `path-${String(pathCounter++).padStart(3, '0')}`,
            tenantId: graph.tenantId,
            entryAssetId: entry.id,
            targetAssetId: target.id,
            pathLength: rawEdges.length,
            steps,
            riskScore,
            verifiedEliminated: false,
          };

          AttackPathSchema.parse(attackPath);
          attackPaths.push(attackPath);
        }
      }
    }

    // Sort paths by highest risk first
    attackPaths.sort((a, b) => b.riskScore.totalRisk - a.riskScore.totalRisk);
    return attackPaths;
  }

  private buildAttackSteps(graph: SecurityGraphEngine, edges: GraphEdge[]): AttackStep[] {
    const steps: AttackStep[] = [];

    for (let i = 0; i < edges.length; i++) {
      const edge = edges[i];
      const sourceNode = graph.getNode(edge.sourceAssetId);
      const targetNode = graph.getNode(edge.targetAssetId);

      const sourceName = sourceNode?.asset.name ?? edge.sourceAssetId;
      const targetName = targetNode?.asset.name ?? edge.targetAssetId;

      // Find any finding attached to the source asset matching this hop
      const matchingFinding = sourceNode?.findings[0];

      let explanation = `Attacker pivots from ${sourceName} to ${targetName} via ${edge.type}`;
      if (edge.type === 'EXPOSES_HTTP') {
        explanation = `Public internet traffic accesses exposed ingress endpoint on ${targetName}`;
      } else if (edge.type === 'ROUTES_TO') {
        explanation = `Ingress load balancer forwards traffic to backend ${targetName}`;
      } else if (edge.type === 'DEPLOYED_TO') {
        explanation = `Workload execution context runs within container/pod ${targetName}`;
      } else if (edge.type === 'RUNS_AS') {
        explanation = `Workload runs under the identity of ${targetName}`;
      } else if (edge.type === 'ASSUMES_ROLE') {
        explanation = `Workload identity assumes cloud IAM Role ${targetName}${
          matchingFinding ? ` (leveraging ${matchingFinding.title})` : ''
        }`;
      } else if (edge.type === 'CAN_READ' || edge.type === 'CAN_WRITE') {
        explanation = `Assumed IAM role grants ${edge.type === 'CAN_READ' ? 'read' : 'write'} access to sensitive asset ${targetName}`;
      }

      steps.push({
        stepNumber: i + 1,
        sourceAssetId: edge.sourceAssetId,
        targetAssetId: edge.targetAssetId,
        relationshipType: edge.type,
        findingId: matchingFinding?.id,
        evidenceRef: edge.evidenceRef || matchingFinding?.evidence?.id,
        explanation,
      });
    }

    return steps;
  }

  private calculatePathRisk(
    graph: SecurityGraphEngine,
    edges: GraphEdge[],
    entry: Asset,
    target: Asset
  ) {
    // 1. Calculate Target Criticality
    const criticalityMap: Record<string, number> = {
      CRITICAL: 10.0,
      HIGH: 8.0,
      MEDIUM: 5.0,
      LOW: 2.0,
    };
    const targetCriticality = criticalityMap[target.criticality] ?? 8.0;

    // 2. Exploitability (based on public exposure + highest finding severity on path)
    let maxFindingSeverity = 5.0;
    for (const edge of edges) {
      const node = graph.getNode(edge.sourceAssetId);
      if (node?.findings) {
        for (const finding of node.findings) {
          if (finding.severity === 'CRITICAL') maxFindingSeverity = Math.max(maxFindingSeverity, 9.5);
          else if (finding.severity === 'HIGH') maxFindingSeverity = Math.max(maxFindingSeverity, 8.5);
          else if (finding.severity === 'MEDIUM') maxFindingSeverity = Math.max(maxFindingSeverity, 6.0);
        }
      }
    }

    const exploitability = entry.isPublic ? Math.min(10.0, maxFindingSeverity + 0.5) : maxFindingSeverity;

    // 3. Impact (Impact on target data confidentiality/integrity)
    const impact = target.isSensitiveData ? 9.5 : targetCriticality;

    // 4. Reachability & Confidence
    const reachability = 1.0; // Path exists deterministically
    const avgConfidence =
      edges.reduce((sum, e) => sum + (e.confidence ?? 1.0), 0) / Math.max(1, edges.length);

    return calculateRiskScore({
      impact,
      exploitability,
      reachability,
      assetCriticality: targetCriticality,
      confidence: Math.round(avgConfidence * 100) / 100,
    });
  }
}
