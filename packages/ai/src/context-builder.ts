import {
  AIContextHandoffSchema,
  type AIContextHandoff,
  type AttackPath,
  type Finding,
} from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';

export function redactSensitiveData(text: string): string {
  return text
    // GitHub Personal Access Token
    .replace(/ghp_[a-zA-Z0-9]{36}/g, '[REDACTED_GITHUB_TOKEN]')
    // AWS Access Key ID
    .replace(/(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, '[REDACTED_AWS_ACCESS_KEY]')
    // Generic Private Keys
    .replace(/-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]')
    // Passwords / tokens in assignments (avoid overwriting existing [REDACTED_ tags)
    .replace(/((?:password|passwd|pwd|secret|token|api_key)\s*[:=]\s*["'])(?!\[REDACTED_)([^"'\s]{6,})(["'])/gi, '$1[REDACTED_SECRET]$3')
    // Bearer tokens
    .replace(/Bearer\s+(?!\[REDACTED_)[a-zA-Z0-9_\-\.]{20,}/gi, 'Bearer [REDACTED_AUTH_TOKEN]');
}

export class ContextBuilder {
  public buildContextHandoff(
    attackPath: AttackPath,
    graph: SecurityGraphEngine,
    repository: string
  ): AIContextHandoff {
    const evidenceReferences: AIContextHandoff['evidenceReferences'] = [];
    const findingsSummary: AIContextHandoff['findingsSummary'] = [];
    const seenEvidenceIds = new Set<string>();
    const seenFindingIds = new Set<string>();

    const pathNodeIds = new Set<string>([
      attackPath.entryAssetId,
      attackPath.targetAssetId,
      ...attackPath.steps.map((s) => s.sourceAssetId),
      ...attackPath.steps.map((s) => s.targetAssetId),
    ]);

    // Also collect child nodes connected to path nodes (e.g. Endpoints contained by a Service)
    const expandedNodeIds = new Set<string>(pathNodeIds);
    for (const nodeId of pathNodeIds) {
      const outgoing = graph.getOutgoingEdges(nodeId);
      for (const edge of outgoing) {
        if (edge.type === 'CONTAINS' || edge.type === 'DEPLOYED_TO' || edge.type === 'RUNS_AS') {
          expandedNodeIds.add(edge.targetAssetId);
        }
      }
    }

    for (const nodeId of expandedNodeIds) {
      const node = graph.getNode(nodeId);
      if (!node) continue;

      for (const finding of node.findings) {
        if (!seenFindingIds.has(finding.id)) {
          seenFindingIds.add(finding.id);
          findingsSummary.push({
            findingId: finding.id,
            category: finding.category,
            title: finding.title,
            severity: finding.severity,
            ruleId: finding.ruleId,
          });
        }

        if (finding.evidence && !seenEvidenceIds.has(finding.evidence.id)) {
          seenEvidenceIds.add(finding.evidence.id);
          evidenceReferences.push({
            evidenceId: finding.evidence.id,
            sourceType: finding.evidence.sourceType,
            repository: finding.evidence.repository || repository,
            filePath: finding.evidence.filePath,
            lineRange: `${finding.evidence.lineStart}-${finding.evidence.lineEnd}`,
            snippet: redactSensitiveData(finding.evidence.snippet),
          });
        }
      }
    }

    // Default optimal choke point edge fallback if not present
    const chokePoint = attackPath.recommendedChokePoint || {
      sourceAssetId: attackPath.steps[attackPath.steps.length - 1]?.sourceAssetId || attackPath.entryAssetId,
      targetAssetId: attackPath.targetAssetId,
      relationshipType: attackPath.steps[attackPath.steps.length - 1]?.relationshipType || 'CAN_READ',
    };

    const handoff: AIContextHandoff = {
      attackPathId: attackPath.id,
      deterministicMetrics: {
        entryNode: attackPath.entryAssetId,
        targetNode: attackPath.targetAssetId,
        pathLength: attackPath.pathLength,
        calculatedRiskScore: attackPath.riskScore.totalRisk,
        riskBreakdown: attackPath.riskScore,
        optimalChokePointEdge: {
          source: chokePoint.sourceAssetId,
          relationship: chokePoint.relationshipType,
          target: chokePoint.targetAssetId,
        },
      },
      graphChain: attackPath.steps,
      evidenceReferences,
      findingsSummary,
    };

    AIContextHandoffSchema.parse(handoff);
    return handoff;
  }
}
