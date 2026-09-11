import { Asset, Relationship } from '@ai-security-architect/core';
import {
  InboundSecurityAlert,
  IncidentCorrelationResult,
  LiveIncidentContext,
  BlastRadiusNode,
  LIVE_INCIDENT_CONTEXT_LABEL,
} from './types.js';

export interface IncidentCorrelatorOptions {
  maxTraversalHops?: number;
}

export class IncidentCorrelator {
  private maxHops: number;

  constructor(options: IncidentCorrelatorOptions = {}) {
    this.maxHops = options.maxTraversalHops ?? 8;
  }

  /**
   * Resolves an inbound SIEM/EDR alert to an exact asset in the security graph.
   * STRICT GUARANTEE: Never guesses or uses fuzzy matching. Rejects ambiguous or unknown identifiers.
   */
  processAlert(
    alert: InboundSecurityAlert,
    assets: Asset[],
    relationships: Relationship[]
  ): IncidentCorrelationResult {
    const id = alert.assetIdentifier.trim();
    if (!id) {
      return {
        resolved: false,
        status: 'NOT_FOUND',
        reason: 'Asset identifier in alert is empty.',
      };
    }

    // 1. Exact-match candidate search
    const exactMatches = assets.filter((a) => {
      if (a.id === id) return true;
      if (a.name === id) return true;
      if ((a as any).cloudArnOrId === id) return true;
      if (typeof a.metadata?.arn === 'string' && a.metadata.arn === id) return true;
      if (typeof a.metadata?.instanceId === 'string' && a.metadata.instanceId === id) return true;
      if (typeof a.metadata?.podName === 'string' && a.metadata.podName === id) return true;
      return false;
    });

    if (exactMatches.length === 0) {
      return {
        resolved: false,
        status: 'NOT_FOUND',
        reason: `Could not confidently resolve asset identifier "${id}" against graph inventory.`,
      };
    }

    if (exactMatches.length > 1) {
      return {
        resolved: false,
        status: 'REJECTED_AMBIGUOUS',
        reason: `Ambiguous match: Identifier "${id}" matched ${exactMatches.length} distinct assets ([${exactMatches.map((m) => m.id).join(', ')}]). Refusing to execute incident response on ambiguous target.`,
      };
    }

    const matchedAsset = exactMatches[0];

    // 2. Perform rapid in-memory graph traversal for blast radius and ingress paths
    const assetMap = new Map(assets.map((a) => [a.id, a]));

    // Forward adjacency (outbound edges)
    const forwardAdj = new Map<string, string[]>();
    // Backward adjacency (inbound edges)
    const backwardAdj = new Map<string, string[]>();

    for (const a of assets) {
      forwardAdj.set(a.id, []);
      backwardAdj.set(a.id, []);
    }

    for (const rel of relationships) {
      if (forwardAdj.has(rel.sourceAssetId)) {
        forwardAdj.get(rel.sourceAssetId)!.push(rel.targetAssetId);
      }
      if (backwardAdj.has(rel.targetAssetId)) {
        backwardAdj.get(rel.targetAssetId)!.push(rel.sourceAssetId);
      }
    }

    // A. Forward traversal: Downstream blast radius
    const blastRadiusNodes: BlastRadiusNode[] = [];
    const criticalAssetsAtRisk: string[] = [];
    const forwardVisited = new Map<string, number>(); // assetId -> hops
    forwardVisited.set(matchedAsset.id, 0);

    const fwdQueue: Array<{ id: string; hops: number }> = [{ id: matchedAsset.id, hops: 0 }];

    while (fwdQueue.length > 0) {
      const { id: currId, hops } = fwdQueue.shift()!;
      if (hops >= this.maxHops) continue;

      const neighbors = forwardAdj.get(currId) || [];
      for (const nbr of neighbors) {
        if (!forwardVisited.has(nbr)) {
          forwardVisited.set(nbr, hops + 1);
          const targetAsset = assetMap.get(nbr);
          if (targetAsset) {
            const isSensitive = Boolean(targetAsset.isSensitiveData);
            blastRadiusNodes.push({
              assetId: targetAsset.id,
              name: targetAsset.name,
              type: targetAsset.type,
              isSensitive,
              criticality: targetAsset.criticality,
              hopsFromCompromise: hops + 1,
            });

            if (targetAsset.criticality === 'CRITICAL' || isSensitive) {
              criticalAssetsAtRisk.push(`${targetAsset.name} (${targetAsset.id})`);
            }
          }
          fwdQueue.push({ id: nbr, hops: hops + 1 });
        }
      }
    }

    // B. Backward traversal: Upstream ingress paths leading into compromised asset
    const ingressPaths: string[][] = [];
    const backQueue: Array<{ id: string; path: string[] }> = [
      { id: matchedAsset.id, path: [matchedAsset.id] },
    ];
    const backVisited = new Set<string>([matchedAsset.id]);

    while (backQueue.length > 0 && ingressPaths.length < 5) {
      const { id: currId, path } = backQueue.shift()!;
      if (path.length > this.maxHops) continue;

      const parents = backwardAdj.get(currId) || [];
      if (parents.length === 0 && path.length > 1) {
        ingressPaths.push([...path].reverse());
      } else {
        for (const p of parents) {
          if (!backVisited.has(p)) {
            backVisited.add(p);
            backQueue.push({ id: p, path: [...path, p] });
          }
        }
      }
    }

    // C. Recommended Choke Points: Outbound edges directly from compromised asset
    const directOutgoing = forwardAdj.get(matchedAsset.id) || [];
    const recommendedChokePoints = directOutgoing.map((targetId) => {
      const target = assetMap.get(targetId);
      return {
        sourceAssetId: matchedAsset.id,
        targetAssetId: targetId,
        action: `Sever egress connectivity/IAM permissions from compromised ${matchedAsset.name} to ${target?.name || targetId}`,
      };
    });

    const incidentContext: LiveIncidentContext = {
      alertId: alert.alertId,
      sourceSystem: alert.sourceSystem,
      compromisedAssetId: matchedAsset.id,
      compromisedAssetName: matchedAsset.name,
      incidentTimestamp: alert.timestamp,
      ingressHops: ingressPaths.length > 0 ? ingressPaths[0].length - 1 : 0,
      ingressPaths,
      blastRadiusNodes,
      criticalAssetsAtRisk,
      recommendedChokePoints,
      contextLabel: LIVE_INCIDENT_CONTEXT_LABEL,
    };

    return {
      resolved: true,
      matchedAsset,
      incidentContext,
    };
  }
}
