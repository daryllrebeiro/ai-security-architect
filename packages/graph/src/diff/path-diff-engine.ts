import type { AttackPath, DiffClosureReason } from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '../security-graph-engine.js';
import { computePathFingerprint } from './path-fingerprint.js';

export interface IntroducedPathItem {
  path: AttackPath;
  fingerprint: string;
}

export interface ClosedPathItem {
  path: AttackPath;
  fingerprint: string;
  closureReason: DiffClosureReason;
  originAssetId: string;
}

export interface UnchangedPathItem {
  path: AttackPath;
  fingerprint: string;
}

export interface SeverityChangedPathItem {
  basePath: AttackPath;
  headPath: AttackPath;
  fingerprint: string;
  baseRiskScore: number;
  headRiskScore: number;
  delta: number;
}

export interface PathDiffResult {
  introduced: IntroducedPathItem[];
  closed: ClosedPathItem[];
  unchanged: UnchangedPathItem[];
  severityChanged: SeverityChangedPathItem[];
  summary: {
    totalBase: number;
    totalHead: number;
    introducedCount: number;
    closedCount: number;
    closedRemediatedCount: number;
    closedAssetRemovedCount: number;
    closedUnknownCount: number;
    unchangedCount: number;
    severityChangedCount: number;
  };
}

export class PathDiffEngine {
  /**
   * Compares attack paths between base and head graph states into 4 distinct buckets
   * with origin-aware closure reason analysis.
   */
  public diffAttackPaths(
    basePaths: AttackPath[],
    headPaths: AttackPath[],
    baseGraph: SecurityGraphEngine,
    headGraph: SecurityGraphEngine
  ): PathDiffResult {
    // 1. Compute fingerprints for base paths
    const baseMap = new Map<string, AttackPath>();
    for (const p of basePaths) {
      const fp = p.fingerprint ?? computePathFingerprint(p, baseGraph);
      p.fingerprint = fp;
      baseMap.set(fp, p);
    }

    // 2. Compute fingerprints for head paths
    const headMap = new Map<string, AttackPath>();
    for (const p of headPaths) {
      const fp = p.fingerprint ?? computePathFingerprint(p, headGraph);
      p.fingerprint = fp;
      headMap.set(fp, p);
    }

    const introduced: IntroducedPathItem[] = [];
    const closed: ClosedPathItem[] = [];
    const unchanged: UnchangedPathItem[] = [];
    const severityChanged: SeverityChangedPathItem[] = [];

    // 3. Find introduced, unchanged, and severity-changed
    for (const [headFp, headPath] of headMap.entries()) {
      const basePath = baseMap.get(headFp);
      if (!basePath) {
        introduced.push({ path: headPath, fingerprint: headFp });
      } else {
        const baseRisk = basePath.riskScore.totalRisk;
        const headRisk = headPath.riskScore.totalRisk;

        if (Math.abs(baseRisk - headRisk) > 0.05) {
          severityChanged.push({
            basePath,
            headPath,
            fingerprint: headFp,
            baseRiskScore: baseRisk,
            headRiskScore: headRisk,
            delta: Math.round((headRisk - baseRisk) * 10) / 10,
          });
        } else {
          unchanged.push({ path: headPath, fingerprint: headFp });
        }
      }
    }

    // 4. Find closed paths and determine closure reason based on path assets
    for (const [baseFp, basePath] of baseMap.entries()) {
      if (!headMap.has(baseFp)) {
        // Collect all assets participating in this attack path
        const pathAssetIds = new Set<string>();
        pathAssetIds.add(basePath.entryAssetId);
        pathAssetIds.add(basePath.targetAssetId);
        for (const s of basePath.steps) {
          pathAssetIds.add(s.sourceAssetId);
          pathAssetIds.add(s.targetAssetId);
        }

        let anyAssetRemoved = false;
        let removedAssetId: string | undefined;

        for (const assetId of pathAssetIds) {
          const exists = this.doesOriginAssetExist(assetId, baseGraph, headGraph);
          if (exists === false) {
            anyAssetRemoved = true;
            removedAssetId = assetId;
            break;
          }
        }

        let closureReason: DiffClosureReason;
        const originAssetId = removedAssetId ?? this.resolveOriginAssetId(basePath, baseGraph);

        if (anyAssetRemoved) {
          // One or more assets in the path were deleted/decommissioned
          closureReason = 'asset-removed';
        } else {
          // All assets in the path still exist in headGraph, meaning
          // the vulnerability or relationship was severed -> genuine remediation
          closureReason = 'remediated';
        }

        closed.push({
          path: basePath,
          fingerprint: baseFp,
          closureReason,
          originAssetId,
        });
      }
    }

    const closedRemediatedCount = closed.filter((c) => c.closureReason === 'remediated').length;
    const closedAssetRemovedCount = closed.filter((c) => c.closureReason === 'asset-removed').length;
    const closedUnknownCount = closed.filter((c) => c.closureReason === 'unknown').length;

    return {
      introduced,
      closed,
      unchanged,
      severityChanged,
      summary: {
        totalBase: basePaths.length,
        totalHead: headPaths.length,
        introducedCount: introduced.length,
        closedCount: closed.length,
        closedRemediatedCount,
        closedAssetRemovedCount,
        closedUnknownCount,
        unchangedCount: unchanged.length,
        severityChangedCount: severityChanged.length,
      },
    };
  }

  private resolveOriginAssetId(path: AttackPath, baseGraph: SecurityGraphEngine): string {
    // If first step has a finding, origin is the source/target of that step
    if (path.steps.length > 0) {
      const firstStep = path.steps[0];
      if (firstStep.findingId) {
        const finding = baseGraph.getAllFindings().find((f) => f.id === firstStep.findingId);
        if (finding) return finding.assetId;
      }
      return firstStep.sourceAssetId;
    }
    return path.entryAssetId;
  }

  private doesOriginAssetExist(
    originAssetId: string,
    baseGraph: SecurityGraphEngine,
    headGraph: SecurityGraphEngine
  ): boolean | undefined {
    // 1. Direct ID check in head graph
    if (headGraph.hasNode(originAssetId)) {
      return true;
    }

    // 2. Name & type check in case of ID variation
    const baseNode = baseGraph.getNode(originAssetId);
    if (!baseNode) return undefined;

    const matchByName = headGraph
      .getAllNodes()
      .find((n) => n.asset.name === baseNode.asset.name && n.asset.type === baseNode.asset.type);

    if (matchByName) {
      return true;
    }

    return false;
  }
}
