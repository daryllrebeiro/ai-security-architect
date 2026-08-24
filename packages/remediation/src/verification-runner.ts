import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';
import type { AttackPath, Finding } from '@ai-security-architect/core';
import { DiscoveryEngine } from '@ai-security-architect/discovery';
import { AnalyzerRunner } from '@ai-security-architect/analyzers';
import { EntityResolver } from '@ai-security-architect/graph';
import { AttackPathEngine } from '@ai-security-architect/attackpath';
import type { VerificationResult } from './types.js';

export class VerificationRunner {
  public async verifyRemediation(options: {
    tenantId: string;
    repository: string;
    workspace: EphemeralWorkspace;
    initialAttackPath: AttackPath;
    initialFindings: Finding[];
  }): Promise<VerificationResult> {
    const { tenantId, repository, workspace, initialAttackPath, initialFindings } = options;

    // 1. Re-run Discovery
    const discoveryEngine = new DiscoveryEngine();
    const postDiscovery = await discoveryEngine.discover({
      tenantId,
      repository,
      workspace,
    });

    // 2. Re-run Security Analyzers
    const analyzerRunner = new AnalyzerRunner();
    const postAnalysis = await analyzerRunner.runAnalyzers({
      tenantId,
      repository,
      workspace,
      discoveredAssets: postDiscovery.assets,
    });

    // 3. Re-run Entity Resolver & Graph Construction
    const resolver = new EntityResolver();
    const postGraph = resolver.resolve({
      tenantId,
      assets: postDiscovery.assets,
      relationships: postDiscovery.relationships,
      findings: postAnalysis.findings,
      evidence: [...postDiscovery.evidence, ...postAnalysis.evidence],
    });

    // 4. Re-run Attack Path Traversal
    const pathEngine = new AttackPathEngine();
    const postAttackPaths = pathEngine.analyzePaths(postGraph);

    // 5. Evaluate Target Path Elimination
    const remainingTargetPaths = postAttackPaths.filter(
      (p) =>
        p.entryAssetId === initialAttackPath.entryAssetId &&
        p.targetAssetId === initialAttackPath.targetAssetId
    );

    const isTargetEliminated = remainingTargetPaths.length === 0;
    const initialRisk = initialAttackPath.riskScore.totalRisk;
    const postRisk = isTargetEliminated ? 0.0 : (postAttackPaths[0]?.riskScore.totalRisk || 0.0);
    const riskReductionPercentage = isTargetEliminated
      ? 100
      : Math.round(((initialRisk - postRisk) / initialRisk) * 100);

    // 6. Check for newly introduced regressions
    const initialFindingIds = new Set(initialFindings.map((f) => f.ruleId));
    const newRegressions = postAnalysis.findings.filter(
      (f) => !initialFindingIds.has(f.ruleId)
    );

    const verified = isTargetEliminated && newRegressions.length === 0;

    return {
      verified,
      initialRiskScore: initialRisk,
      postRemediationRiskScore: postRisk,
      riskReductionPercentage,
      pathsEliminatedCount: isTargetEliminated ? 1 : 0,
      remainingPathsCount: remainingTargetPaths.length,
      severedEdges: isTargetEliminated
        ? [
            `${initialAttackPath.recommendedChokePoint?.sourceAssetId || 'source'} -> ${
              initialAttackPath.recommendedChokePoint?.targetAssetId || 'target'
            }`,
          ]
        : [],
      newRegressionsCount: newRegressions.length,
      verificationTimestamp: new Date().toISOString(),
    };
  }
}
