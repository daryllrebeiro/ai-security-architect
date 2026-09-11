import { describe, it, expect } from 'vitest';
import type { AttackPath } from '@ai-security-architect/core';
import type { PathDiffResult } from '@ai-security-architect/graph';
import { BudgetEvaluator } from '../src/budget-evaluator.js';

describe('Task A.4 — Policy-as-Code Guardrails (Security Budgets)', () => {
  function makeMockPath(id: string, totalRisk: number, relationshipType = 'ROUTES_TO'): AttackPath {
    return {
      id,
      tenantId: 'tenant-test',
      entryAssetId: 'asset-entry',
      targetAssetId: 'asset-target',
      pathLength: 2,
      fingerprint: `fp-${id}`,
      steps: [
        {
          stepNumber: 1,
          sourceAssetId: 'asset-entry',
          targetAssetId: 'asset-mid',
          relationshipType: relationshipType as any,
          explanation: 'step 1',
        },
        {
          stepNumber: 2,
          sourceAssetId: 'asset-mid',
          targetAssetId: 'asset-target',
          relationshipType: 'CAN_READ',
          explanation: 'step 2',
        },
      ],
      riskScore: {
        impact: 9.0,
        exploitability: 9.0,
        reachability: 1.0,
        assetCriticality: 9.0,
        confidence: 1.0,
        totalRisk,
      },
      verifiedEliminated: false,
    };
  }

  it('fails PR when maxNewPathsPerPR is 0 and new path is introduced, while grandfathering existing paths', () => {
    const evaluator = new BudgetEvaluator();

    const existingPath = makeMockPath('path-legacy-01', 9.2);
    const newPath = makeMockPath('path-new-pr-01', 7.5);

    const mockDiff: PathDiffResult = {
      introduced: [{ path: newPath, fingerprint: newPath.fingerprint! }],
      closed: [],
      unchanged: [{ path: existingPath, fingerprint: existingPath.fingerprint! }],
      severityChanged: [],
      summary: {
        totalBase: 1,
        totalHead: 2,
        introducedCount: 1,
        closedCount: 0,
        closedRemediatedCount: 0,
        closedAssetRemovedCount: 0,
        closedUnknownCount: 0,
        unchangedCount: 1,
        severityChangedCount: 0,
      },
    };

    const result = evaluator.evaluateDiff(mockDiff, {
      maxNewPathsPerPR: 0,
      grandfatherExisting: true,
      maxCriticalPaths: 0,
    });

    expect(result.passed).toBe(false);
    expect(result.summary.grandfatheredCount).toBe(1);
    expect(result.grandfatheredPaths[0].id).toBe('path-legacy-01');

    // Only 1 violation for maxNewPathsPerPR (legacy critical path was grandfathered)
    expect(result.violations.length).toBe(1);
    expect(result.violations[0].rule).toBe('maxNewPathsPerPR');
    expect(result.violations[0].actualValue).toBe(1);
  });

  it('fails with maxCriticalPaths violation when grandfatherExisting is false', () => {
    const evaluator = new BudgetEvaluator();

    const existingCriticalPath = makeMockPath('path-legacy-01', 9.5);

    const mockDiff: PathDiffResult = {
      introduced: [],
      closed: [],
      unchanged: [{ path: existingCriticalPath, fingerprint: existingCriticalPath.fingerprint! }],
      severityChanged: [],
      summary: {
        totalBase: 1,
        totalHead: 1,
        introducedCount: 0,
        closedCount: 0,
        closedRemediatedCount: 0,
        closedAssetRemovedCount: 0,
        closedUnknownCount: 0,
        unchangedCount: 1,
        severityChangedCount: 0,
      },
    };

    // Strict audit: grandfathering is disabled
    const result = evaluator.evaluateDiff(mockDiff, {
      maxCriticalPaths: 0,
      grandfatherExisting: false,
    });

    expect(result.passed).toBe(false);
    expect(result.violations.some((v) => v.rule === 'maxCriticalPaths')).toBe(true);
    expect(result.summary.grandfatheredCount).toBe(0);
  });

  it('detects and flags prohibited relationship types along evaluated attack paths', () => {
    const evaluator = new BudgetEvaluator();

    const dangerousPath = makeMockPath('path-dangerous-role', 8.0, 'ASSUMES_ROLE');

    const mockDiff: PathDiffResult = {
      introduced: [{ path: dangerousPath, fingerprint: dangerousPath.fingerprint! }],
      closed: [],
      unchanged: [],
      severityChanged: [],
      summary: {
        totalBase: 0,
        totalHead: 1,
        introducedCount: 1,
        closedCount: 0,
        closedRemediatedCount: 0,
        closedAssetRemovedCount: 0,
        closedUnknownCount: 0,
        unchangedCount: 0,
        severityChangedCount: 0,
      },
    };

    const result = evaluator.evaluateDiff(mockDiff, {
      maxNewPathsPerPR: 5,
      prohibitedRelationshipTypes: ['ASSUMES_ROLE'],
    });

    expect(result.passed).toBe(false);
    const violation = result.violations.find((v) => v.rule === 'prohibitedRelationshipType');
    expect(violation).toBeDefined();
    expect(violation?.pathId).toBe('path-dangerous-role');
    expect(violation?.actualValue).toBe('ASSUMES_ROLE');
  });

  it('bypasses violation when path fingerprint is explicitly allowlisted', () => {
    const evaluator = new BudgetEvaluator();

    const knownPath = makeMockPath('path-accepted-risk', 9.8);

    const mockDiff: PathDiffResult = {
      introduced: [{ path: knownPath, fingerprint: knownPath.fingerprint! }],
      closed: [],
      unchanged: [],
      severityChanged: [],
      summary: {
        totalBase: 0,
        totalHead: 1,
        introducedCount: 1,
        closedCount: 0,
        closedRemediatedCount: 0,
        closedAssetRemovedCount: 0,
        closedUnknownCount: 0,
        unchangedCount: 0,
        severityChangedCount: 0,
      },
    };

    const result = evaluator.evaluateDiff(mockDiff, {
      maxNewPathsPerPR: 1,
      maxRiskScorePerPath: 8.0,
      allowlistFingerprints: [knownPath.fingerprint!],
    });

    expect(result.passed).toBe(true);
    expect(result.violations.length).toBe(0);
  });

  it('passes cleanly when PR closes a path and introduces none', () => {
    const evaluator = new BudgetEvaluator();

    const remediatedPath = makeMockPath('path-fixed-01', 9.0);

    const mockDiff: PathDiffResult = {
      introduced: [],
      closed: [
        {
          path: remediatedPath,
          fingerprint: remediatedPath.fingerprint!,
          closureReason: 'remediated',
          originAssetId: 'asset-entry',
        },
      ],
      unchanged: [],
      severityChanged: [],
      summary: {
        totalBase: 1,
        totalHead: 0,
        introducedCount: 0,
        closedCount: 1,
        closedRemediatedCount: 1,
        closedAssetRemovedCount: 0,
        closedUnknownCount: 0,
        unchangedCount: 0,
        severityChangedCount: 0,
      },
    };

    const result = evaluator.evaluateDiff(mockDiff, {
      maxNewPathsPerPR: 0,
      maxCriticalPaths: 0,
    });

    expect(result.passed).toBe(true);
    expect(result.violations.length).toBe(0);
  });
});
