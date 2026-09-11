import { BudgetEvaluator, type BudgetEvaluationResult } from '@ai-security-architect/policy';
import { computePathFingerprint, type PathDiffResult } from '@ai-security-architect/graph';
import { executeScan } from './scan.js';
import type { CliPolicyOptions } from '../types.js';

export async function executePolicy(options: CliPolicyOptions): Promise<BudgetEvaluationResult> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  const diff: PathDiffResult = {
    introduced: scanResult.attackPaths.map((p) => ({
      path: p,
      fingerprint: computePathFingerprint(p, scanResult.graph),
    })),
    closed: [],
    unchanged: [],
    severityChanged: [],
    summary: {
      totalBase: 0,
      totalHead: scanResult.attackPaths.length,
      introducedCount: scanResult.attackPaths.length,
      closedCount: 0,
      closedRemediatedCount: 0,
      closedAssetRemovedCount: 0,
      closedUnknownCount: 0,
      unchangedCount: 0,
      severityChangedCount: 0,
    },
  };

  const evaluator = new BudgetEvaluator();
  const evaluation = await evaluator.evaluateWithBaseline(
    scanResult.attackPaths,
    scanResult.graph,
    {
      grandfatherExisting: true,
      maxCriticalPaths: 0,
      maxRiskScorePerPath: 8.5,
      maxNewPathsPerPR: 0,
    }
  );

  console.log(`\n================================================================================`);
  console.log(`  SECURITY BUDGET & POLICY-AS-CODE GUARDRAIL EVALUATION`);
  console.log(`================================================================================`);
  console.log(`  Repository:          ${scanResult.repository}`);
  console.log(`  Policy Status:       ${evaluation.passed ? '✅ PASSED' : '❌ BREACHED (BLOCK MERGE)'}`);
  console.log(`  Total Violations:    ${evaluation.summary.totalViolations} (${evaluation.summary.criticalViolations} Critical)`);
  console.log(`  Evaluated Paths:     ${evaluation.summary.totalEvaluated}`);
  console.log(`  Grandfathered Paths: ${evaluation.summary.grandfatheredCount}`);
  console.log(`--------------------------------------------------------------------------------`);

  if (evaluation.violations.length > 0) {
    console.log(`  🚨 POLICY BUDGET BREACHES (CI BLOCKING):`);
    for (const v of evaluation.violations) {
      console.log(`    ⚠️  [${v.severity}] Rule '${v.rule}': ${v.message}`);
      if (v.pathId) {
        console.log(`       Triggering Path(s): ${v.pathId}`);
      }
    }
  } else {
    console.log(`  ✅ All security budget thresholds respected. Merge allowed.`);
  }
  console.log(`================================================================================\n`);

  if (options.failOnBreach && !evaluation.passed) {
    // Distinct exit code 2 for policy budget violation (vs exit code 1 for runtime crashes)
    process.exitCode = 2;
  }

  return evaluation;
}
