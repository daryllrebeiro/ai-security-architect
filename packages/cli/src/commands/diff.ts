import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { PathDiffEngine, PrCommentFormatter, type PathDiffResult } from '@ai-security-architect/graph';
import { executeScan } from './scan.js';
import type { CliDiffOptions } from '../types.js';

export async function executeDiff(options: CliDiffOptions): Promise<PathDiffResult> {
  const format = options.format ?? (options.prComment ? 'markdown' : 'table');

  // Scan base and head silently
  const baseResult = await executeScan({
    path: options.basePath,
    tenantId: options.tenantId,
    silent: true,
  });

  const headResult = await executeScan({
    path: options.headPath,
    tenantId: options.tenantId,
    silent: true,
  });

  const diffEngine = new PathDiffEngine();
  const diffResult = diffEngine.diffAttackPaths(
    baseResult.attackPaths,
    headResult.attackPaths,
    baseResult.graph,
    headResult.graph
  );

  const formatter = new PrCommentFormatter();
  const markdownComment = formatter.format(diffResult, {
    baseRef: options.basePath,
    headRef: options.headPath,
  });

  if (options.outputFile) {
    const contentToWrite =
      format === 'json'
        ? JSON.stringify(diffResult, null, 2)
        : markdownComment;
    await fs.writeFile(options.outputFile, contentToWrite, 'utf-8');
  }

  if (format === 'json') {
    console.log(JSON.stringify(diffResult, null, 2));
  } else if (format === 'markdown' || options.prComment) {
    console.log(markdownComment);
  } else {
    // Console table format
    console.log(`\n================================================================================`);
    console.log(`  ATTACK PATH DIFF: ${options.basePath} ➔ ${options.headPath}`);
    console.log(`================================================================================`);
    console.log(`  Base Paths:            ${diffResult.summary.totalBase}`);
    console.log(`  Head Paths:            ${diffResult.summary.totalHead}`);
    console.log(`  🚨 Introduced:         ${diffResult.summary.introducedCount}`);
    console.log(`  🛡️ Closed:             ${diffResult.summary.closedCount} (Remediated: ${diffResult.summary.closedRemediatedCount}, Asset Removed: ${diffResult.summary.closedAssetRemovedCount}, Unknown: ${diffResult.summary.closedUnknownCount})`);
    console.log(`  ⚡ Severity Changed:   ${diffResult.summary.severityChangedCount}`);
    console.log(`  ⏸️ Unchanged:          ${diffResult.summary.unchangedCount}`);
    console.log(`--------------------------------------------------------------------------------`);

    if (diffResult.introduced.length > 0) {
      console.log(`  🚨 NEWLY INTRODUCED PATHS:`);
      for (const item of diffResult.introduced) {
        console.log(`    - ID: ${item.path.id} | Risk: ${item.path.riskScore.totalRisk.toFixed(1)}/10.0 | FP: ${item.fingerprint}`);
        console.log(`      ${item.path.entryAssetId} ➔ ${item.path.targetAssetId}`);
      }
    }

    if (diffResult.severityChanged.length > 0) {
      console.log(`  ⚡ SEVERITY CHANGED PATHS:`);
      for (const sc of diffResult.severityChanged) {
        const deltaStr = sc.delta > 0 ? `+${sc.delta.toFixed(1)}` : `${sc.delta.toFixed(1)}`;
        console.log(`    - FP: ${sc.fingerprint} | Base: ${sc.baseRiskScore.toFixed(1)} ➔ Head: ${sc.headRiskScore.toFixed(1)} (${deltaStr})`);
      }
    }

    if (diffResult.closed.length > 0) {
      console.log(`  🛡️ CLOSED PATHS:`);
      for (const cl of diffResult.closed) {
        console.log(`    - FP: ${cl.fingerprint} | Target: ${cl.path.targetAssetId} | Reason: ${cl.closureReason}`);
      }
    }

    console.log(`================================================================================\n`);
  }

  return diffResult;
}
