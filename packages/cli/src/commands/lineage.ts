import * as fs from 'node:fs/promises';
import { LineageTracer } from '@ai-security-architect/graph';
import { executeScan } from './scan.js';
import type { CliLineageOptions } from '../types.js';

export async function executeLineage(options: CliLineageOptions): Promise<unknown> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  const assets = scanResult.graph.getAllNodes().map((n) => n.asset);
  const edges = scanResult.graph.getAllEdges().map((e) => e.relationship);

  const tracer = new LineageTracer(assets, edges);

  const targetId =
    options.entryAssetId ||
    assets.find((a) => a.isSensitiveData)?.id ||
    assets[0]?.id;

  if (!targetId) {
    throw new Error('No assets found in graph to trace lineage');
  }

  const result =
    options.direction === 'reverse'
      ? tracer.traceReverse(targetId)
      : tracer.traceForward(targetId);

  const outputStr = JSON.stringify(result, null, 2);
  console.log(outputStr);

  if (options.outputFile) {
    await fs.writeFile(options.outputFile, outputStr, 'utf-8');
    console.log(`\n[Lineage] Saved data flow lineage to ${options.outputFile}`);
  }

  return result;
}
