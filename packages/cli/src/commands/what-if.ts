import * as fs from 'node:fs/promises';
import { WhatIfEngine, type WhatIfHypothesis } from '@ai-security-architect/attackpath';
import { executeScan } from './scan.js';
import type { CliWhatIfOptions } from '../types.js';

export async function executeWhatIf(options: CliWhatIfOptions): Promise<unknown> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  const hypothesis: WhatIfHypothesis = {
    id: `hyp-${Date.now()}`,
    action: options.action,
    target: {
      sourceAssetId: options.sourceAssetId,
      targetAssetId: options.targetAssetId,
      edgeType: options.edgeType,
      assetId: options.assetId,
    },
    description: `Remediation hypothesis for ${options.action}`,
  };

  const engine = new WhatIfEngine();
  const outcome = engine.evaluateHypothesis(scanResult.graph, hypothesis);

  const outputStr = JSON.stringify(outcome, null, 2);
  console.log(outputStr);

  if (options.outputFile) {
    await fs.writeFile(options.outputFile, outputStr, 'utf-8');
    console.log(`\n[What-If] Saved simulation outcome to ${options.outputFile}`);
  }

  return outcome;
}
