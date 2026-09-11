import * as fs from 'node:fs/promises';
import { RunbookGenerator, type RemediationPlaybook } from '@ai-security-architect/runbooks';
import { executeScan } from './scan.js';
import type { CliRunbookOptions } from '../types.js';

export async function executeRunbook(options: CliRunbookOptions): Promise<RemediationPlaybook> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  if (scanResult.attackPaths.length === 0) {
    throw new Error('No attack paths found in repository to generate runbook for.');
  }

  const targetPath = options.pathId
    ? scanResult.attackPaths.find((p) => p.id === options.pathId) || scanResult.attackPaths[0]
    : scanResult.attackPaths[0];

  const generator = new RunbookGenerator();
  const playbook = generator.generatePlaybook(targetPath, scanResult.graph);
  const formatted =
    options.format === 'confluence'
      ? generator.formatConfluence(playbook)
      : generator.formatMarkdown(playbook);

  console.log(formatted);

  if (options.outputFile) {
    await fs.writeFile(options.outputFile, formatted, 'utf-8');
    console.log(`\n[Runbook] Playbook saved to ${options.outputFile}`);
  }

  return playbook;
}
