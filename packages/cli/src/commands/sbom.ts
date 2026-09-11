import * as fs from 'node:fs/promises';
import { CycloneDxGenerator, SpdxGenerator } from '@ai-security-architect/discovery';
import { executeScan } from './scan.js';
import type { CliSbomOptions } from '../types.js';

export async function executeSbom(options: CliSbomOptions): Promise<unknown> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  const nodes = scanResult.graph.getAllNodes();
  let dependencies = nodes
    .filter((n) => n.asset.type === 'DEPENDENCY' || n.asset.metadata?.dependencyType)
    .map((n) => ({
      name: n.asset.name,
      version: (n.asset.metadata?.version as string) || '1.0.0',
      ecosystem: ((n.asset.metadata?.ecosystem as string) || 'npm') as any,
      purl: n.asset.metadata?.purl as string | undefined,
      license: (n.asset.metadata?.license as string) || 'Apache-2.0',
    }));

  if (dependencies.length === 0) {
    // Fall back to general components in graph
    dependencies = nodes.map((n) => ({
      name: n.asset.name,
      version: '1.0.0',
      ecosystem: 'npm' as any,
      purl: undefined,
      license: 'MIT',
    }));
  }

  const sbomOptions = {
    serviceName: scanResult.repository || 'workspace-sbom',
    version: '1.0.0',
  };

  let outputObj: unknown;
  if (options.format === 'spdx') {
    outputObj = SpdxGenerator.generate(dependencies, sbomOptions);
  } else {
    outputObj = CycloneDxGenerator.generate(dependencies, sbomOptions);
  }

  const outputStr = JSON.stringify(outputObj, null, 2);
  console.log(outputStr);

  if (options.outputFile) {
    await fs.writeFile(options.outputFile, outputStr, 'utf-8');
    console.log(`\n[SBOM] Saved ${options.format ?? 'cyclonedx'} SBOM to ${options.outputFile}`);
  }

  return outputObj;
}
