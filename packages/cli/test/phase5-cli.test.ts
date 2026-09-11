import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import { describe, it, expect, beforeAll } from 'vitest';
import { executeSbom } from '../src/commands/sbom.js';
import { executeLineage } from '../src/commands/lineage.js';
import { executeLeastPrivilege } from '../src/commands/least-privilege.js';
import { executeBriefing } from '../src/commands/briefing.js';
import { executeWhatIf } from '../src/commands/what-if.js';

describe('Phase 5 — Advanced Capabilities CLI Integration (Waves D, E, F)', () => {
  const fixturePath = path.resolve('fixtures/001-ssrf-iam-s3');
  const tempOutputDir = path.resolve('.sec-arch/test-output-phase5');

  beforeAll(async () => {
    await fs.mkdir(tempOutputDir, { recursive: true });
  });

  it('sec-arch sbom: exports CycloneDX specification with components and dependencies', async () => {
    const sbomPath = path.join(tempOutputDir, 'sbom-cyclonedx.json');
    const result = (await executeSbom({
      path: fixturePath,
      format: 'cyclonedx',
      outputFile: sbomPath,
    })) as Record<string, unknown>;

    expect(result).toBeDefined();
    expect(result.bomFormat).toBe('CycloneDX');
    expect(result.specVersion).toBe('1.5');
    expect(Array.isArray(result.components)).toBe(true);

    const fileContent = await fs.readFile(sbomPath, 'utf-8');
    expect(fileContent).toContain('CycloneDX');
  });

  it('sec-arch lineage: traces sensitive data flows across repository architecture', async () => {
    const lineagePath = path.join(tempOutputDir, 'lineage.json');
    const result = (await executeLineage({
      path: fixturePath,
      direction: 'forward',
      outputFile: lineagePath,
    })) as Record<string, unknown>;

    expect(result).toBeDefined();
    expect(result.sourceAsset).toBeDefined();
    expect((result.sourceAsset as any).id).toBeDefined();
    expect(Array.isArray(result.downstreamAssets)).toBe(true);

    const fileContent = await fs.readFile(lineagePath, 'utf-8');
    expect(fileContent).toContain('sourceAsset');
  });

  it('sec-arch least-privilege: calculates inferred permissions and right-sizing policy diff', async () => {
    const policyPath = path.join(tempOutputDir, 'least-privilege.json');
    const result = (await executeLeastPrivilege({
      path: fixturePath,
      roleId: 'arn:aws:iam::123456789012:role/AppExecutionRole',
      outputFile: policyPath,
    })) as Record<string, unknown>;

    expect(result).toBeDefined();
    expect(result.policyId).toBe('arn:aws:iam::123456789012:role/AppExecutionRole');
    expect(result.status).toBeDefined();
    expect(result.isProvisional).toBe(true);

    const fileContent = await fs.readFile(policyPath, 'utf-8');
    expect(fileContent).toContain('AppExecutionRole');
  });

  it('sec-arch briefing: generates 1-page board-ready executive risk briefing without jargon', async () => {
    const briefingPath = path.join(tempOutputDir, 'executive-briefing.md');
    const result = (await executeBriefing({
      path: fixturePath,
      reportingPeriod: 'Q3 2026',
      currency: 'USD',
      outputFile: briefingPath,
    })) as Record<string, unknown>;

    expect(result).toBeDefined();
    expect(result.postureTrend).toBeDefined();
    expect(result.executiveSummary).toBeDefined();
    expect(result.markdown).toContain('Executive Cybersecurity Risk Briefing');

    const fileContent = await fs.readFile(briefingPath, 'utf-8');
    expect(fileContent).toContain('Executive Cybersecurity Risk Briefing');
    expect(fileContent).toContain('Model Estimate');
  });

  it('sec-arch what-if: simulates hypothetical edge severance with zero persistent mutation', async () => {
    const whatIfPath = path.join(tempOutputDir, 'what-if.json');
    const result = (await executeWhatIf({
      path: fixturePath,
      action: 'SEVER_EDGE',
      sourceAssetId: 'role-s3-access',
      targetAssetId: 's3-customer-data',
      outputFile: whatIfPath,
    })) as Record<string, unknown>;

    expect(result).toBeDefined();
    expect(result.isSimulatedOnly).toBe(true);
    expect(result.baselinePathsCount).toBeGreaterThanOrEqual(1);
    expect(result.riskDelta).toBeDefined();

    const fileContent = await fs.readFile(whatIfPath, 'utf-8');
    expect(fileContent).toContain('isSimulatedOnly');
  });
});
