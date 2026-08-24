import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { executeScan, executeRemediate, SarifFormatter } from '../src/index.js';

describe('Phase 11 - CLI Engine, CI/CD Integration & SARIF 2.1.0 Exporter', () => {
  const fixturePath = path.resolve('fixtures/001-ssrf-iam-s3');

  it('executeScan discovers attack paths and returns structured scan result', async () => {
    const result = await executeScan({
      path: fixturePath,
      format: 'table',
      tenantId: 'tenant-cli-test',
    });

    expect(result.tenantId).toBe('tenant-cli-test');
    expect(result.totalAssets).toBeGreaterThanOrEqual(5);
    expect(result.totalFindings).toBeGreaterThanOrEqual(2);
    expect(result.attackPaths.length).toBeGreaterThanOrEqual(1);
    expect(result.highestRiskScore).toBeGreaterThanOrEqual(8.5);

    const primaryPath = result.attackPaths[0];
    expect(primaryPath.entryAssetId).toBe('asset-internet');
    expect(primaryPath.targetAssetId).toContain('customer-pii');
    expect(primaryPath.recommendedChokePoint).toBeDefined();
  });

  it('SarifFormatter produces valid OASIS SARIF 2.1.0 schema report', async () => {
    const result = await executeScan({
      path: fixturePath,
      format: 'json',
      tenantId: 'tenant-sarif-test',
    });

    const sarifFormatter = new SarifFormatter();
    const sarif = sarifFormatter.format(result);

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarif.runs).toHaveLength(1);

    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe('AISecurityArchitect');
    expect(run.tool.driver.rules.length).toBeGreaterThanOrEqual(2);
    expect(run.results.length).toBeGreaterThanOrEqual(2);

    // Verify finding with physicalLocation
    const firstResult = run.results[0];
    expect(firstResult.ruleId).toBeDefined();
    expect(firstResult.level).toBeDefined();
    expect(firstResult.locations[0].physicalLocation.artifactLocation.uri).toBeDefined();
    expect(firstResult.locations[0].physicalLocation.region.startLine).toBeGreaterThanOrEqual(1);
  });

  it('executeRemediate synthesizes verified PR payload for target attack path', async () => {
    const prPayload = await executeRemediate({
      path: fixturePath,
      pathId: 'path-001',
      tenantId: 'tenant-remediation-cli',
    });

    expect(prPayload.title).toContain('fix(security)');
    expect(prPayload.branchName).toContain('security/remediate');
    expect(prPayload.bodyMarkdown).toContain('```mermaid');
    expect(prPayload.bodyMarkdown).toContain('VERIFIED CLEAN');
    expect(prPayload.verification.verified).toBe(true);
    expect(prPayload.verification.riskReductionPercentage).toBe(100);
  });
});
