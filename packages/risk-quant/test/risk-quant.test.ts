import { describe, it, expect } from 'vitest';
import type { Asset, AttackPath } from '@ai-security-architect/core';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import { FairCalculator, FAIR_DISCLAIMER } from '../src/fair-calculator.js';
import type { BreachCostReferenceTable } from '../src/types.js';

describe('Task B.2 — Cost-of-Exploit / FAIR Risk Quantification (Bands & Estimates)', () => {
  const tenantId = 'tenant-fair-test';

  function buildTopology(): SecurityGraphEngine {
    const graph = new SecurityGraphEngine(tenantId);

    const internet: Asset = {
      id: 'asset-internet',
      tenantId,
      type: 'INTERNET',
      name: 'public-internet',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'LOW',
      metadata: {},
      tags: [],
    };

    const s3Pii: Asset = {
      id: 'asset-s3-pii',
      tenantId,
      type: 'BUCKET',
      name: 'customer-credit-cards',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      metadata: {},
      tags: ['contains-pii', 'compliance=pci'],
    };

    const untaggedAsset: Asset = {
      id: 'asset-internal-worker',
      tenantId,
      type: 'SERVICE',
      name: 'background-worker',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'LOW',
      metadata: {},
      tags: [],
    };

    graph.addAsset(internet);
    graph.addAsset(s3Pii);
    graph.addAsset(untaggedAsset);

    return graph;
  }

  function makeShortPiiPath(id: string): AttackPath {
    return {
      id,
      tenantId,
      entryAssetId: 'asset-internet',
      targetAssetId: 'asset-s3-pii',
      pathLength: 2,
      steps: [
        {
          stepNumber: 1,
          sourceAssetId: 'asset-internet',
          targetAssetId: 'asset-s3-pii',
          relationshipType: 'CAN_READ',
          explanation: 'public read access to s3 bucket',
        },
      ],
      riskScore: {
        impact: 9.5,
        exploitability: 9.0,
        reachability: 1.0,
        assetCriticality: 10.0,
        confidence: 1.0,
        totalRisk: 9.5,
      },
      verifiedEliminated: false,
    };
  }

  function makeLongUntaggedPath(id: string): AttackPath {
    return {
      id,
      tenantId,
      entryAssetId: 'asset-internet',
      targetAssetId: 'asset-internal-worker',
      pathLength: 7, // Multi-hop decay
      steps: [
        {
          stepNumber: 1,
          sourceAssetId: 'asset-internet',
          targetAssetId: 'asset-internal-worker',
          relationshipType: 'ROUTES_TO',
          explanation: 'ingress to deep worker',
        },
      ],
      riskScore: {
        impact: 3.0,
        exploitability: 4.0,
        reachability: 1.0,
        assetCriticality: 3.0,
        confidence: 0.8,
        totalRisk: 3.2,
      },
      verifiedEliminated: false,
    };
  }

  it('emits Low, Likely, and High loss bands visibly labeled as [ESTIMATE]', () => {
    const graph = buildTopology();
    const path = makeShortPiiPath('path-leak-01');
    const calculator = new FairCalculator();

    const exposure = calculator.calculatePathExposure(path, graph);

    expect(exposure.pathId).toBe('path-leak-01');
    expect(exposure.estimateLabel).toBe('[ESTIMATE]');

    // Verify range order: low <= likely <= high
    expect(exposure.singleLossExpectancyBand.low).toBeLessThanOrEqual(
      exposure.singleLossExpectancyBand.likely
    );
    expect(exposure.singleLossExpectancyBand.likely).toBeLessThanOrEqual(
      exposure.singleLossExpectancyBand.high
    );

    expect(exposure.annualizedLossExpectancyBand.low).toBeLessThanOrEqual(
      exposure.annualizedLossExpectancyBand.likely
    );
    expect(exposure.annualizedLossExpectancyBand.likely).toBeLessThanOrEqual(
      exposure.annualizedLossExpectancyBand.high
    );

    // Verify driving inputs are recorded and auditable
    expect(exposure.drivingInputs).toBeDefined();
    expect(exposure.drivingInputs.terminalAssetId).toBe('asset-s3-pii');
    expect(exposure.drivingInputs.sensitivityClassifications).toContain('contains-pii');
    expect(exposure.drivingInputs.referenceTableVersion).toBeDefined();
    expect(exposure.drivingInputs.pathHops).toBe(2);
  });

  it('produces materially higher estimate for short path to PII asset vs long path to untagged asset', () => {
    const graph = buildTopology();
    const shortPiiPath = makeShortPiiPath('path-pii');
    const longUntaggedPath = makeLongUntaggedPath('path-untagged');
    const calculator = new FairCalculator();

    const piiExposure = calculator.calculatePathExposure(shortPiiPath, graph);
    const untaggedExposure = calculator.calculatePathExposure(longUntaggedPath, graph);

    // PII asset with few hops must produce substantially greater financial exposure
    expect(piiExposure.annualizedLossExpectancyBand.likely).toBeGreaterThan(
      untaggedExposure.annualizedLossExpectancyBand.likely * 10
    );
    expect(piiExposure.singleLossExpectancyBand.likely).toBeGreaterThan(
      untaggedExposure.singleLossExpectancyBand.likely * 5
    );
  });

  it('uses fully overridden reference table end-to-end without fallback', () => {
    const graph = buildTopology();
    const path = makeShortPiiPath('path-custom-ref');
    const calculator = new FairCalculator();

    const customTable: BreachCostReferenceTable = {
      version: 'custom-fintech-table-v2',
      source: 'FinTech Enterprise Risk Committee 2026',
      baseForensicCost: { low: 200000, likely: 500000, high: 1000000 },
      baseDowntimeCost: { low: 100000, likely: 300000, high: 800000 },
      costPerRecord: {
        pii: { low: 500, likely: 800, high: 1500 },
        paymentData: { low: 600, likely: 1000, high: 2000 },
        secretsOrCredentials: { low: 700, likely: 1200, high: 2500 },
        general: { low: 200, likely: 400, high: 800 },
      },
      regulatoryFineMultiplier: { low: 0.5, likely: 1.0, high: 2.0 },
    };

    const exposure = calculator.calculatePathExposure(path, graph, {
      referenceTable: customTable,
      currency: 'EUR',
    });

    expect(exposure.currency).toBe('EUR');
    expect(exposure.drivingInputs.referenceTableVersion).toBe('custom-fintech-table-v2');

    // Single loss expectancy with custom table must reflect custom forensics + record costs
    // Critical asset multiplier is 2.0 -> (500k + 300k)*2 = 1.6M primary + 10k * 800 * 2 = 16M secondary = 17.6M
    expect(exposure.singleLossExpectancyBand.likely).toBeGreaterThanOrEqual(10000000);
  });

  it('aggregates portfolio exposure with estimate tags and transparent table markdown', () => {
    const graph = buildTopology();
    const paths = [makeShortPiiPath('path-01'), makeLongUntaggedPath('path-02')];
    const calculator = new FairCalculator();

    const portfolio = calculator.calculatePortfolioExposure(paths, graph);

    expect(portfolio.evaluatedPathCount).toBe(2);
    expect(portfolio.estimateLabel).toBe('[ESTIMATE]');
    expect(portfolio.disclaimer).toContain(FAIR_DISCLAIMER);

    const markdown = calculator.formatMarkdownSummary(portfolio);
    expect(markdown).toContain('[ESTIMATE]');
    expect(markdown).toContain('Annualized Loss Expectancy (ALE)');
    expect(markdown).toContain('Prioritized Attack Path Exposure Breakdown');
  });
});
