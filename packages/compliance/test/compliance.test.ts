import { describe, it, expect } from 'vitest';
import { createEvidence, type Asset, type AttackPath, type Finding } from '@ai-security-architect/core';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import { ComplianceEngine } from '../src/compliance-engine.js';

describe('Task B.1 — Compliance Framework Mapping (Data-Driven & Honest Partitioning)', () => {
  const tenantId = 'tenant-compliance-test';

  function buildGraph(): SecurityGraphEngine {
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

    const alb: Asset = {
      id: 'asset-alb',
      tenantId,
      type: 'LOAD_BALANCER',
      name: 'public-alb',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'MEDIUM',
      metadata: {},
      tags: [],
    };

    const cardDatabase: Asset = {
      id: 'asset-db-pci',
      tenantId,
      type: 'DATABASE',
      name: 'cardholder-db',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      metadata: {},
      tags: ['compliance=pci', 'contains-payment-data'],
    };

    graph.addAsset(internet);
    graph.addAsset(alb);
    graph.addAsset(cardDatabase);

    // Finding attached to ALB: SSRF
    const ssrfFinding: Finding = {
      id: 'finding-ssrf-001',
      tenantId,
      assetId: alb.id,
      category: 'SSRF',
      ruleId: 'rule-ssrf-ingress',
      title: 'Server-Side Request Forgery on Ingress Endpoint',
      description: 'Ingress forwards untrusted user input without validation.',
      severity: 'HIGH',
      confidence: 'CERTAIN',
      scanner: 'Semgrep',
      evidence: createEvidence({
        id: 'ev-001',
        tenantId,
        sourceType: 'SOURCE_CODE',
        repository: 'payments',
        filePath: 'src/proxy.ts',
        lineStart: 12,
        lineEnd: 15,
        snippet: 'fetch(req.query.url)',
        scanner: 'Semgrep',
      }),
      metadata: {},
    };
    graph.attachFinding(ssrfFinding);

    // Finding attached with an arbitrary category unmapped in standard frameworks (e.g. UNRESOLVED_REFERENCE)
    const unmappedFinding: Finding = {
      id: 'finding-unmapped-002',
      tenantId,
      assetId: cardDatabase.id,
      category: 'UNRESOLVED_REFERENCE',
      ruleId: 'rule-unresolved-ref',
      title: 'Dangling Terraform Resource Reference',
      description: 'Resource references variable that has no default.',
      severity: 'LOW',
      confidence: 'CERTAIN',
      scanner: 'IaCParser',
      evidence: createEvidence({
        id: 'ev-002',
        tenantId,
        sourceType: 'TERRAFORM',
        repository: 'infra',
        filePath: 'main.tf',
        lineStart: 45,
        lineEnd: 46,
        snippet: 'var.missing_id',
        scanner: 'IaCParser',
      }),
      metadata: {},
    };
    graph.attachFinding(unmappedFinding);

    return graph;
  }

  function makeMockPath(id: string): AttackPath {
    return {
      id,
      tenantId,
      entryAssetId: 'asset-internet',
      targetAssetId: 'asset-db-pci',
      pathLength: 2,
      steps: [
        {
          stepNumber: 1,
          sourceAssetId: 'asset-internet',
          targetAssetId: 'asset-alb',
          relationshipType: 'EXPOSES_HTTP',
          findingId: 'finding-ssrf-001',
          explanation: 'public ingress to alb exploiting ssrf',
        },
        {
          stepNumber: 2,
          sourceAssetId: 'asset-alb',
          targetAssetId: 'asset-db-pci',
          relationshipType: 'CAN_READ',
          explanation: 'alb reads card database',
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

  it('correctly partitions controls into covered-clean, covered-with-findings, and not-observable', () => {
    const graph = buildGraph();
    const paths = [makeMockPath('path-pci-leak-01')];
    const engine = new ComplianceEngine();

    const report = engine.evaluateCompliance(graph, paths, ['SOC2', 'PCI-DSS']);

    expect(report.tenantId).toBe(tenantId);
    expect(report.frameworks).toContain('SOC2');
    expect(report.frameworks).toContain('PCI-DSS');

    // 1. Check partition: COVERED_WITH_FINDINGS
    const pciReq13 = report.controls.find((c) => c.controlId === 'PCI-Req-1.3');
    expect(pciReq13).toBeDefined();
    expect(pciReq13?.partition).toBe('COVERED_WITH_FINDINGS');
    expect(pciReq13?.violatingPathIds).toContain('path-pci-leak-01');

    const soc2CC66 = report.controls.find((c) => c.controlId === 'SOC2-CC6.6');
    expect(soc2CC66).toBeDefined();
    expect(soc2CC66?.partition).toBe('COVERED_WITH_FINDINGS');

    // 2. Check partition: NOT_OBSERVABLE_BY_TOOL
    const soc2Physical = report.controls.find((c) => c.controlId === 'SOC2-CC6.4');
    expect(soc2Physical).toBeDefined();
    expect(soc2Physical?.partition).toBe('NOT_OBSERVABLE_BY_TOOL');
    expect(soc2Physical?.observableByTool).toBe(false);

    const pciPhysical = report.controls.find((c) => c.controlId === 'PCI-Req-9.1');
    expect(pciPhysical).toBeDefined();
    expect(pciPhysical?.partition).toBe('NOT_OBSERVABLE_BY_TOOL');

    // 3. Check partition: COVERED_CLEAN
    const soc2Encryption = report.controls.find((c) => c.controlId === 'SOC2-CC6.7');
    expect(soc2Encryption).toBeDefined();
    expect(soc2Encryption?.partition).toBe('COVERED_CLEAN');
    expect(soc2Encryption?.violatingPathIds).toHaveLength(0);

    // Summary counts check
    expect(report.summary.coveredWithFindingsCount).toBeGreaterThan(0);
    expect(report.summary.coveredCleanCount).toBeGreaterThan(0);
    expect(report.summary.notObservableCount).toBeGreaterThan(0);
  });

  it('explicitly reports unmapped findings rather than silently omitting them', () => {
    const graph = buildGraph();
    const paths = [makeMockPath('path-001')];
    const engine = new ComplianceEngine();

    const report = engine.evaluateCompliance(graph, paths, ['SOC2']);

    expect(report.unmappedFindings.length).toBeGreaterThan(0);
    const unmapped = report.unmappedFindings.find((u) => u.findingId === 'finding-unmapped-002');
    expect(unmapped).toBeDefined();
    expect(unmapped?.category).toBe('UNRESOLVED_REFERENCE');
    expect(report.summary.unmappedFindingsCount).toBeGreaterThan(0);
  });

  it('formats markdown report visibly separating partitions without claiming an overall percentage', () => {
    const graph = buildGraph();
    const paths = [makeMockPath('path-001')];
    const engine = new ComplianceEngine();

    const report = engine.evaluateCompliance(graph, paths, ['SOC2', 'PCI-DSS']);
    const markdown = engine.formatMarkdownReport(report);

    expect(markdown).toContain('Architecture & Infrastructure Compliance Posture Report');
    expect(markdown).toContain('Covered — Currently Clean');
    expect(markdown).toContain('Covered — Open Findings');
    expect(markdown).toContain('Not Observable by This Tool');
    expect(markdown).toContain('Unmapped Scan Findings');
    expect(markdown).toContain('finding-unmapped-002');
    expect(markdown).toContain('DISCLAIMER');

    // Must NOT contain misleading overall percentage claim (e.g. "Overall Compliance: 85%")
    expect(markdown).not.toMatch(/Overall Compliance:\s*\d+%/i);
  });
});
