import { describe, it, expect } from 'vitest';
import { Asset, Finding, createEvidence } from '@ai-security-architect/core';
import { DueDiligenceEngine } from '../src/index.js';

describe('Task I.3: M&A / Due Diligence Assessment Mode', () => {
  const engine = new DueDiligenceEngine();

  const assets: Asset[] = [
    {
      id: 'asset-db-targetcorp-customers',
      tenantId: 'target-tenant',
      type: 'DATABASE',
      name: 'targetcorp-customer-rds',
      environment: 'production',
      isPublic: true,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      tags: ['pii'],
      metadata: {},
    },
    {
      id: 'asset-svc-targetcorp-auth',
      tenantId: 'target-tenant',
      type: 'SERVICE',
      name: 'targetcorp-auth-service',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      tags: [],
      metadata: {},
    },
  ];

  const findings: Finding[] = [
    {
      id: 'finding-001',
      tenantId: 'target-tenant',
      assetId: 'asset-db-targetcorp-customers',
      category: 'PUBLIC_EXPOSURE',
      ruleId: 'DUE-DIL-001',
      title: 'Direct public internet exposure of targetcorp-customer-rds',
      description: 'Customer database is accessible from 0.0.0.0/0.',
      severity: 'CRITICAL',
      confidence: 'CERTAIN',
      scanner: 'static-analyzer',
      evidence: createEvidence({
        id: 'ev-1',
        tenantId: 'target-tenant',
        sourceType: 'TERRAFORM',
        repository: 'targetcorp/infrastructure',
        filePath: 'main.tf',
        lineStart: 10,
        lineEnd: 15,
        snippet: 'cidr_blocks = ["0.0.0.0/0"]',
        scanner: 'static-analyzer',
      }),
      metadata: {},
    },
  ];

  const attackPathCount = 2;

  it('generates consistent unredacted and anonymized reports differing only in redaction, never in metrics', () => {
    // 1. Generate unredacted report for technical deal team
    const unredacted = engine.generateAssessment(assets, findings, attackPathCount, {
      targetCompanyName: 'TargetCorp Technologies',
      anonymize: false,
    });

    // 2. Generate anonymized report for wide deal room
    const anonymized = engine.generateAssessment(assets, findings, attackPathCount, {
      targetCompanyName: 'TargetCorp Technologies',
      anonymize: true,
    });

    // Check Metrics Consistency Guarantee
    expect(anonymized.metrics).toEqual(unredacted.metrics);
    expect(anonymized.metrics.dealRiskRating).toBe('HIGH');
    expect(anonymized.metrics.criticalCount).toBe(1);
    expect(anonymized.metrics.attackPathsCount).toBe(2);
    expect(anonymized.metrics.estimatedRemediationLiabilityUsd).toBe(unredacted.metrics.estimatedRemediationLiabilityUsd);

    // Assert Unredacted Content Retains Real Identifiers
    expect(unredacted.targetIdentifier).toBe('TargetCorp Technologies');
    expect(unredacted.isAnonymized).toBe(false);
    expect(unredacted.executiveSummary).toContain('TargetCorp Technologies');
    expect(unredacted.technicalAppendix).toContain('targetcorp-customer-rds');
    expect(unredacted.technicalAppendix).toContain('asset-db-targetcorp-customers');

    // Assert Anonymized Content Sanitizes Sensitive Identifiers
    expect(anonymized.targetIdentifier).toContain('PROJECT_ACQUISITION_TARGET');
    expect(anonymized.isAnonymized).toBe(true);
    expect(anonymized.executiveSummary.includes('TargetCorp')).toBe(false);
    expect(anonymized.technicalAppendix.includes('targetcorp-customer-rds')).toBe(false);
    expect(anonymized.technicalAppendix.includes('asset-db-targetcorp-customers')).toBe(false);

    // Anonymized tokens are present
    expect(anonymized.technicalAppendix).toContain('TARGET_ASSET_');
  });
});
