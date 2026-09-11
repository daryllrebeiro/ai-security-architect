import { describe, it, expect } from 'vitest';
import { Asset, Relationship, Finding } from '@ai-security-architect/core';
import {
  InsuranceReportExporter,
  INSURANCE_DRAFT_DISCLAIMER,
} from '../src/insurance-export/index.js';

describe('Task I.1: Cyber Insurance Underwriting Report Export', () => {
  const exporter = new InsuranceReportExporter();

  it('correctly partitions questionnaire into direct, partial, and not-observable evidence without overstating coverage', () => {
    const assets: Asset[] = [
      {
        id: 'asset-db-postgres',
        tenantId: 'tenant-1',
        type: 'DATABASE',
        name: 'production-postgres',
        environment: 'production',
        isPublic: false,
        isSensitiveData: true,
        criticality: 'HIGH',
        tags: ['pii'],
        metadata: {},
      },
      {
        id: 'asset-iam-role',
        tenantId: 'tenant-1',
        type: 'IAM_ROLE',
        name: 'backend-service-role',
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        tags: [],
        metadata: {},
      },
    ];

    const relationships: Relationship[] = [];
    const findings: Finding[] = [];

    const summary = exporter.generateReport('tenant-1', assets, relationships, findings);

    // Assert total questions evaluated
    expect(summary.totalQuestionsEvaluated).toBe(5);
    expect(summary.disclaimer).toBe(INSURANCE_DRAFT_DISCLAIMER);

    // 1. Network Segmentation / DB Isolation -> DIRECT_EVIDENCE (database is modeled, 0 public paths)
    const netQ = summary.questions.find((q) => q.id === 'INS-Q1-NETWORK-SEGMENTATION')!;
    expect(netQ).toBeDefined();
    expect(netQ.confidence).toBe('DIRECT_EVIDENCE');
    expect(netQ.underwriterAnswerDraft).toContain('YES - Fully Confirmed');

    // 2. IAM Least Privilege without access logs -> PARTIAL_EVIDENCE (never overstated as direct proof)
    const iamQ = summary.questions.find((q) => q.id === 'INS-Q2-PRIVILEGED-ACCESS')!;
    expect(iamQ).toBeDefined();
    expect(iamQ.confidence).toBe('PARTIAL_EVIDENCE');
    expect(iamQ.underwriterAnswerDraft).toContain('PARTIAL EVIDENCE ONLY');

    // 3. Sensitive Data Protection -> PARTIAL_EVIDENCE
    const dataQ = summary.questions.find((q) => q.id === 'INS-Q3-DATA-PROTECTION')!;
    expect(dataQ).toBeDefined();
    expect(dataQ.confidence).toBe('PARTIAL_EVIDENCE');

    // 4. Incident Logging -> NOT_OBSERVABLE (no log aggregator in scope)
    const logQ = summary.questions.find((q) => q.id === 'INS-Q4-INCIDENT-LOGGING')!;
    expect(logQ).toBeDefined();
    expect(logQ.confidence).toBe('NOT_OBSERVABLE');

    // 5. MFA Enforcement -> NOT_OBSERVABLE (IdP policy out of scope)
    const mfaQ = summary.questions.find((q) => q.id === 'INS-Q5-MFA-ENFORCEMENT')!;
    expect(mfaQ).toBeDefined();
    expect(mfaQ.confidence).toBe('NOT_OBSERVABLE');
    expect(mfaQ.underwriterAnswerDraft).toContain('NOT OBSERVED BY THIS TOOL');

    // Check counts
    expect(summary.directEvidenceQuestions).toBe(1);
    expect(summary.partialEvidenceQuestions).toBe(2);
    expect(summary.notObservableQuestions).toBe(2);

    // Markdown export includes disclaimer
    const md = exporter.exportToMarkdown(summary);
    expect(md).toContain(INSURANCE_DRAFT_DISCLAIMER);
    expect(md).toContain('## Executive Evidence Scorecard');
  });
});
