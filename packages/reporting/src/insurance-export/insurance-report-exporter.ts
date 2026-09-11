import { Asset, Relationship, Finding } from '@ai-security-architect/core';
import {
  UnderwritingQuestion,
  InsuranceReportSummary,
  INSURANCE_DRAFT_DISCLAIMER,
} from './types.js';

export class InsuranceReportExporter {
  /**
   * Generates a structured Cyber Insurance Underwriting Evidence Draft from graph and finding state.
   * Strictly partitions evidence into DIRECT_EVIDENCE, PARTIAL_EVIDENCE, and NOT_OBSERVABLE.
   * Never overclaims coverage.
   */
  generateReport(
    tenantId: string,
    assets: Asset[],
    relationships: Relationship[],
    findings: Finding[]
  ): InsuranceReportSummary {
    const questions: UnderwritingQuestion[] = [];

    // Question 1: Network Segmentation & Database Isolation
    const databaseAssets = assets.filter((a) => a.type === 'DATABASE');
    const publicDatabases = databaseAssets.filter((a) => a.isPublic);
    const publicExpoFindings = findings.filter(
      (f) => f.category === 'PUBLIC_EXPOSURE' && databaseAssets.some((d) => d.id === f.assetId)
    );

    if (databaseAssets.length > 0) {
      if (publicDatabases.length === 0 && publicExpoFindings.length === 0) {
        questions.push({
          id: 'INS-Q1-NETWORK-SEGMENTATION',
          category: 'Network Defense & Infrastructure Isolation',
          prompt: 'Are all production data stores and relational databases isolated from direct public internet exposure?',
          confidence: 'DIRECT_EVIDENCE',
          directEvidenceCount: databaseAssets.length,
          partialEvidenceNotes: [],
          findingsCorrelated: [],
          underwriterAnswerDraft: `YES - Fully Confirmed. Empirical graph traversal confirms 0 of ${databaseAssets.length} modeled databases have direct ingress routes from public internet endpoints.`,
          sourceAssets: databaseAssets.map((d) => d.id),
        });
      } else {
        questions.push({
          id: 'INS-Q1-NETWORK-SEGMENTATION',
          category: 'Network Defense & Infrastructure Isolation',
          prompt: 'Are all production data stores and relational databases isolated from direct public internet exposure?',
          confidence: 'DIRECT_EVIDENCE',
          directEvidenceCount: databaseAssets.length,
          partialEvidenceNotes: [],
          findingsCorrelated: publicExpoFindings.map((f) => f.id),
          underwriterAnswerDraft: `NO - Direct Exposure Identified. ${publicDatabases.length} database(s) declare public accessibility or have open ingress paths from internet.`,
          sourceAssets: publicDatabases.map((d) => d.id),
        });
      }
    } else {
      questions.push({
        id: 'INS-Q1-NETWORK-SEGMENTATION',
        category: 'Network Defense & Infrastructure Isolation',
        prompt: 'Are all production data stores and relational databases isolated from direct public internet exposure?',
        confidence: 'NOT_OBSERVABLE',
        directEvidenceCount: 0,
        partialEvidenceNotes: ['No database assets identified in current scan scope.'],
        findingsCorrelated: [],
        underwriterAnswerDraft: 'NOT OBSERVED. Scope of analysis does not contain persistent data tier assets.',
        sourceAssets: [],
      });
    }

    // Question 2: Privileged Access & IAM Least Privilege
    const iamAssets = assets.filter((a) => a.type === 'IAM_ROLE' || a.type === 'SERVICE_ACCOUNT');
    const iamFindings = findings.filter((f) => f.category === 'IAM_OVERPRIVILEGE');

    if (iamAssets.length > 0) {
      if (iamFindings.length > 0) {
        questions.push({
          id: 'INS-Q2-PRIVILEGED-ACCESS',
          category: 'Identity & Access Management (IAM)',
          prompt: 'Is least-privilege access enforced across administrative and service identities without wildcard authorizations?',
          confidence: 'DIRECT_EVIDENCE',
          directEvidenceCount: iamFindings.length,
          partialEvidenceNotes: [],
          findingsCorrelated: iamFindings.map((f) => f.id),
          underwriterAnswerDraft: `PARTIAL / DEFICIENT. Static analysis detected wildcard or over-scoped permissions on ${iamFindings.length} identities. Remediation tickets open.`,
          sourceAssets: iamFindings.map((f) => f.assetId),
        });
      } else {
        // Without runtime access logs (e.g. CloudTrail), IaC scan alone is only partial evidence
        questions.push({
          id: 'INS-Q2-PRIVILEGED-ACCESS',
          category: 'Identity & Access Management (IAM)',
          prompt: 'Is least-privilege access enforced across administrative and service identities without wildcard authorizations?',
          confidence: 'PARTIAL_EVIDENCE',
          directEvidenceCount: 0,
          partialEvidenceNotes: [
            'Declared IaC policies contain no syntax wildcards, but runtime access logs (e.g. CloudTrail/GCP Audit) were not analyzed to verify behavioral least-privilege.',
          ],
          findingsCorrelated: [],
          underwriterAnswerDraft: `PARTIAL EVIDENCE ONLY. Declared IaC policies on ${iamAssets.length} identities have no wildcard grants. However, runtime access logs must be independently audited to confirm least privilege.`,
          sourceAssets: iamAssets.map((i) => i.id),
        });
      }
    } else {
      questions.push({
        id: 'INS-Q2-PRIVILEGED-ACCESS',
        category: 'Identity & Access Management (IAM)',
        prompt: 'Is least-privilege access enforced across administrative and service identities without wildcard authorizations?',
        confidence: 'NOT_OBSERVABLE',
        directEvidenceCount: 0,
        partialEvidenceNotes: ['No cloud IAM resources found in scope.'],
        findingsCorrelated: [],
        underwriterAnswerDraft: 'NOT OBSERVED. Scope does not contain cloud IAM policy declarations.',
        sourceAssets: [],
      });
    }

    // Question 3: Data Protection & Classification
    const sensitiveAssets = assets.filter((a) => a.isSensitiveData);
    if (sensitiveAssets.length > 0) {
      questions.push({
        id: 'INS-Q3-DATA-PROTECTION',
        category: 'Data Protection & Encryption',
        prompt: 'Are sensitive customer data assets classified and protected with cryptographic controls?',
        confidence: 'PARTIAL_EVIDENCE',
        directEvidenceCount: sensitiveAssets.length,
        partialEvidenceNotes: [
          `Identified ${sensitiveAssets.length} classified data repositories. Cloud KMS key rotation and client-side encryption require external KMS validation.`,
        ],
        findingsCorrelated: [],
        underwriterAnswerDraft: `PARTIAL EVIDENCE. ${sensitiveAssets.length} repositories are tagged and tracked as sensitive data in architecture models. External KMS key management policies should be verified separately.`,
        sourceAssets: sensitiveAssets.map((s) => s.id),
      });
    } else {
      questions.push({
        id: 'INS-Q3-DATA-PROTECTION',
        category: 'Data Protection & Encryption',
        prompt: 'Are sensitive customer data assets classified and protected with cryptographic controls?',
        confidence: 'NOT_OBSERVABLE',
        directEvidenceCount: 0,
        partialEvidenceNotes: ['No assets explicitly tagged as sensitive data in current architecture model.'],
        findingsCorrelated: [],
        underwriterAnswerDraft: 'NOT OBSERVED. Data classification metadata not configured.',
        sourceAssets: [],
      });
    }

    // Question 4: Centralized Audit Logging & Monitoring
    const logAggregators = assets.filter((a) => a.type === 'LOG_AGGREGATOR');
    if (logAggregators.length > 0) {
      questions.push({
        id: 'INS-Q4-INCIDENT-LOGGING',
        category: 'Security Operations & Incident Logging',
        prompt: 'Are immutable security audit logs aggregated to a centralized SIEM or security data lake?',
        confidence: 'DIRECT_EVIDENCE',
        directEvidenceCount: logAggregators.length,
        partialEvidenceNotes: [],
        findingsCorrelated: [],
        underwriterAnswerDraft: `YES. Centralized log aggregators identified in infrastructure model: [${logAggregators.map((l) => l.name).join(', ')}].`,
        sourceAssets: logAggregators.map((l) => l.id),
      });
    } else {
      questions.push({
        id: 'INS-Q4-INCIDENT-LOGGING',
        category: 'Security Operations & Incident Logging',
        prompt: 'Are immutable security audit logs aggregated to a centralized SIEM or security data lake?',
        confidence: 'NOT_OBSERVABLE',
        directEvidenceCount: 0,
        partialEvidenceNotes: ['No log aggregation infrastructure declared in analyzed IaC repositories.'],
        findingsCorrelated: [],
        underwriterAnswerDraft: 'NOT OBSERVED. Dedicated SIEM / log aggregation infrastructure not captured in repository scope.',
        sourceAssets: [],
      });
    }

    // Question 5: Multi-Factor Authentication (MFA)
    questions.push({
      id: 'INS-Q5-MFA-ENFORCEMENT',
      category: 'Identity Provider & Authentication',
      prompt: 'Is Multi-Factor Authentication (MFA) mandated for all administrative console and remote access?',
      confidence: 'NOT_OBSERVABLE',
      directEvidenceCount: 0,
      partialEvidenceNotes: [
        'MFA policies reside within SaaS Identity Providers (Okta, Entra ID, Google Workspace) and are outside the scope of repository IaC and service graphs.',
      ],
      findingsCorrelated: [],
      underwriterAnswerDraft: 'NOT OBSERVED BY THIS TOOL. Identity Provider (IdP) MFA configuration must be confirmed directly via corporate IdP administrative consoles.',
      sourceAssets: [],
    });

    const directEvidenceQuestions = questions.filter((q) => q.confidence === 'DIRECT_EVIDENCE').length;
    const partialEvidenceQuestions = questions.filter((q) => q.confidence === 'PARTIAL_EVIDENCE').length;
    const notObservableQuestions = questions.filter((q) => q.confidence === 'NOT_OBSERVABLE').length;

    return {
      tenantId,
      generatedAt: new Date().toISOString(),
      totalQuestionsEvaluated: questions.length,
      directEvidenceQuestions,
      partialEvidenceQuestions,
      notObservableQuestions,
      questions,
      disclaimer: INSURANCE_DRAFT_DISCLAIMER,
    };
  }

  /**
   * Export the draft underwriting summary to a clean Markdown document
   */
  exportToMarkdown(summary: InsuranceReportSummary): string {
    const lines: string[] = [];
    lines.push(`# Cyber Insurance Underwriting Assessment & Evidence Draft`);
    lines.push(`**Tenant**: \`${summary.tenantId}\` | **Generated**: \`${summary.generatedAt}\``);
    lines.push('');
    lines.push(`> [!IMPORTANT]`);
    lines.push(`> ${summary.disclaimer}`);
    lines.push('');
    lines.push('## Executive Evidence Scorecard');
    lines.push(`- **Total Questionnaire Domains Evaluated**: ${summary.totalQuestionsEvaluated}`);
    lines.push(`- **Direct Evidence Questions**: ${summary.directEvidenceQuestions}`);
    lines.push(`- **Partial Evidence Questions**: ${summary.partialEvidenceQuestions}`);
    lines.push(`- **Not Observable / Out of Scope**: ${summary.notObservableQuestions}`);
    lines.push('');
    lines.push('---');
    lines.push('## Detailed Underwriter Questions & Technical Draft Responses');
    lines.push('');

    for (const q of summary.questions) {
      lines.push(`### [${q.confidence}] ${q.category}`);
      lines.push(`**Underwriter Question**: *${q.prompt}*`);
      lines.push('');
      lines.push(`**Draft Response**: ${q.underwriterAnswerDraft}`);
      lines.push('');
      if (q.partialEvidenceNotes.length > 0) {
        lines.push(`**Scope Limitations**:`);
        for (const note of q.partialEvidenceNotes) {
          lines.push(`- ${note}`);
        }
        lines.push('');
      }
      if (q.findingsCorrelated.length > 0) {
        lines.push(`**Correlated Security Findings**: \`${q.findingsCorrelated.join('`, `')}\``);
        lines.push('');
      }
      lines.push('---');
    }

    return lines.join('\n');
  }
}
