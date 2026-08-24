import { describe, it, expect } from 'vitest';
import {
  AssetSchema,
  RelationshipSchema,
  FindingSchema,
  EvidenceSchema,
  createEvidence,
  AttackPathSchema,
  calculateRiskScore,
  AIContextHandoffSchema,
  AIReasoningOutputSchema,
} from '../src/index.js';

describe('Canonical Domain Contracts', () => {
  const tenantId = 'tenant-enterprise-01';

  it('validates a valid Asset model', () => {
    const validAsset = {
      id: 'asset-order-svc',
      tenantId,
      type: 'SERVICE',
      name: 'order-service',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: { language: 'java', framework: 'spring-boot' },
      tags: ['pci-scope'],
    };

    const parsed = AssetSchema.parse(validAsset);
    expect(parsed.name).toBe('order-service');
    expect(parsed.type).toBe('SERVICE');
  });

  it('validates a valid Relationship with directionality', () => {
    const validRel = {
      id: 'rel-01',
      tenantId,
      sourceAssetId: 'asset-alb',
      targetAssetId: 'asset-order-svc',
      type: 'ROUTES_TO',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: { port: 8080 },
    };

    const parsed = RelationshipSchema.parse(validRel);
    expect(parsed.type).toBe('ROUTES_TO');
    expect(parsed.nature).toBe('DECLARED');
  });

  it('creates and validates immutable cryptographic Evidence', () => {
    const evidence = createEvidence({
      id: 'ev-01',
      tenantId,
      sourceType: 'TERRAFORM',
      repository: 'enterprise/infrastructure',
      filePath: 'terraform/iam.tf',
      lineStart: 18,
      lineEnd: 28,
      snippet: 'Action = ["s3:*"]\nResource = "*"',
      scanner: 'Checkov',
    });

    const parsed = EvidenceSchema.parse(evidence);
    expect(parsed.snippetSha256).toHaveLength(64);
    expect(parsed.filePath).toBe('terraform/iam.tf');
  });

  it('validates a canonical Finding linked to Asset and Evidence', () => {
    const evidence = createEvidence({
      id: 'ev-02',
      tenantId,
      sourceType: 'SOURCE_CODE',
      repository: 'enterprise/order-service',
      filePath: 'OrderController.java',
      lineStart: 25,
      lineEnd: 32,
      snippet: 'URL url = new URL(callbackUrl);',
      scanner: 'Semgrep',
    });

    const finding = {
      id: 'finding-ssrf-01',
      tenantId,
      assetId: 'asset-order-endpoint',
      category: 'SSRF',
      ruleId: 'JAVA-SSRF-URL-CONNECTION',
      title: 'Server-Side Request Forgery via Unvalidated Callback URL',
      description: 'Unvalidated user input passed directly to HttpURLConnection',
      severity: 'HIGH',
      confidence: 'HIGH',
      scanner: 'Semgrep',
      cwe: 'CWE-918',
      evidence,
      remediationRecommendation: 'Validate and allowlist destination hostnames before opening connections.',
      metadata: {},
    };

    const parsed = FindingSchema.parse(finding);
    expect(parsed.category).toBe('SSRF');
    expect(parsed.evidence.snippetSha256).toBeDefined();
  });

  it('computes explainable risk score and validates Attack Path model', () => {
    const risk = calculateRiskScore({
      impact: 9.5,
      exploitability: 8.5,
      reachability: 1.0,
      assetCriticality: 10.0,
      confidence: 0.95,
    });

    expect(risk.totalRisk).toBeGreaterThanOrEqual(8.0);
    expect(risk.totalRisk).toBeLessThanOrEqual(10.0);

    const attackPath = {
      id: 'path-01',
      tenantId,
      entryAssetId: 'asset-internet',
      targetAssetId: 'asset-s3-pii',
      pathLength: 4,
      steps: [
        {
          stepNumber: 1,
          sourceAssetId: 'asset-internet',
          targetAssetId: 'asset-alb',
          relationshipType: 'EXPOSES_HTTP',
          explanation: 'Internet traffic reaches public Application Load Balancer',
        },
        {
          stepNumber: 2,
          sourceAssetId: 'asset-alb',
          targetAssetId: 'asset-order-svc',
          relationshipType: 'ROUTES_TO',
          explanation: 'ALB forwards traffic to Order Service',
        },
        {
          stepNumber: 3,
          sourceAssetId: 'asset-order-svc',
          targetAssetId: 'asset-iam-role',
          relationshipType: 'ASSUMES_ROLE',
          findingId: 'finding-ssrf-01',
          explanation: 'SSRF vulnerability allows pod to query IMDS and assume IAM role',
        },
        {
          stepNumber: 4,
          sourceAssetId: 'asset-iam-role',
          targetAssetId: 'asset-s3-pii',
          relationshipType: 'CAN_READ',
          explanation: 'IAM role policy permits wildcard s3:* access to customer PII bucket',
        },
      ],
      riskScore: risk,
      recommendedChokePoint: {
        edgeId: 'rel-iam-s3',
        sourceAssetId: 'asset-iam-role',
        targetAssetId: 'asset-s3-pii',
        relationshipType: 'CAN_READ',
        actionDescription: 'Restrict IAM role policy to least-privilege specific bucket ARNs',
        pathsEliminatedCount: 1,
        riskReductionPercentage: 90,
        engineeringEffort: 'LOW',
        blastRadius: 'LOW',
      },
      verifiedEliminated: false,
    };

    const parsed = AttackPathSchema.parse(attackPath);
    expect(parsed.steps).toHaveLength(4);
    expect(parsed.recommendedChokePoint?.riskReductionPercentage).toBe(90);
  });

  it('validates AI Handoff and Structured Reasoning Output schemas', () => {
    const risk = calculateRiskScore({
      impact: 9.0,
      exploitability: 8.0,
      reachability: 1.0,
      assetCriticality: 9.5,
      confidence: 0.9,
    });

    const handoff = {
      attackPathId: 'path-01',
      deterministicMetrics: {
        entryNode: 'asset-internet',
        targetNode: 'asset-s3-pii',
        pathLength: 2,
        calculatedRiskScore: risk.totalRisk,
        riskBreakdown: risk,
        optimalChokePointEdge: {
          source: 'asset-iam-role',
          relationship: 'CAN_READ',
          target: 'asset-s3-pii',
        },
      },
      graphChain: [
        {
          stepNumber: 1,
          sourceAssetId: 'asset-internet',
          targetAssetId: 'asset-order-svc',
          relationshipType: 'EXPOSES_HTTP',
          explanation: 'Public ingress',
        },
        {
          stepNumber: 2,
          sourceAssetId: 'asset-order-svc',
          targetAssetId: 'asset-s3-pii',
          relationshipType: 'CAN_READ',
          explanation: 'IAM Access',
        },
      ],
      evidenceReferences: [
        {
          evidenceId: 'ev-01',
          sourceType: 'TERRAFORM',
          repository: 'enterprise/infra',
          filePath: 'terraform/iam.tf',
          lineRange: '18-28',
          snippet: 'Action = ["s3:*"]',
        },
      ],
      findingsSummary: [
        {
          findingId: 'finding-01',
          category: 'IAM_OVERPRIVILEGE',
          title: 'Wildcard S3 access',
          severity: 'CRITICAL',
          ruleId: 'CKV_AWS_1',
        },
      ],
    };

    const parsedHandoff = AIContextHandoffSchema.parse(handoff);
    expect(parsedHandoff.attackPathId).toBe('path-01');

    const aiOutput = {
      summary: 'Publicly reachable SSRF chain leading to full read access on Customer PII S3 bucket.',
      rootCauseAnalysis:
        'The order-service exposes an unauthenticated webhook endpoint that issues arbitrary HTTP requests without IP sanitization. Combined with an overprivileged EKS IAM role having s3:* wildcard access, an attacker can access customer PII.',
      businessImpact: 'Total confidentiality breach of customer PII, leading to regulatory and GDPR exposure.',
      evidenceReferences: ['ev-01'],
      recommendedRemediation: {
        description: 'Constrain the IAM policy in terraform/iam.tf to only allow read operations on necessary buckets.',
        targetChokePoint: 'asset-iam-role -> asset-s3-pii',
        expectedRiskReductionPercentage: 92,
        engineeringEffort: 'LOW',
        patches: [
          {
            filePath: 'terraform/iam.tf',
            action: 'MODIFY',
            diff: '- Action = "s3:*"\n+ Action = ["s3:GetObject", "s3:ListBucket"]',
            description: 'Replace wildcard action with specific read permissions',
          },
        ],
      },
      alternativeRemediations: [
        {
          description: 'Enable IMDSv2 with hop limit = 1 on EKS nodes',
          tradeoff: 'Blocks SSRF token exfiltration but leaves IAM policy overprivileged if compromised via other means.',
        },
      ],
      confidence: 'HIGH',
    };

    const parsedOutput = AIReasoningOutputSchema.parse(aiOutput);
    expect(parsedOutput.confidence).toBe('HIGH');
    expect(parsedOutput.recommendedRemediation.patches).toHaveLength(1);
  });
});
