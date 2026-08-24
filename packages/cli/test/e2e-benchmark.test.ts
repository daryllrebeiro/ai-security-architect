import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { executeScan, executeRemediate } from '../src/index.js';

describe('Phase 12 - Comprehensive End-to-End Enterprise Benchmark Suite', () => {
  it('Benchmark Scenario 001: Microservice SSRF -> IMDS -> IAM Wildcard -> S3 PII Exfiltration', async () => {
    const fixturePath = path.resolve('fixtures/001-ssrf-iam-s3');

    // 1. Discovery & Attack Path Traversal
    const scanResult = await executeScan({
      path: fixturePath,
      tenantId: 'tenant-bench-001',
    });

    expect(scanResult.attackPaths.length).toBeGreaterThanOrEqual(1);
    expect(scanResult.highestRiskScore).toBeGreaterThanOrEqual(8.5);

    const primaryPath = scanResult.attackPaths[0];
    expect(primaryPath.entryAssetId).toBe('asset-internet');
    expect(primaryPath.targetAssetId).toContain('customer-pii');

    // 2. Closed-Loop Remediation Verification
    const prPayload = await executeRemediate({
      path: fixturePath,
      pathId: primaryPath.id,
      tenantId: 'tenant-bench-001',
    });

    expect(prPayload.verification.verified).toBe(true);
    expect(prPayload.verification.riskReductionPercentage).toBe(100);
    expect(prPayload.verification.postRemediationRiskScore).toBe(0.0);
  });

  it('Benchmark Scenario 002: Kubernetes Ingress -> Overprivileged IAM Role -> Financial Vault S3', async () => {
    const fixturePath = path.resolve('fixtures/002-k8s-rbac-secrets');

    const scanResult = await executeScan({
      path: fixturePath,
      tenantId: 'tenant-bench-002',
    });

    expect(scanResult.totalAssets).toBeGreaterThanOrEqual(4);
    expect(scanResult.attackPaths.length).toBeGreaterThanOrEqual(1);

    const primaryPath = scanResult.attackPaths[0];
    expect(primaryPath.targetAssetId).toContain('financial-vault');
    expect(primaryPath.recommendedChokePoint).toBeDefined();
  });

  it('Benchmark Scenario 003: CI/CD Pipeline -> Hardcoded Cloud Secrets -> Production Release S3', async () => {
    const fixturePath = path.resolve('fixtures/003-cicd-supply-chain');

    const scanResult = await executeScan({
      path: fixturePath,
      tenantId: 'tenant-bench-003',
    });

    // Detects hardcoded AWS keys in workflow
    const secretFinding = scanResult.findings.find((f) => f.category === 'SECRET_EXPOSURE');
    expect(secretFinding).toBeDefined();
    expect(secretFinding?.ruleId).toBe('SECRET-AWS-ACCESS-KEY');

    // Detects overprivileged IAM policy
    const iamFinding = scanResult.findings.find((f) => f.category === 'IAM_OVERPRIVILEGE');
    expect(iamFinding).toBeDefined();
  });
});
