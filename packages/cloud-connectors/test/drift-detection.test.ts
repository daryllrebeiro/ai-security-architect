import { describe, it, expect } from 'vitest';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { Asset, CloudAsset } from '@ai-security-architect/core';
import { DriftDetector } from '../src/drift-detector.js';

describe('DriftDetector & diffCloudDrift', () => {
  it('detects shadow resources, configuration drift, and synthesizes security findings', () => {
    const tenantId = 'tenant-drift-test';

    // 1. Declared Graph (IaC)
    const declaredEngine = new SecurityGraphEngine(tenantId);
    const declaredRole: Asset = {
      id: 'app-role',
      tenantId,
      type: 'IAM_ROLE',
      name: 'app-role',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      source: 'declared-iac',
      metadata: {},
      tags: [],
    };
    const declaredBucket: Asset = {
      id: 'production-data-bucket',
      tenantId,
      type: 'BUCKET',
      name: 'production-data-bucket',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'HIGH',
      source: 'declared-iac',
      metadata: {},
      tags: [],
    };
    declaredEngine.addAsset(declaredRole);
    declaredEngine.addAsset(declaredBucket);

    // 2. Live Graph (AWS runtime)
    const liveEngine = new SecurityGraphEngine(tenantId);
    const liveRole: CloudAsset = {
      ...declaredRole,
      source: 'live-cloud',
      cloudProvider: 'AWS',
      cloudArnOrId: 'arn:aws:iam::123456789012:role/app-role',
      metadata: {},
    };
    const liveBucketWithDrift: CloudAsset = {
      ...declaredBucket,
      isPublic: true, // Configuration Drift!
      source: 'live-cloud',
      cloudProvider: 'AWS',
      cloudArnOrId: 'arn:aws:s3:::production-data-bucket',
      metadata: {},
    };
    const shadowVaultBucket: CloudAsset = {
      id: 'shadow-finance-vault',
      tenantId,
      type: 'BUCKET',
      name: 'shadow-finance-vault',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      source: 'live-cloud',
      cloudProvider: 'AWS',
      cloudArnOrId: 'arn:aws:s3:::shadow-finance-vault',
      metadata: {},
      tags: [],
    };

    liveEngine.addAsset(liveRole);
    liveEngine.addAsset(liveBucketWithDrift);
    liveEngine.addAsset(shadowVaultBucket);

    // 3. Detect Drift
    const detector = new DriftDetector();
    const { driftResult, findings } = detector.detectDrift(declaredEngine, liveEngine);

    // 4. Assertions on Drift Structure
    expect(driftResult.onlyInLive.length).toBe(1);
    expect(driftResult.onlyInLive[0].id).toBe('shadow-finance-vault');
    expect(driftResult.onlyInDeclared.length).toBe(0);

    expect(driftResult.configDrift.length).toBe(1);
    expect(driftResult.configDrift[0].assetId).toBe('production-data-bucket');
    expect(driftResult.configDrift[0].differences[0].property).toBe('isPublic');
    expect(driftResult.configDrift[0].differences[0].declaredValue).toBe(false);
    expect(driftResult.configDrift[0].differences[0].liveValue).toBe(true);

    // 5. Assertions on Synthesized Findings
    expect(findings.length).toBe(2);

    const shadowFinding = findings.find((f) => f.category === 'SHADOW_RESOURCE');
    expect(shadowFinding).toBeDefined();
    expect(shadowFinding?.severity).toBe('CRITICAL');
    expect(shadowFinding?.assetId).toBe('shadow-finance-vault');

    const configDriftFinding = findings.find((f) => f.category === 'CLOUD_DRIFT');
    expect(configDriftFinding).toBeDefined();
    expect(configDriftFinding?.severity).toBe('CRITICAL');
    expect(configDriftFinding?.title).toContain('Security Configuration Drift');

    // Verify findings were attached to liveEngine
    expect(liveEngine.getFindingsForNode('shadow-finance-vault').length).toBe(1);
    expect(liveEngine.getFindingsForNode('production-data-bucket').length).toBe(1);
  });
});
