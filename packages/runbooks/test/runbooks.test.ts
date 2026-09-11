import { describe, it, expect } from 'vitest';
import type { Asset, AttackPath } from '@ai-security-architect/core';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import { RunbookGenerator } from '../src/runbook-generator.js';

describe('Task B.4 — Guided Remediation Playbooks / Runbooks Generator', () => {
  const tenantId = 'tenant-runbook-test';

  function buildGraph(): SecurityGraphEngine {
    const graph = new SecurityGraphEngine(tenantId);

    const pod: Asset = {
      id: 'asset-pod',
      tenantId,
      type: 'POD',
      name: 'payment-processor-pod',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    const role: Asset = {
      id: 'asset-role',
      tenantId,
      type: 'IAM_ROLE',
      name: 'payment-vault-role',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'CRITICAL',
      metadata: {},
      tags: [],
    };

    const bucket: Asset = {
      id: 'asset-bucket',
      tenantId,
      type: 'BUCKET',
      name: 'customer-vault-storage',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      metadata: {},
      tags: ['contains-pii'],
    };

    graph.addAsset(pod);
    graph.addAsset(role);
    graph.addAsset(bucket);

    return graph;
  }

  function makeMockPath(): AttackPath {
    return {
      id: 'path-role-abuse-01',
      tenantId,
      entryAssetId: 'asset-pod',
      targetAssetId: 'asset-bucket',
      pathLength: 2,
      steps: [
        {
          stepNumber: 1,
          sourceAssetId: 'asset-pod',
          targetAssetId: 'asset-role',
          relationshipType: 'ASSUMES_ROLE',
          explanation: 'pod assumes payment vault role',
        },
        {
          stepNumber: 2,
          sourceAssetId: 'asset-role',
          targetAssetId: 'asset-bucket',
          relationshipType: 'CAN_READ',
          explanation: 'role reads customer vault storage',
        },
      ],
      recommendedChokePoint: {
        edgeId: 'edge-1',
        sourceAssetId: 'asset-pod',
        targetAssetId: 'asset-role',
        relationshipType: 'ASSUMES_ROLE',
        actionDescription: 'Sever assume-role relationship',
        pathsEliminatedCount: 1,
        riskReductionPercentage: 100,
        engineeringEffort: 'LOW',
        blastRadius: 'LOW',
      },
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

  it('generates structured remediation runbook with pre-flight checks, IaC patch, rollback, and verification', () => {
    const graph = buildGraph();
    const path = makeMockPath();
    const generator = new RunbookGenerator();

    const playbook = generator.generatePlaybook(path, graph);

    expect(playbook.id).toBe('playbook-path-role-abuse-01');
    expect(playbook.severity).toBe('CRITICAL');
    expect(playbook.chokePoint.sourceAssetName).toBe('payment-processor-pod');
    expect(playbook.chokePoint.targetAssetName).toBe('payment-vault-role');
    expect(playbook.chokePoint.relationshipType).toBe('ASSUMES_ROLE');

    // Pre-flight checks
    expect(playbook.preFlightChecks.some((c) => c.includes('git status'))).toBe(true);

    // Execution steps
    expect(playbook.executionSteps.length).toBe(2);
    expect(playbook.executionSteps[0].actionType).toBe('IAC_PATCH');
    expect(playbook.executionSteps[0].commandOrSnippet).toContain('aws_iam_policy_document');
    expect(playbook.executionSteps[1].commandOrSnippet).toContain('terraform apply');

    // Rollback and verification
    expect(playbook.rollbackSteps.some((r) => r.includes('git checkout'))).toBe(true);
    expect(playbook.postVerificationQuery).toContain('sec-arch scan --verify-closed');
  });

  it('formats clean markdown runbook with syntax highlighted code blocks', () => {
    const graph = buildGraph();
    const path = makeMockPath();
    const generator = new RunbookGenerator();

    const playbook = generator.generatePlaybook(path, graph);
    const markdown = generator.formatMarkdown(playbook);

    expect(markdown).toContain('# Remediation Runbook for Attack Path path-role-abuse-01');
    expect(markdown).toContain('## 1. Pre-Flight Verification Checks');
    expect(markdown).toContain('## 2. Step-by-Step Remediation Execution');
    expect(markdown).toContain('## 3. Rollback Procedure');
    expect(markdown).toContain('## 4. Post-Remediation Verification Checklist');
    expect(markdown).toContain('```hcl');
    expect(markdown).toContain('```bash');
  });

  it('classifies direct/low-effort paths as auto-patchable and multi-hop paths as requires-runbook', () => {
    const generator = new RunbookGenerator();
    const shortPath = makeMockPath(); // length 2, low effort choke point

    const complexPath: AttackPath = {
      id: 'path-complex-01',
      tenantId,
      entryAssetId: 'asset-internet',
      targetAssetId: 'asset-bucket',
      pathLength: 5,
      steps: [],
      riskScore: {
        impact: 9.0,
        exploitability: 8.0,
        reachability: 1.0,
        assetCriticality: 9.0,
        confidence: 1.0,
        totalRisk: 8.5,
      },
      verifiedEliminated: false,
    };

    expect(generator.classifyPath(shortPath)).toBe('auto-patchable');
    expect(generator.classifyPath(complexPath)).toBe('requires-runbook');

    const summary = generator.classifyPaths([shortPath, complexPath]);
    expect(summary.autoPatchable).toEqual(['path-role-abuse-01']);
    expect(summary.requiresRunbook).toEqual(['path-complex-01']);
  });

  it('assigns owning team and generates Confluence wiki formatted markup', () => {
    const graph = buildGraph();
    const path = makeMockPath();
    const generator = new RunbookGenerator();

    const playbook = generator.generatePlaybook(path, graph);
    expect(playbook.owningTeam).toBe('IAM Administration / Platform Security');
    expect(playbook.verificationChecklist.length).toBeGreaterThan(0);
    expect(playbook.verificationChecklist[0].fingerprint).toBeDefined();

    const confluence = generator.formatConfluence(playbook);
    expect(confluence).toContain('h1. Remediation Runbook for Attack Path path-role-abuse-01');
    expect(confluence).toContain('{panel:title=Notice|borderColor=#d29922|bgColor=#fff8e5}');
    expect(confluence).toContain('h2. 1. Pre-Flight Verification Checks');
    expect(confluence).toContain('{code:bash}');
    expect(confluence).toContain('h2. 4. Post-Remediation Verification Checklist');
  });
});
