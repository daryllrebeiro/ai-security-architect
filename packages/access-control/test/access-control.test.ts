import { describe, expect, it } from 'vitest';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import { createEvidence, type Asset, type AttackPath, type AttackStep } from '@ai-security-architect/core';
import { PartialDisclosurePolicy } from '../src/partial-disclosure.js';
import { ScopedGraphView } from '../src/scoped-graph-view.js';
import type { UserScope } from '../src/types.js';

describe('Multi-Tenant RBAC & Partial Disclosure Scoped Graph View', () => {
  function setupMultiTeamGraph(): {
    graph: SecurityGraphEngine;
    teamAAsset: Asset;
    teamBAsset: Asset;
    sharedDb: Asset;
  } {
    const graph = new SecurityGraphEngine('tenant-corp', { backend: 'memory' });

    const teamAAsset: Asset = {
      id: 'asset-team-a-api',
      tenantId: 'tenant-corp',
      name: 'Team A API Service',
      type: 'SERVICE',
      environment: 'PRODUCTION',
      criticality: 'HIGH',
      isPublic: false,
      isSensitiveData: false,
      tags: ['team:team-a'],
      metadata: { team: 'team-a' },
    };

    const teamBAsset: Asset = {
      id: 'asset-team-b-ingress',
      tenantId: 'tenant-corp',
      name: 'Team B Ingress Proxy',
      type: 'LOAD_BALANCER',
      environment: 'PRODUCTION',
      criticality: 'HIGH',
      isPublic: true,
      isSensitiveData: false,
      tags: ['team:team-b'],
      metadata: { team: 'team-b' },
    };

    const sharedDb: Asset = {
      id: 'asset-team-a-db',
      tenantId: 'tenant-corp',
      name: 'Team A Customer DB',
      type: 'DATABASE',
      environment: 'PRODUCTION',
      criticality: 'CRITICAL',
      isPublic: false,
      isSensitiveData: true,
      tags: ['team:team-a'],
      metadata: { team: 'team-a' },
    };

    graph.addAsset(teamAAsset);
    graph.addAsset(teamBAsset);
    graph.addAsset(sharedDb);

    const ev1 = createEvidence({
      id: 'ev-team-b',
      tenantId: 'tenant-corp',
      sourceType: 'KUBERNETES',
      repository: 'infra/k8s',
      filePath: 'ingress.yaml',
      lineStart: 1,
      lineEnd: 10,
      snippet: 'image: vulnerable-proxy:v1',
      scanner: 'trivy',
    });

    const ev2 = createEvidence({
      id: 'ev-team-a',
      tenantId: 'tenant-corp',
      sourceType: 'SOURCE_CODE',
      repository: 'team-a/api',
      filePath: 'src/auth.ts',
      lineStart: 42,
      lineEnd: 55,
      snippet: 'jwt.verify(token, null)',
      scanner: 'semgrep',
    });

    graph.attachFinding({
      id: 'finding-team-b-rce',
      tenantId: 'tenant-corp',
      assetId: 'asset-team-b-ingress',
      category: 'SUPPLY_CHAIN_INTEGRITY',
      ruleId: 'RULE-RCE-01',
      title: 'Ingress proxy vulnerable to RCE',
      description: 'Ingress proxy contains remote code execution vulnerability',
      severity: 'HIGH',
      confidence: 'HIGH',
      scanner: 'trivy',
      evidence: ev1,
      metadata: {},
    });

    graph.attachFinding({
      id: 'finding-team-a-misconfig',
      tenantId: 'tenant-corp',
      assetId: 'asset-team-a-api',
      category: 'DATA_LINEAGE_EXPOSURE',
      ruleId: 'RULE-AUTH-02',
      title: 'Misconfigured JWT validation',
      description: 'JWT verification missing key check',
      severity: 'MEDIUM',
      confidence: 'CERTAIN',
      scanner: 'semgrep',
      evidence: ev2,
      metadata: {},
    });

    return { graph, teamAAsset, teamBAsset, sharedDb };
  }

  it('restricts asset and finding queries to the assigned team scope', () => {
    const { graph } = setupMultiTeamGraph();

    const teamAScope: UserScope = {
      userId: 'user-alice',
      tenantId: 'tenant-corp',
      role: 'ENGINEER',
      allowedTeams: ['team-a'],
      allowedEnvironments: ['PRODUCTION'],
    };

    const scopedView = new ScopedGraphView(graph, teamAScope);

    // Can see Team A assets
    expect(scopedView.getNode('asset-team-a-api')).toBeDefined();
    expect(scopedView.getNode('asset-team-a-db')).toBeDefined();

    // Cannot see Team B internal assets
    expect(scopedView.getNode('asset-team-b-ingress')).toBeUndefined();

    // Only 2 of the 3 nodes returned
    const visibleNodes = scopedView.getAllNodes();
    expect(visibleNodes.length).toBe(2);
    expect(visibleNodes.some((n) => n.asset.id === 'asset-team-b-ingress')).toBe(false);

    // Finding on Team B asset is hidden from Alice
    const visibleFindings = scopedView.getAllFindings();
    expect(visibleFindings.length).toBe(1);
    expect(visibleFindings[0].id).toBe('finding-team-a-misconfig');
  });

  it('applies partial disclosure to cross-boundary attack paths without leaking external internals', () => {
    const { graph } = setupMultiTeamGraph();

    const teamAScope: UserScope = {
      userId: 'user-alice',
      tenantId: 'tenant-corp',
      role: 'ENGINEER',
      allowedTeams: ['team-a'],
    };

    const crossBoundarySteps: AttackStep[] = [
      {
        stepNumber: 1,
        sourceAssetId: 'asset-team-b-ingress',
        targetAssetId: 'asset-team-a-api',
        relationshipType: 'ROUTES_TO',
        findingId: 'finding-team-b-rce',
        explanation: 'Attacker leverages Team B Ingress RCE to pivot into Team A API',
      },
      {
        stepNumber: 2,
        sourceAssetId: 'asset-team-a-api',
        targetAssetId: 'asset-team-a-db',
        relationshipType: 'CAN_READ',
        findingId: 'finding-team-a-misconfig',
        explanation: 'Team A API reads from sensitive customer DB',
      },
    ];

    const crossBoundaryPath: AttackPath = {
      id: 'path-cross-boundary-01',
      tenantId: 'tenant-corp',
      entryAssetId: 'asset-team-b-ingress',
      targetAssetId: 'asset-team-a-db',
      pathLength: 2,
      steps: crossBoundarySteps,
      riskScore: {
        impact: 9.0,
        exploitability: 8.0,
        reachability: 1.0,
        assetCriticality: 9.5,
        confidence: 0.9,
        totalRisk: 8.8,
      },
      verifiedEliminated: false,
    };

    const scopedView = new ScopedGraphView(graph, teamAScope);
    const visiblePaths = scopedView.getAttackPaths([crossBoundaryPath]);

    expect(visiblePaths.length).toBe(1);
    const sanitizedPath = visiblePaths[0];

    // External entrypoint masked
    expect(sanitizedPath.entryAssetId).toBe('[REDACTED_CROSS_BOUNDARY_ENTRY]');
    expect(sanitizedPath.targetAssetId).toBe('asset-team-a-db');

    // Step 1 was across boundary from Team B -> Team A
    const step1 = sanitizedPath.steps[0];
    expect(step1.isCrossBoundaryRedacted).toBe(true);
    expect(step1.sourceAssetId).toBe('[REDACTED_CROSS_BOUNDARY_ASSET]');
    expect(step1.targetAssetId).toBe('asset-team-a-api'); // Team A can see their own asset as target
    expect(step1.findingId).toBeUndefined(); // Team B vulnerability details hidden
    expect(step1.explanation).toContain('[CROSS_BOUNDARY_REDACTED]');

    // Step 2 is purely internal to Team A -> full disclosure
    const step2 = sanitizedPath.steps[1];
    expect(step2.isCrossBoundaryRedacted).toBeUndefined();
    expect(step2.sourceAssetId).toBe('asset-team-a-api');
    expect(step2.targetAssetId).toBe('asset-team-a-db');
    expect(step2.findingId).toBe('finding-team-a-misconfig');
  });

  it('completely suppresses attack paths that do not touch the user scope', () => {
    const { graph } = setupMultiTeamGraph();

    const teamAScope: UserScope = {
      userId: 'user-alice',
      tenantId: 'tenant-corp',
      role: 'ENGINEER',
      allowedTeams: ['team-a'],
    };

    const externalOnlyPath: AttackPath = {
      id: 'path-team-b-isolated',
      tenantId: 'tenant-corp',
      entryAssetId: 'asset-team-b-ingress',
      targetAssetId: 'asset-team-b-ingress',
      pathLength: 1,
      steps: [
        {
          stepNumber: 1,
          sourceAssetId: 'asset-team-b-ingress',
          targetAssetId: 'asset-team-b-ingress',
          relationshipType: 'CALLS',
          explanation: 'Self loop',
        },
      ],
      riskScore: {
        impact: 5.0,
        exploitability: 5.0,
        reachability: 1.0,
        assetCriticality: 5.0,
        confidence: 0.8,
        totalRisk: 5.0,
      },
      verifiedEliminated: false,
    };

    const scopedView = new ScopedGraphView(graph, teamAScope);
    const visiblePaths = scopedView.getAttackPaths([externalOnlyPath]);

    expect(visiblePaths.length).toBe(0);
  });

  it('allows tenant ADMIN users to view all assets and paths unredacted', () => {
    const { graph } = setupMultiTeamGraph();

    const adminScope: UserScope = {
      userId: 'admin-bob',
      tenantId: 'tenant-corp',
      role: 'ADMIN',
    };

    const scopedView = new ScopedGraphView(graph, adminScope);
    expect(scopedView.getAllNodes().length).toBe(3);
    expect(scopedView.getNode('asset-team-b-ingress')).toBeDefined();
    expect(scopedView.getAllFindings().length).toBe(2);
  });
});
