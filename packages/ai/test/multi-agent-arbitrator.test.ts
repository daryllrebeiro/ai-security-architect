import { describe, it, expect } from 'vitest';
import { MultiAgentArbitrator } from '../src/multi-agent-arbitrator.js';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { AttackPath, Asset } from '@ai-security-architect/core';

describe('Milestone 3.2: Multi-Agent Remediation Arbitrator', () => {
  const graph = new SecurityGraphEngine('test-tenant');

  const ingress: Asset = {
    id: 'alb-ingress',
    tenantId: 'test-tenant',
    name: 'External Ingress ALB',
    type: 'LOAD_BALANCER',
    criticality: 'MEDIUM',
    environment: 'production',
    isPublic: true,
    isSensitiveData: false,
    metadata: {},
    tags: [],
  };

  const database: Asset = {
    id: 'db-orders',
    tenantId: 'test-tenant',
    name: 'Orders Master Database',
    type: 'DATABASE',
    criticality: 'CRITICAL',
    environment: 'production',
    isPublic: false,
    isSensitiveData: true,
    metadata: {},
    tags: [],
  };

  graph.addAsset(ingress);
  graph.addAsset(database);

  const samplePath: AttackPath = {
    id: 'path-arb-01',
    tenantId: 'test-tenant',
    entryAssetId: 'alb-ingress',
    targetAssetId: 'db-orders',
    pathLength: 2,
    steps: [],
    riskScore: {
      totalRisk: 9.0,
      exploitability: 8.5,
      impact: 9.0,
      reachability: 1.0,
      assetCriticality: 10.0,
      confidence: 1.0,
    },
    verifiedEliminated: false,
  };

  it('generates diverse viewpoints across IAM, Network, and App personas', () => {
    const arbitrator = new MultiAgentArbitrator();
    const proposals = arbitrator.generatePersonaProposals(samplePath, graph);

    expect(proposals).toHaveLength(3);
    const personas = proposals.map((p) => p.persona);
    expect(personas).toContain('IAM_SPECIALIST');
    expect(personas).toContain('NETWORK_ARCHITECT');
    expect(personas).toContain('APP_DEVELOPER');

    for (const p of proposals) {
      expect(p.securityEfficacyScore).toBeGreaterThan(0);
      expect(p.risksAndMitigations.length).toBeGreaterThan(0);
    }
  });

  it('arbitrates consensus with balanced weighting and operational safeguards', () => {
    const arbitrator = new MultiAgentArbitrator();
    const decision = arbitrator.arbitrate(samplePath, graph);

    expect(decision.attackPathId).toBe('path-arb-01');
    expect(decision.winningPersona).toBeDefined();
    expect(decision.consensusScore).toBeGreaterThan(0);
    expect(decision.consensusRationale).toContain('consensus favoring');
    expect(decision.operationalSafeguards).toEqual(
      expect.arrayContaining([expect.stringContaining('Canary deployment')])
    );
  });
});
