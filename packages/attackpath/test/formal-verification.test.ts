import { describe, it, expect } from 'vitest';
import {
  FormalVerificationEngine,
  SubgraphSpecification,
  CrownJewelInvariant,
  FORMAL_PROOF_DISCLAIMER,
} from '../src/formal-verification/index.js';

describe('Task G.2: Formal Verification / Policy Proof Layer for Crown-Jewel Paths', () => {
  const engine = new FormalVerificationEngine();

  it('formally proves unsatisfiable (proven safe) across all configuration assignments', () => {
    // Topology: Internet -> ALB -> App -> (no route to isolated DB)
    // Conditional variables: enable_internal_cache, enable_analytics
    const subgraph: SubgraphSpecification = {
      nodeIds: ['asset-internet', 'asset-alb', 'asset-app', 'asset-db', 'asset-cache'],
      configurationVariables: ['enable_internal_cache', 'enable_analytics'],
      edges: [
        { id: 'e1', fromAssetId: 'asset-internet', toAssetId: 'asset-alb' },
        { id: 'e2', fromAssetId: 'asset-alb', toAssetId: 'asset-app' },
        { id: 'e3', fromAssetId: 'asset-app', toAssetId: 'asset-cache', conditionVar: 'enable_internal_cache' },
      ],
    };

    const invariant: CrownJewelInvariant = {
      name: 'INV-001-ISOLATED-DATABASE',
      crownJewelAssetId: 'asset-db',
      entryNodeId: 'asset-internet',
    };

    const result = engine.verifyInvariant(subgraph, invariant);

    expect(result.provenSafe).toBe(true);
    expect(result.totalConfigurationSpace).toBe(4); // 2^2
    expect(result.counterexample).toBeUndefined();
    expect(result.violatingPath).toBeUndefined();
    expect(result.scopeDisclaimer).toBe(FORMAL_PROOF_DISCLAIMER);
  });

  it('returns satisfiable (exposure found) with concrete counterexample assignment when a configuration creates a path', () => {
    // Topology: Internet -> ALB -> App -> DB (if enable_legacy_bastion is true)
    const subgraph: SubgraphSpecification = {
      nodeIds: ['asset-internet', 'asset-alb', 'asset-app', 'asset-bastion', 'asset-db'],
      configurationVariables: ['enable_legacy_bastion', 'enable_waf_strict_mode'],
      edges: [
        { id: 'e1', fromAssetId: 'asset-internet', toAssetId: 'asset-alb' },
        { id: 'e2', fromAssetId: 'asset-alb', toAssetId: 'asset-app' },
        {
          id: 'e3',
          fromAssetId: 'asset-internet',
          toAssetId: 'asset-bastion',
          conditionVar: 'enable_legacy_bastion',
        },
        { id: 'e4', fromAssetId: 'asset-bastion', toAssetId: 'asset-db' },
      ],
    };

    const invariant: CrownJewelInvariant = {
      name: 'INV-002-CROWN-JEWEL-DB',
      crownJewelAssetId: 'asset-db',
      entryNodeId: 'asset-internet',
    };

    const result = engine.verifyInvariant(subgraph, invariant);

    expect(result.provenSafe).toBe(false);
    expect(result.counterexample).toBeDefined();
    expect(result.counterexample!['enable_legacy_bastion']).toBe(true);
    expect(result.violatingPath).toEqual([
      'asset-internet',
      'asset-bastion',
      'asset-db',
    ]);
  });
});
