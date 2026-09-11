import { describe, it, expect } from 'vitest';
import type { Asset } from '@ai-security-architect/core';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import { AttackPathEngine } from '../src/attack-path-engine.js';
import { SimulationEngine } from '../src/simulation/simulation-engine.js';

describe('Task A.3 — Threat Modeling & Attack Simulation (Purple Team Mode)', () => {
  const tenantId = 'tenant-sim-test';

  function buildSimulationTopology(): SecurityGraphEngine {
    const graph = new SecurityGraphEngine(tenantId);

    const internet: Asset = {
      id: 'asset-internet',
      tenantId,
      type: 'INTERNET',
      name: 'public-internet',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'LOW',
      metadata: {},
      tags: [],
    };

    const ingressGateway: Asset = {
      id: 'asset-ingress-gw',
      tenantId,
      type: 'LOAD_BALANCER',
      name: 'api-gateway',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'MEDIUM',
      metadata: {},
      tags: [],
    };

    const internalService: Asset = {
      id: 'asset-internal-auth',
      tenantId,
      type: 'SERVICE',
      name: 'auth-service',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    const devMachine: Asset = {
      id: 'asset-dev-workstation',
      tenantId,
      type: 'SERVICE',
      name: 'engineer-macbook',
      environment: 'development',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'MEDIUM',
      metadata: {},
      tags: ['internal-only', 'corp-net'],
    };

    const adminRole: Asset = {
      id: 'asset-role-admin',
      tenantId,
      type: 'IAM_ROLE',
      name: 'super-admin-role',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'CRITICAL',
      metadata: {},
      tags: [],
    };

    const piiDatabase: Asset = {
      id: 'asset-db-customers',
      tenantId,
      type: 'DATABASE',
      name: 'customer-db-primary',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      metadata: {},
      tags: ['contains-pii', 'compliance=gdpr'],
    };

    graph.addAsset(internet);
    graph.addAsset(ingressGateway);
    graph.addAsset(internalService);
    graph.addAsset(devMachine);
    graph.addAsset(adminRole);
    graph.addAsset(piiDatabase);

    // Ingress route: Internet -> Gateway -> Internal Auth
    graph.addRelationship({
      id: 'rel-inet-gw',
      tenantId,
      sourceAssetId: internet.id,
      targetAssetId: ingressGateway.id,
      type: 'EXPOSES_HTTP',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-gw-auth',
      tenantId,
      sourceAssetId: ingressGateway.id,
      targetAssetId: internalService.id,
      type: 'ROUTES_TO',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    // Developer workstation route: Dev Machine has SSH key / privileged access to Auth Service
    graph.addRelationship({
      id: 'rel-dev-auth',
      tenantId,
      sourceAssetId: devMachine.id,
      targetAssetId: internalService.id,
      type: 'ROUTES_TO',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    // Internal Auth assumes Admin Role
    graph.addRelationship({
      id: 'rel-auth-role',
      tenantId,
      sourceAssetId: internalService.id,
      targetAssetId: adminRole.id,
      type: 'ASSUMES_ROLE',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    // Admin Role can read PII Database
    graph.addRelationship({
      id: 'rel-role-db',
      tenantId,
      sourceAssetId: adminRole.id,
      targetAssetId: piiDatabase.id,
      type: 'CAN_READ',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    return graph;
  }

  it('simulates forward blast-radius from non-internet developer workstation to crown jewel database', () => {
    const graph = buildSimulationTopology();
    const simEngine = new SimulationEngine();

    const result = simEngine.simulateCompromise(graph, {
      assumedBreachedAssetId: 'asset-dev-workstation',
      description: 'Hypothetical developer laptop compromised via drive-by malware download',
      threatActor: 'APT29',
      mode: 'FORWARD',
    });

    expect(result.breachedAsset.name).toBe('engineer-macbook');
    expect(result.summary.totalBlastRadiusPaths).toBe(1);
    expect(result.blastRadiusPaths.length).toBe(1);

    const blastPath = result.blastRadiusPaths[0];
    expect(blastPath.isSimulation).toBe(true);
    expect(blastPath.simulationContext?.rootAssetId).toBe('asset-dev-workstation');
    expect(blastPath.simulationContext?.direction).toBe('FORWARD');
    expect(blastPath.simulationContext?.hypothesis).toContain('drive-by malware download');

    expect(blastPath.entryAssetId).toBe('asset-dev-workstation');
    expect(blastPath.targetAssetId).toBe('asset-db-customers');
    expect(blastPath.pathLength).toBe(3); // dev -> auth -> role -> db

    expect(result.reachableCrownJewels.length).toBe(1);
    expect(result.reachableCrownJewels[0].id).toBe('asset-db-customers');
  });

  it('simulates reverse entrypoint tracing to reveal how external attackers can reach an internal asset', () => {
    const graph = buildSimulationTopology();
    const simEngine = new SimulationEngine();

    const result = simEngine.simulateCompromise(graph, {
      assumedBreachedAssetId: 'asset-internal-auth',
      description: 'Find all external ingress vectors reaching auth service',
      mode: 'REVERSE',
    });

    expect(result.summary.totalUpstreamPaths).toBe(2);
    expect(result.upstreamEntrypointPaths.length).toBe(2);

    expect(result.potentialExternalIngressAssets.some((a) => a.id === 'asset-internet')).toBe(true);
    expect(result.potentialExternalIngressAssets.some((a) => a.id === 'asset-ingress-gw')).toBe(true);
  });

  it('guarantees simulated paths are excluded from standard baseline alert counts', () => {
    const graph = buildSimulationTopology();
    const pathEngine = new AttackPathEngine();
    const simEngine = new SimulationEngine(pathEngine);

    // Standard baseline scan
    const baselinePaths = pathEngine.analyzePaths(graph);
    // Baseline paths must not have isSimulation set to true
    expect(baselinePaths.every((p) => !p.isSimulation)).toBe(true);

    // Purple team simulation
    const simResult = simEngine.simulateCompromise(graph, {
      assumedBreachedAssetId: 'asset-dev-workstation',
      description: 'What-if test',
    });

    // Mix simulated paths with baseline paths (e.g. in aggregate data pool)
    const combinedPaths = [...baselinePaths, ...simResult.blastRadiusPaths];

    // Production alerting filter MUST strictly exclude simulated paths
    const productionAlertablePaths = pathEngine.filterProductionAlertablePaths(combinedPaths);

    expect(productionAlertablePaths.length).toBe(baselinePaths.length);
    expect(productionAlertablePaths.every((p) => !p.isSimulation)).toBe(true);
  });

  it('throws descriptive error if assumed breach asset does not exist in graph', () => {
    const graph = buildSimulationTopology();
    const simEngine = new SimulationEngine();

    expect(() => {
      simEngine.simulateCompromise(graph, {
        assumedBreachedAssetId: 'asset-does-not-exist',
        description: 'Missing node test',
      });
    }).toThrowError(/does not exist in the graph/);
  });

  it('returns empty blast radius without throwing when starting simulation from a leaf node with no outgoing edges', () => {
    const graph = buildSimulationTopology();
    const simEngine = new SimulationEngine();

    // asset-db-customers is a leaf node with no outgoing edges
    const result = simEngine.simulateCompromise(graph, {
      assumedBreachedAssetId: 'asset-db-customers',
      description: 'Simulation starting at terminal leaf node',
      mode: 'FORWARD',
    });

    expect(result.breachedAsset.id).toBe('asset-db-customers');
    expect(result.blastRadiusPaths.length).toBe(0);
    expect(result.summary.totalBlastRadiusPaths).toBe(0);
    expect(result.reachableCrownJewels.length).toBe(0);
  });
});
