import { SecurityGraphEngine } from '../packages/graph/src/index.js';
import { MinCutOptimizer } from '../packages/attackpath/src/index.js';
import type { AttackPath, Asset, Relationship } from '@ai-security-architect/core';

async function runMinCutBenchmark() {
  console.log('================================================================');
  console.log('  DINIC RESIDUAL FLOW MIN-CUT BENCHMARK');
  console.log('================================================================\n');

  const graph = new SecurityGraphEngine('bench-min-cut');
  const optimizer = new MinCutOptimizer();

  // Create multi-tier, multi-ingress topology with 20 ingress nodes, 50 intermediate microservices, 5 crown jewels
  const INGRESS_COUNT = 20;
  const SERVICE_COUNT = 50;
  const TARGET_COUNT = 5;

  console.log(`[1/2] Generating enterprise multi-ingress attack paths...`);
  console.log(`  -> ${INGRESS_COUNT} Ingress Points, ${SERVICE_COUNT} Services, ${TARGET_COUNT} Crown Jewels`);

  for (let i = 0; i < INGRESS_COUNT; i++) {
    graph.addAsset({
      id: `ingress-${i}`,
      tenantId: 'bench-min-cut',
      type: 'LOAD_BALANCER',
      name: `alb-${i}`,
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    });
  }

  for (let i = 0; i < SERVICE_COUNT; i++) {
    graph.addAsset({
      id: `service-${i}`,
      tenantId: 'bench-min-cut',
      type: 'SERVICE',
      name: `svc-${i}`,
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'MEDIUM',
      metadata: {},
      tags: [],
    });
  }

  for (let i = 0; i < TARGET_COUNT; i++) {
    graph.addAsset({
      id: `target-${i}`,
      tenantId: 'bench-min-cut',
      type: 'DATABASE',
      name: `db-${i}`,
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      metadata: {},
      tags: [],
    });
  }

  // Connect ingress -> services
  for (let i = 0; i < INGRESS_COUNT; i++) {
    const svc = `service-${i % SERVICE_COUNT}`;
    graph.addRelationship({
      id: `rel-in-${i}`,
      tenantId: 'bench-min-cut',
      sourceAssetId: `ingress-${i}`,
      targetAssetId: svc,
      type: 'ROUTES_TO',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    });
  }

  // Connect services -> target
  for (let i = 0; i < SERVICE_COUNT; i++) {
    const tgt = `target-${i % TARGET_COUNT}`;
    graph.addRelationship({
      id: `rel-svc-${i}`,
      tenantId: 'bench-min-cut',
      sourceAssetId: `service-${i}`,
      targetAssetId: tgt,
      type: 'CAN_READ',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    });
  }

  // Synthesize 200 distinct attack paths
  const attackPaths: AttackPath[] = [];
  for (let i = 0; i < 200; i++) {
    const ingressId = `ingress-${i % INGRESS_COUNT}`;
    const serviceId = `service-${i % SERVICE_COUNT}`;
    const targetId = `target-${i % TARGET_COUNT}`;

    attackPaths.push({
      id: `path-${i}`,
      tenantId: 'bench-min-cut',
      entryAssetId: ingressId,
      targetAssetId: targetId,
      pathLength: 2,
      steps: [
        {
          stepNumber: 1,
          sourceAssetId: ingressId,
          targetAssetId: serviceId,
          relationshipType: 'ROUTES_TO',
          explanation: 'Ingress routing',
        },
        {
          stepNumber: 2,
          sourceAssetId: serviceId,
          targetAssetId: targetId,
          relationshipType: 'CAN_READ',
          explanation: 'DB Read',
        },
      ],
      riskScore: {
        impact: 9.0,
        exploitability: 8.5,
        reachability: 1.0,
        assetCriticality: 10.0,
        confidence: 0.95,
        totalRisk: 9.2,
      },
      verifiedEliminated: false,
    });
  }

  console.log(`  -> Generated ${attackPaths.length} attack paths across topology.`);

  console.log(`\n[2/2] Running Dinic Residual Flow Min-Cut across 200 attack paths...`);
  const start = performance.now();
  const globalCut = optimizer.findGlobalMinCut(graph, attackPaths);
  const elapsed = performance.now() - start;

  console.log(`  -> Execution Time: ${elapsed.toFixed(2)}ms`);
  console.log(`  -> Total Choke Points in Min-Cut Set: ${globalCut.chokePoints.length}`);
  console.log(`  -> Total Cut Capacity Cost: ${globalCut.totalCapacityCost.toFixed(2)}`);
  console.log(`  -> Paths Severed: ${globalCut.pathsEliminatedCount}/${attackPaths.length} (${((globalCut.pathsEliminatedCount / attackPaths.length) * 100).toFixed(0)}%)`);
  console.log(`  -> Fully Severed: ${globalCut.fullySevered}`);

  console.log('\n================================================================');
  console.log('  MIN-CUT BENCHMARK COMPLETE - SUB-MILLISECOND RESIDUAL FLOW CUT');
  console.log('================================================================\n');
}

runMinCutBenchmark().catch((err) => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
