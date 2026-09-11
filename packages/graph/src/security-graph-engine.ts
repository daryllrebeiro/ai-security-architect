import type { Asset, Relationship, Finding } from '@ai-security-architect/core';
import type {
  GraphNode,
  GraphEdge,
  GraphTraversalOptions,
  GraphDiff,
  SecurityGraphSnapshot,
  GraphStore,
  GraphEngineOptions,
  CloudDriftResult,
  CloudDriftConfigItem,
  CloudDriftDifference,
} from './types.js';
import { InMemoryGraphStore } from './stores/in-memory-graph-store.js';
import { SqliteGraphStore } from './stores/sqlite-graph-store.js';

export class SecurityGraphEngine {
  public readonly tenantId: string;
  private store: GraphStore;
  private readonly options: GraphEngineOptions;

  constructor(tenantId: string = 'default-tenant', options: GraphEngineOptions = {}) {
    this.tenantId = tenantId;
    this.options = options;

    if (options.store) {
      this.store = options.store;
    } else if (options.backend === 'sqlite') {
      this.store = new SqliteGraphStore(tenantId, options.dbPath ?? ':memory:');
    } else {
      this.store = new InMemoryGraphStore(tenantId);
    }
  }

  public getStore(): GraphStore {
    return this.store;
  }

  public addAsset(asset: Asset): GraphNode {
    this.checkAutoSpill();
    return this.store.addAsset(asset);
  }

  public getNode(assetId: string): GraphNode | undefined {
    return this.store.getNode(assetId);
  }

  public hasNode(assetId: string): boolean {
    return this.store.hasNode(assetId);
  }

  public getAllNodes(): GraphNode[] {
    return this.store.getAllNodes();
  }

  public removeNode(assetId: string): boolean {
    return this.store.removeNode(assetId);
  }

  public addRelationship(rel: Relationship): GraphEdge {
    return this.store.addRelationship(rel);
  }

  public getEdge(edgeId: string): GraphEdge | undefined {
    return this.store.getEdge(edgeId);
  }

  public getAllEdges(): GraphEdge[] {
    return this.store.getAllEdges();
  }

  public removeEdge(edgeId: string): boolean {
    return this.store.removeEdge(edgeId);
  }

  public attachFinding(finding: Finding): void {
    this.store.attachFinding(finding);
  }

  public getFindingsForNode(assetId: string): Finding[] {
    return this.store.getFindingsForNode(assetId);
  }

  public getAllFindings(): Finding[] {
    return this.store.getAllFindings();
  }

  public getOutgoingEdges(assetId: string): GraphEdge[] {
    return this.store.getOutgoingEdges(assetId);
  }

  public getIncomingEdges(assetId: string): GraphEdge[] {
    return this.store.getIncomingEdges(assetId);
  }

  public getNeighbors(
    assetId: string,
    direction: 'OUTGOING' | 'INCOMING' | 'BOTH' = 'OUTGOING'
  ): GraphNode[] {
    return this.store.getNeighbors(assetId, direction);
  }

  public findAllPaths(
    startAssetId: string,
    targetAssetId: string,
    options: GraphTraversalOptions = {}
  ): GraphEdge[][] {
    return this.store.findAllPaths(startAssetId, targetAssetId, options);
  }

  public toSnapshot(): SecurityGraphSnapshot {
    return this.store.toSnapshot();
  }

  public vacuumInto(targetPath: string): void {
    if (this.store instanceof SqliteGraphStore) {
      this.store.vacuumInto(targetPath);
    } else {
      throw new Error('vacuumInto is only supported when using SqliteGraphStore');
    }
  }

  public transaction<T>(fn: () => T): T {
    return this.store.transaction ? this.store.transaction(fn) : fn();
  }

  public close(): void {
    this.store.close?.();
  }

  private checkAutoSpill(): void {
    if (
      this.options.backend === 'auto' &&
      this.store instanceof InMemoryGraphStore &&
      this.store.getAllNodes().length >= (this.options.nodeThreshold ?? 10_000)
    ) {
      const sqliteStore = new SqliteGraphStore(this.tenantId, this.options.dbPath ?? ':memory:');
      for (const node of this.store.getAllNodes()) {
        sqliteStore.addAsset(node.asset);
        for (const finding of node.findings) {
          sqliteStore.attachFinding(finding);
        }
      }
      for (const edge of this.store.getAllEdges()) {
        sqliteStore.addRelationship(edge.relationship);
      }
      this.store = sqliteStore;
    }
  }

  public static fromSnapshot(
    snapshot: SecurityGraphSnapshot,
    options?: GraphEngineOptions
  ): SecurityGraphEngine {
    const engine = new SecurityGraphEngine(snapshot.tenantId, options);

    for (const nodeData of snapshot.nodes) {
      engine.addAsset(nodeData.asset);
      for (const finding of nodeData.findings) {
        engine.attachFinding(finding);
      }
    }

    for (const rel of snapshot.edges) {
      engine.addRelationship(rel);
    }

    return engine;
  }

  public static diff(before: SecurityGraphEngine, after: SecurityGraphEngine): GraphDiff {
    const beforeNodes = new Map(before.getAllNodes().map((n) => [n.asset.id, n]));
    const afterNodes = new Map(after.getAllNodes().map((n) => [n.asset.id, n]));

    const addedNodes = after.getAllNodes()
      .filter((n) => !beforeNodes.has(n.asset.id))
      .map((n) => n.asset);

    const removedNodes = before.getAllNodes()
      .filter((n) => !afterNodes.has(n.asset.id))
      .map((n) => n.asset);

    const beforeEdges = new Map(before.getAllEdges().map((e) => [e.relationship.id, e.relationship]));
    const afterEdges = new Map(after.getAllEdges().map((e) => [e.relationship.id, e.relationship]));

    const addedEdges = after.getAllEdges()
      .filter((e) => !beforeEdges.has(e.relationship.id))
      .map((e) => e.relationship);

    const removedEdges = before.getAllEdges()
      .filter((e) => !afterEdges.has(e.relationship.id))
      .map((e) => e.relationship);

    const beforeFindings = new Map(before.getAllFindings().map((f) => [f.id, f]));
    const afterFindings = new Map(after.getAllFindings().map((f) => [f.id, f]));

    const resolvedFindings = before.getAllFindings().filter((f) => !afterFindings.has(f.id));
    const newFindings = after.getAllFindings().filter((f) => !beforeFindings.has(f.id));

    return {
      addedNodes,
      removedNodes,
      addedEdges,
      removedEdges,
      resolvedFindings,
      newFindings,
    };
  }

  public static diffCloudDrift(
    declaredGraph: SecurityGraphEngine,
    liveGraph: SecurityGraphEngine
  ): CloudDriftResult {
    const declaredNodes = declaredGraph.getAllNodes();
    const liveNodes = liveGraph.getAllNodes();

    const declaredById = new Map<string, Asset>();
    const declaredByName = new Map<string, Asset>();
    for (const node of declaredNodes) {
      declaredById.set(node.asset.id, node.asset);
      declaredByName.set(node.asset.name, node.asset);
    }

    const liveById = new Map<string, Asset>();
    const liveByName = new Map<string, Asset>();
    for (const node of liveNodes) {
      liveById.set(node.asset.id, node.asset);
      liveByName.set(node.asset.name, node.asset);
    }

    const onlyInDeclared: Asset[] = [];
    const onlyInLive: Asset[] = [];
    const configDrift: CloudDriftConfigItem[] = [];

    // Check declared against live
    for (const dNode of declaredNodes) {
      const match = liveById.get(dNode.asset.id) ?? liveByName.get(dNode.asset.name);
      if (!match) {
        onlyInDeclared.push(dNode.asset);
      }
    }

    // Check live against declared
    for (const lNode of liveNodes) {
      const match = declaredById.get(lNode.asset.id) ?? declaredByName.get(lNode.asset.name);
      if (!match) {
        onlyInLive.push(lNode.asset);
      } else {
        const differences: CloudDriftDifference[] = [];
        if (Boolean(match.isPublic) !== Boolean(lNode.asset.isPublic)) {
          differences.push({
            property: 'isPublic',
            declaredValue: match.isPublic,
            liveValue: lNode.asset.isPublic,
          });
        }
        if (match.type !== lNode.asset.type) {
          differences.push({
            property: 'type',
            declaredValue: match.type,
            liveValue: lNode.asset.type,
          });
        }
        if (Boolean(match.isSensitiveData) !== Boolean(lNode.asset.isSensitiveData)) {
          differences.push({
            property: 'isSensitiveData',
            declaredValue: match.isSensitiveData,
            liveValue: lNode.asset.isSensitiveData,
          });
        }

        if (match.metadata?.publicAccessBlock !== undefined || lNode.asset.metadata?.publicAccessBlock !== undefined) {
          const dPab = JSON.stringify(match.metadata?.publicAccessBlock);
          const lPab = JSON.stringify(lNode.asset.metadata?.publicAccessBlock);
          if (dPab !== lPab) {
            differences.push({
              property: 'metadata.publicAccessBlock',
              declaredValue: match.metadata?.publicAccessBlock,
              liveValue: lNode.asset.metadata?.publicAccessBlock,
            });
          }
        }

        if (differences.length > 0) {
          configDrift.push({
            assetId: match.id,
            declaredAsset: match,
            liveAsset: lNode.asset,
            differences,
          });
        }
      }
    }

    const declaredEdgeKeys = new Set(
      declaredGraph.getAllEdges().map((e) => `${e.sourceAssetId}->${e.targetAssetId}:${e.type}`)
    );
    const shadowRelationships = liveGraph
      .getAllEdges()
      .filter((e) => !declaredEdgeKeys.has(`${e.sourceAssetId}->${e.targetAssetId}:${e.type}`))
      .map((e) => e.relationship);

    return {
      onlyInDeclared,
      onlyInLive,
      configDrift,
      shadowRelationships,
    };
  }
}
