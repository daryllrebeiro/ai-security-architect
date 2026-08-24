import {
  AssetSchema,
  RelationshipSchema,
  FindingSchema,
  type Asset,
  type Relationship,
  type Finding,
} from '@ai-security-architect/core';
import type {
  GraphNode,
  GraphEdge,
  GraphTraversalOptions,
  GraphDiff,
  SecurityGraphSnapshot,
} from './types.js';

export class SecurityGraphEngine {
  public readonly tenantId: string;
  private readonly nodes = new Map<string, GraphNode>();
  private readonly edges = new Map<string, GraphEdge>();
  private readonly outgoingEdges = new Map<string, Set<string>>();
  private readonly incomingEdges = new Map<string, Set<string>>();

  constructor(tenantId: string = 'default-tenant') {
    this.tenantId = tenantId;
  }

  public addAsset(asset: Asset): GraphNode {
    AssetSchema.parse(asset);

    const existing = this.nodes.get(asset.id);
    if (existing) {
      existing.asset = asset;
      return existing;
    }

    const node: GraphNode = {
      asset,
      findings: [],
      inDegree: 0,
      outDegree: 0,
    };

    this.nodes.set(asset.id, node);
    this.outgoingEdges.set(asset.id, new Set());
    this.incomingEdges.set(asset.id, new Set());

    return node;
  }

  public getNode(assetId: string): GraphNode | undefined {
    return this.nodes.get(assetId);
  }

  public hasNode(assetId: string): boolean {
    return this.nodes.has(assetId);
  }

  public getAllNodes(): GraphNode[] {
    return Array.from(this.nodes.values());
  }

  public addRelationship(rel: Relationship): GraphEdge {
    RelationshipSchema.parse(rel);

    // Ensure source and target nodes exist (or create placeholders)
    if (!this.nodes.has(rel.sourceAssetId)) {
      this.addAsset({
        id: rel.sourceAssetId,
        tenantId: this.tenantId,
        type: 'SERVICE',
        name: rel.sourceAssetId,
        environment: 'inferred',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        metadata: {},
        tags: ['inferred'],
      });
    }

    if (!this.nodes.has(rel.targetAssetId)) {
      this.addAsset({
        id: rel.targetAssetId,
        tenantId: this.tenantId,
        type: 'SERVICE',
        name: rel.targetAssetId,
        environment: 'inferred',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        metadata: {},
        tags: ['inferred'],
      });
    }

    const edge: GraphEdge = {
      relationship: rel,
      sourceAssetId: rel.sourceAssetId,
      targetAssetId: rel.targetAssetId,
      type: rel.type,
      confidence: rel.confidence,
      evidenceRef: rel.evidenceRef,
    };

    this.edges.set(rel.id, edge);

    this.outgoingEdges.get(rel.sourceAssetId)!.add(rel.id);
    this.incomingEdges.get(rel.targetAssetId)!.add(rel.id);

    this.updateDegrees(rel.sourceAssetId);
    this.updateDegrees(rel.targetAssetId);

    return edge;
  }

  public getEdge(edgeId: string): GraphEdge | undefined {
    return this.edges.get(edgeId);
  }

  public getAllEdges(): GraphEdge[] {
    return Array.from(this.edges.values());
  }

  public removeEdge(edgeId: string): boolean {
    const edge = this.edges.get(edgeId);
    if (!edge) return false;

    this.edges.delete(edgeId);
    this.outgoingEdges.get(edge.sourceAssetId)?.delete(edgeId);
    this.incomingEdges.get(edge.targetAssetId)?.delete(edgeId);

    this.updateDegrees(edge.sourceAssetId);
    this.updateDegrees(edge.targetAssetId);

    return true;
  }

  public removeNode(assetId: string): boolean {
    const node = this.nodes.get(assetId);
    if (!node) return false;

    // Remove all outgoing edges
    const outgoing = Array.from(this.outgoingEdges.get(assetId) || []);
    for (const edgeId of outgoing) {
      this.removeEdge(edgeId);
    }

    // Remove all incoming edges
    const incoming = Array.from(this.incomingEdges.get(assetId) || []);
    for (const edgeId of incoming) {
      this.removeEdge(edgeId);
    }

    this.nodes.delete(assetId);
    this.outgoingEdges.delete(assetId);
    this.incomingEdges.delete(assetId);

    return true;
  }

  public attachFinding(finding: Finding): void {
    FindingSchema.parse(finding);

    const node = this.nodes.get(finding.assetId);
    if (node) {
      // Deduplicate finding on node
      if (!node.findings.some((f) => f.id === finding.id)) {
        node.findings.push(finding);
      }
    } else {
      // If node doesn't exist yet, create and attach
      const newNode = this.addAsset({
        id: finding.assetId,
        tenantId: this.tenantId,
        type: 'SERVICE',
        name: finding.assetId,
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        metadata: {},
        tags: [],
      });
      newNode.findings.push(finding);
    }
  }

  public getFindingsForNode(assetId: string): Finding[] {
    return this.nodes.get(assetId)?.findings ?? [];
  }

  public getAllFindings(): Finding[] {
    const allFindings: Finding[] = [];
    for (const node of this.nodes.values()) {
      allFindings.push(...node.findings);
    }
    return allFindings;
  }

  public getOutgoingEdges(assetId: string): GraphEdge[] {
    const edgeIds = this.outgoingEdges.get(assetId);
    if (!edgeIds) return [];
    return Array.from(edgeIds)
      .map((id) => this.edges.get(id)!)
      .filter(Boolean);
  }

  public getIncomingEdges(assetId: string): GraphEdge[] {
    const edgeIds = this.incomingEdges.get(assetId);
    if (!edgeIds) return [];
    return Array.from(edgeIds)
      .map((id) => this.edges.get(id)!)
      .filter(Boolean);
  }

  public getNeighbors(
    assetId: string,
    direction: 'OUTGOING' | 'INCOMING' | 'BOTH' = 'OUTGOING'
  ): GraphNode[] {
    const neighborIds = new Set<string>();

    if (direction === 'OUTGOING' || direction === 'BOTH') {
      for (const edge of this.getOutgoingEdges(assetId)) {
        neighborIds.add(edge.targetAssetId);
      }
    }

    if (direction === 'INCOMING' || direction === 'BOTH') {
      for (const edge of this.getIncomingEdges(assetId)) {
        neighborIds.add(edge.sourceAssetId);
      }
    }

    return Array.from(neighborIds)
      .map((id) => this.nodes.get(id)!)
      .filter(Boolean);
  }

  public findAllPaths(
    startAssetId: string,
    targetAssetId: string,
    options: GraphTraversalOptions = {}
  ): GraphEdge[][] {
    const maxDepth = options.maxDepth ?? 10;
    const paths: GraphEdge[][] = [];
    const currentPath: GraphEdge[] = [];
    const visitedNodes = new Set<string>([startAssetId]);

    const dfs = (currentAssetId: string, depth: number) => {
      if (currentAssetId === targetAssetId && currentPath.length > 0) {
        paths.push([...currentPath]);
        return;
      }

      if (depth >= maxDepth) return;

      const outgoing = this.getOutgoingEdges(currentAssetId);

      for (const edge of outgoing) {
        if (options.blockedEdgeIds?.has(edge.relationship.id)) continue;
        if (options.allowedEdgeTypes && !options.allowedEdgeTypes.includes(edge.type)) continue;

        const nextAssetId = edge.targetAssetId;
        if (options.blockedAssetIds?.has(nextAssetId)) continue;
        if (visitedNodes.has(nextAssetId)) continue; // Prevent graph cycles

        visitedNodes.add(nextAssetId);
        currentPath.push(edge);

        dfs(nextAssetId, depth + 1);

        currentPath.pop();
        visitedNodes.delete(nextAssetId);
      }
    };

    dfs(startAssetId, 0);
    return paths;
  }

  public toSnapshot(): SecurityGraphSnapshot {
    return {
      tenantId: this.tenantId,
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      nodes: Array.from(this.nodes.values()).map((n) => ({
        asset: n.asset,
        findings: n.findings,
      })),
      edges: Array.from(this.edges.values()).map((e) => e.relationship),
    };
  }

  public static fromSnapshot(snapshot: SecurityGraphSnapshot): SecurityGraphEngine {
    const engine = new SecurityGraphEngine(snapshot.tenantId);

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

  private updateDegrees(assetId: string): void {
    const node = this.nodes.get(assetId);
    if (!node) return;
    node.outDegree = this.outgoingEdges.get(assetId)?.size ?? 0;
    node.inDegree = this.incomingEdges.get(assetId)?.size ?? 0;
  }
}
