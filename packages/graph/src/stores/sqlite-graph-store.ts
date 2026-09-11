import Database from 'better-sqlite3';
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
  SecurityGraphSnapshot,
  GraphStore,
} from '../types.js';

export class SqliteGraphStore implements GraphStore {
  public readonly tenantId: string;
  private readonly db: Database.Database;

  private readonly insertNodeStmt: Database.Statement;
  private readonly updateNodeDegreesStmt: Database.Statement;
  private readonly getNodeStmt: Database.Statement;
  private readonly hasNodeStmt: Database.Statement;
  private readonly getAllNodesStmt: Database.Statement;
  private readonly deleteNodeStmt: Database.Statement;

  private readonly insertEdgeStmt: Database.Statement;
  private readonly getEdgeStmt: Database.Statement;
  private readonly getAllEdgesStmt: Database.Statement;
  private readonly deleteEdgeStmt: Database.Statement;
  private readonly deleteEdgesByNodeStmt: Database.Statement;
  private readonly getOutgoingEdgesStmt: Database.Statement;
  private readonly getIncomingEdgesStmt: Database.Statement;

  private readonly insertFindingStmt: Database.Statement;
  private readonly getFindingsForNodeStmt: Database.Statement;
  private readonly getAllFindingsStmt: Database.Statement;

  constructor(tenantId: string = 'default-tenant', dbPath: string = ':memory:') {
    this.tenantId = tenantId;
    this.db = new Database(dbPath);

    if (dbPath !== ':memory:') {
      this.db.pragma('journal_mode = WAL');
    }

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS nodes (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        asset_json TEXT NOT NULL,
        type TEXT NOT NULL,
        in_degree INTEGER DEFAULT 0,
        out_degree INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS edges (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        source_id TEXT NOT NULL,
        target_id TEXT NOT NULL,
        type TEXT NOT NULL,
        nature TEXT NOT NULL,
        confidence REAL NOT NULL,
        metadata_json TEXT,
        rel_json TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        finding_json TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_edges_source ON edges (tenant_id, source_id);
      CREATE INDEX IF NOT EXISTS idx_edges_target ON edges (tenant_id, target_id);
      CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings (tenant_id, asset_id);
      CREATE INDEX IF NOT EXISTS idx_nodes_tenant ON nodes (tenant_id);
    `);

    this.insertNodeStmt = this.db.prepare(`
      INSERT OR REPLACE INTO nodes (id, tenant_id, asset_json, type, in_degree, out_degree)
      VALUES (@id, @tenant_id, @asset_json, @type, @in_degree, @out_degree)
    `);

    this.updateNodeDegreesStmt = this.db.prepare(`
      UPDATE nodes SET
        out_degree = (SELECT COUNT(*) FROM edges WHERE tenant_id = @tenant_id AND source_id = @id),
        in_degree = (SELECT COUNT(*) FROM edges WHERE tenant_id = @tenant_id AND target_id = @id)
      WHERE tenant_id = @tenant_id AND id = @id
    `);

    this.getNodeStmt = this.db.prepare(`
      SELECT * FROM nodes WHERE tenant_id = ? AND id = ?
    `);

    this.hasNodeStmt = this.db.prepare(`
      SELECT 1 FROM nodes WHERE tenant_id = ? AND id = ? LIMIT 1
    `);

    this.getAllNodesStmt = this.db.prepare(`
      SELECT * FROM nodes WHERE tenant_id = ?
    `);

    this.deleteNodeStmt = this.db.prepare(`
      DELETE FROM nodes WHERE tenant_id = ? AND id = ?
    `);

    this.insertEdgeStmt = this.db.prepare(`
      INSERT OR REPLACE INTO edges (
        id, tenant_id, source_id, target_id, type, nature, confidence, metadata_json, rel_json
      ) VALUES (
        @id, @tenant_id, @source_id, @target_id, @type, @nature, @confidence, @metadata_json, @rel_json
      )
    `);

    this.getEdgeStmt = this.db.prepare(`
      SELECT * FROM edges WHERE tenant_id = ? AND id = ?
    `);

    this.getAllEdgesStmt = this.db.prepare(`
      SELECT * FROM edges WHERE tenant_id = ?
    `);

    this.deleteEdgeStmt = this.db.prepare(`
      DELETE FROM edges WHERE tenant_id = ? AND id = ?
    `);

    this.deleteEdgesByNodeStmt = this.db.prepare(`
      DELETE FROM edges WHERE tenant_id = ? AND (source_id = ? OR target_id = ?)
    `);

    this.getOutgoingEdgesStmt = this.db.prepare(`
      SELECT * FROM edges WHERE tenant_id = ? AND source_id = ?
    `);

    this.getIncomingEdgesStmt = this.db.prepare(`
      SELECT * FROM edges WHERE tenant_id = ? AND target_id = ?
    `);

    this.insertFindingStmt = this.db.prepare(`
      INSERT OR REPLACE INTO findings (id, tenant_id, asset_id, finding_json)
      VALUES (@id, @tenant_id, @asset_id, @finding_json)
    `);

    this.getFindingsForNodeStmt = this.db.prepare(`
      SELECT finding_json FROM findings WHERE tenant_id = ? AND asset_id = ?
    `);

    this.getAllFindingsStmt = this.db.prepare(`
      SELECT finding_json FROM findings WHERE tenant_id = ?
    `);
  }

  public addAsset(asset: Asset): GraphNode {
    AssetSchema.parse(asset);

    const existingRow = this.getNodeStmt.get(this.tenantId, asset.id) as any;
    const inDegree = existingRow?.in_degree || 0;
    const outDegree = existingRow?.out_degree || 0;

    this.insertNodeStmt.run({
      id: asset.id,
      tenant_id: this.tenantId,
      asset_json: JSON.stringify(asset),
      type: asset.type,
      in_degree: inDegree,
      out_degree: outDegree,
    });

    return {
      asset,
      findings: this.getFindingsForNode(asset.id),
      inDegree,
      outDegree,
    };
  }

  public getNode(assetId: string): GraphNode | undefined {
    const row = this.getNodeStmt.get(this.tenantId, assetId) as any;
    if (!row) return undefined;

    return {
      asset: JSON.parse(row.asset_json),
      findings: this.getFindingsForNode(assetId),
      inDegree: row.in_degree,
      outDegree: row.out_degree,
    };
  }

  public hasNode(assetId: string): boolean {
    return Boolean(this.hasNodeStmt.get(this.tenantId, assetId));
  }

  public getAllNodes(): GraphNode[] {
    const rows = this.getAllNodesStmt.all(this.tenantId) as any[];
    return rows.map((row) => ({
      asset: JSON.parse(row.asset_json),
      findings: this.getFindingsForNode(row.id),
      inDegree: row.in_degree,
      outDegree: row.out_degree,
    }));
  }

  public removeNode(assetId: string): boolean {
    if (!this.hasNode(assetId)) return false;

    const outgoing = this.getOutgoingEdges(assetId);
    const incoming = this.getIncomingEdges(assetId);

    // Remove associated edges
    this.deleteEdgesByNodeStmt.run(this.tenantId, assetId, assetId);
    this.deleteNodeStmt.run(this.tenantId, assetId);

    for (const e of outgoing) {
      if (this.hasNode(e.targetAssetId)) {
        this.updateNodeDegreesStmt.run({ tenant_id: this.tenantId, id: e.targetAssetId });
      }
    }
    for (const e of incoming) {
      if (this.hasNode(e.sourceAssetId)) {
        this.updateNodeDegreesStmt.run({ tenant_id: this.tenantId, id: e.sourceAssetId });
      }
    }

    return true;
  }

  public addRelationship(rel: Relationship): GraphEdge {
    RelationshipSchema.parse(rel);

    // Ensure source and target nodes exist (or create placeholders)
    if (!this.hasNode(rel.sourceAssetId)) {
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

    if (!this.hasNode(rel.targetAssetId)) {
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

    this.insertEdgeStmt.run({
      id: rel.id,
      tenant_id: this.tenantId,
      source_id: rel.sourceAssetId,
      target_id: rel.targetAssetId,
      type: rel.type,
      nature: rel.nature,
      confidence: rel.confidence,
      metadata_json: JSON.stringify(rel.metadata || {}),
      rel_json: JSON.stringify(rel),
    });

    this.updateNodeDegreesStmt.run({ tenant_id: this.tenantId, id: rel.sourceAssetId });
    this.updateNodeDegreesStmt.run({ tenant_id: this.tenantId, id: rel.targetAssetId });

    return {
      relationship: rel,
      sourceAssetId: rel.sourceAssetId,
      targetAssetId: rel.targetAssetId,
      type: rel.type,
      confidence: rel.confidence,
      evidenceRef: rel.evidenceRef,
    };
  }

  public getEdge(edgeId: string): GraphEdge | undefined {
    const row = this.getEdgeStmt.get(this.tenantId, edgeId) as any;
    if (!row) return undefined;
    return this.mapRowToEdge(row);
  }

  public getAllEdges(): GraphEdge[] {
    const rows = this.getAllEdgesStmt.all(this.tenantId) as any[];
    return rows.map((r) => this.mapRowToEdge(r));
  }

  public removeEdge(edgeId: string): boolean {
    const edge = this.getEdge(edgeId);
    if (!edge) return false;

    this.deleteEdgeStmt.run(this.tenantId, edgeId);
    this.updateNodeDegreesStmt.run({ tenant_id: this.tenantId, id: edge.sourceAssetId });
    this.updateNodeDegreesStmt.run({ tenant_id: this.tenantId, id: edge.targetAssetId });

    return true;
  }

  public attachFinding(finding: Finding): void {
    FindingSchema.parse(finding);

    if (!this.hasNode(finding.assetId)) {
      this.addAsset({
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
    }

    this.insertFindingStmt.run({
      id: finding.id,
      tenant_id: this.tenantId,
      asset_id: finding.assetId,
      finding_json: JSON.stringify(finding),
    });
  }

  public getFindingsForNode(assetId: string): Finding[] {
    const rows = this.getFindingsForNodeStmt.all(this.tenantId, assetId) as any[];
    return rows.map((r) => JSON.parse(r.finding_json));
  }

  public getAllFindings(): Finding[] {
    const rows = this.getAllFindingsStmt.all(this.tenantId) as any[];
    return rows.map((r) => JSON.parse(r.finding_json));
  }

  public getOutgoingEdges(assetId: string): GraphEdge[] {
    const rows = this.getOutgoingEdgesStmt.all(this.tenantId, assetId) as any[];
    return rows.map((r) => this.mapRowToEdge(r));
  }

  public getIncomingEdges(assetId: string): GraphEdge[] {
    const rows = this.getIncomingEdgesStmt.all(this.tenantId, assetId) as any[];
    return rows.map((r) => this.mapRowToEdge(r));
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
      .map((id) => this.getNode(id)!)
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
        if (visitedNodes.has(nextAssetId)) continue;

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
      nodes: this.getAllNodes().map((n) => ({
        asset: n.asset,
        findings: n.findings,
      })),
      edges: this.getAllEdges().map((e) => e.relationship),
    };
  }

  public vacuumInto(targetPath: string): void {
    this.db.prepare(`VACUUM INTO ?`).run(targetPath);
  }

  public transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }

  public close(): void {
    this.db.close();
  }

  private mapRowToEdge(row: any): GraphEdge {
    const rel = JSON.parse(row.rel_json);
    return {
      relationship: rel,
      sourceAssetId: row.source_id,
      targetAssetId: row.target_id,
      type: row.type,
      confidence: row.confidence,
      evidenceRef: rel.evidenceRef,
    };
  }
}
