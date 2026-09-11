import type {
  Asset,
  Relationship,
  Finding,
  RelationshipType,
} from '@ai-security-architect/core';

export interface GraphNode {
  asset: Asset;
  findings: Finding[];
  inDegree: number;
  outDegree: number;
}

export interface GraphEdge {
  relationship: Relationship;
  sourceAssetId: string;
  targetAssetId: string;
  type: RelationshipType;
  confidence: number;
  evidenceRef?: string;
}

export interface GraphTraversalOptions {
  maxDepth?: number;
  direction?: 'OUTGOING' | 'INCOMING' | 'BOTH';
  allowedEdgeTypes?: RelationshipType[];
  blockedAssetIds?: Set<string>;
  blockedEdgeIds?: Set<string>;
}

export interface GraphDiff {
  addedNodes: Asset[];
  removedNodes: Asset[];
  addedEdges: Relationship[];
  removedEdges: Relationship[];
  resolvedFindings: Finding[];
  newFindings: Finding[];
}

export interface SecurityGraphSnapshot {
  tenantId: string;
  version: string;
  timestamp: string;
  sourceFingerprint?: string;
  nodes: {
    asset: Asset;
    findings: Finding[];
  }[];
  edges: Relationship[];
}

export interface GraphStore {
  readonly tenantId: string;
  addAsset(asset: Asset): GraphNode;
  getNode(assetId: string): GraphNode | undefined;
  hasNode(assetId: string): boolean;
  getAllNodes(): GraphNode[];
  removeNode(assetId: string): boolean;

  addRelationship(rel: Relationship): GraphEdge;
  getEdge(edgeId: string): GraphEdge | undefined;
  getAllEdges(): GraphEdge[];
  removeEdge(edgeId: string): boolean;

  attachFinding(finding: Finding): void;
  getFindingsForNode(assetId: string): Finding[];
  getAllFindings(): Finding[];

  getOutgoingEdges(assetId: string): GraphEdge[];
  getIncomingEdges(assetId: string): GraphEdge[];
  getNeighbors(assetId: string, direction?: 'OUTGOING' | 'INCOMING' | 'BOTH'): GraphNode[];

  findAllPaths(startAssetId: string, targetAssetId: string, options?: GraphTraversalOptions): GraphEdge[][];
  toSnapshot(): SecurityGraphSnapshot;
  transaction?<T>(fn: () => T): T;
  close?(): void;
}

export interface GraphEngineOptions {
  backend?: 'memory' | 'sqlite' | 'auto';
  dbPath?: string;
  nodeThreshold?: number;
  store?: GraphStore;
}

export interface CloudDriftDifference {
  property: string;
  declaredValue: any;
  liveValue: any;
}

export interface CloudDriftConfigItem {
  assetId: string;
  declaredAsset: Asset;
  liveAsset: Asset;
  differences: CloudDriftDifference[];
}

export interface CloudDriftResult {
  onlyInDeclared: Asset[];
  onlyInLive: Asset[];
  configDrift: CloudDriftConfigItem[];
  shadowRelationships: Relationship[];
}
