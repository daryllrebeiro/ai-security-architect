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
  nodes: {
    asset: Asset;
    findings: Finding[];
  }[];
  edges: Relationship[];
}
