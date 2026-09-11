import * as crypto from 'node:crypto';
import type { AttackPath } from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '../security-graph-engine.js';

export interface PathSemanticShape {
  nodeTypes: string[];
  relationshipTypes: string[];
  terminalTags: string[];
  originatingVulnerabilityCategory: string;
}

export function extractPathSemanticShape(
  path: AttackPath,
  graph: SecurityGraphEngine
): PathSemanticShape {
  const nodeTypes: string[] = [];
  const relationshipTypes: string[] = [];

  // 1. Ordered sequence of node types
  const entryNode = graph.getNode(path.entryAssetId);
  nodeTypes.push(entryNode?.asset.type ?? 'UNKNOWN_ENTRY');

  for (const step of path.steps) {
    const targetNode = graph.getNode(step.targetAssetId);
    nodeTypes.push(targetNode?.asset.type ?? 'UNKNOWN_NODE');
    relationshipTypes.push(step.relationshipType);
  }

  // 2. Canonicalized (sorted) terminal asset tags and sensitivity classification
  const terminalNode = graph.getNode(path.targetAssetId);
  const terminalTags: string[] = [];
  if (terminalNode?.asset.tags) {
    terminalTags.push(...terminalNode.asset.tags);
  }
  if (terminalNode?.asset.isSensitiveData) {
    terminalTags.push('is_sensitive_data');
  }
  if (terminalNode?.asset.isPublic) {
    terminalTags.push('is_public');
  }
  terminalTags.sort();

  // 3. Originating finding vulnerability class / category
  let originatingVulnerabilityCategory = 'NONE';
  const allFindings = graph.getAllFindings();

  // Check step finding IDs first in order
  for (const step of path.steps) {
    if (step.findingId) {
      const f = allFindings.find((item) => item.id === step.findingId);
      if (f) {
        originatingVulnerabilityCategory = f.category;
        break;
      }
    }
  }

  // If no step had a finding ID, check findings attached to entry node
  if (originatingVulnerabilityCategory === 'NONE') {
    const entryFindings = graph.getFindingsForNode(path.entryAssetId);
    if (entryFindings.length > 0) {
      originatingVulnerabilityCategory = entryFindings[0].category;
    }
  }

  return {
    nodeTypes,
    relationshipTypes,
    terminalTags,
    originatingVulnerabilityCategory,
  };
}

/**
 * Computes a deterministic SHA-256 fingerprint based on the semantic shape of the attack path.
 * Raw asset IDs are omitted so renames or redeployments don't churn path identity.
 */
export function computePathFingerprint(
  path: AttackPath,
  graph: SecurityGraphEngine
): string {
  const shape = extractPathSemanticShape(path, graph);
  const canonicalString = JSON.stringify({
    nodeTypes: shape.nodeTypes,
    relationshipTypes: shape.relationshipTypes,
    terminalTags: shape.terminalTags,
    originCategory: shape.originatingVulnerabilityCategory,
  });

  const hash = crypto.createHash('sha256').update(canonicalString).digest('hex');
  return hash.slice(0, 16);
}
