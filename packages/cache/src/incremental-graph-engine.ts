import type { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { FileDelta, FileAnalysisCacheData, IncrementalUpdateResult } from './types.js';

export class IncrementalGraphEngine {
  public applyFileDelta(
    graph: SecurityGraphEngine,
    delta: FileDelta,
    updatedDataList: FileAnalysisCacheData[]
  ): IncrementalUpdateResult {
    const startTime = Date.now();
    let affectedAssetsCount = 0;
    let affectedEdgesCount = 0;

    const modifiedOrDeletedFiles = new Set([...delta.modified, ...delta.deleted]);

    // 1. Remove stale edges & nodes associated with deleted/modified files
    const allEdges = graph.getAllEdges();
    for (const edge of allEdges) {
      const sourceNode = graph.getNode(edge.sourceAssetId);
      const targetNode = graph.getNode(edge.targetAssetId);

      const sourceFile = sourceNode?.asset.metadata?.filePath as string;
      const targetFile = targetNode?.asset.metadata?.filePath as string;

      if (
        (sourceFile && modifiedOrDeletedFiles.has(sourceFile)) ||
        (targetFile && modifiedOrDeletedFiles.has(targetFile))
      ) {
        graph.removeEdge(edge.relationship.id);
        affectedEdgesCount++;
      }
    }

    for (const filePath of delta.deleted) {
      const nodesToDelete = graph
        .getAllNodes()
        .filter((n) => n.asset.metadata?.filePath === filePath);

      for (const node of nodesToDelete) {
        graph.removeNode(node.asset.id);
        affectedAssetsCount++;
      }
    }

    // 2. Ingest updated/added file data
    for (const data of updatedDataList) {
      for (const asset of data.assets) {
        graph.addAsset(asset);
        affectedAssetsCount++;
      }

      for (const rel of data.relationships) {
        graph.addRelationship(rel);
        affectedEdgesCount++;
      }

      for (const finding of data.findings) {
        graph.attachFinding(finding);
      }
    }

    return {
      affectedAssetsCount,
      affectedEdgesCount,
      durationMs: Date.now() - startTime,
    };
  }
}
