import type { SecurityGraphEngine } from '@ai-security-architect/graph';
import { AstContentCache } from './ast-content-cache.js';
import { IncrementalGraphEngine } from './incremental-graph-engine.js';
import type {
  FileDelta,
  FileAnalysisCacheData,
  IncrementalScanSummary,
} from './types.js';

export interface IncrementalScanOptions {
  cache?: AstContentCache;
}

export class IncrementalScanManager {
  private readonly cache: AstContentCache;
  private readonly incrementalEngine: IncrementalGraphEngine;

  constructor(options: IncrementalScanOptions = {}) {
    this.cache = options.cache ?? new AstContentCache();
    this.incrementalEngine = new IncrementalGraphEngine();
  }

  public getCache(): AstContentCache {
    return this.cache;
  }

  /**
   * Compares current workspace file hashes against cached hashes to detect delta
   */
  public detectDelta(
    currentFiles: Map<string, string>,
    previousFiles: Map<string, string>
  ): FileDelta {
    const added: string[] = [];
    const modified: string[] = [];
    const deleted: string[] = [];

    for (const [filePath, currentSha] of currentFiles.entries()) {
      const prevSha = previousFiles.get(filePath);
      if (!prevSha) {
        added.push(filePath);
      } else if (prevSha !== currentSha) {
        modified.push(filePath);
      }
    }

    for (const prevPath of previousFiles.keys()) {
      if (!currentFiles.has(prevPath)) {
        deleted.push(prevPath);
      }
    }

    return { added, modified, deleted };
  }

  /**
   * Performs an incremental PR scan.
   * Only re-analyzes added and modified files; unchanged files are retrieved from cache.
   */
  public async scanIncremental(params: {
    graph: SecurityGraphEngine;
    delta: FileDelta;
    currentFiles: Map<string, { content: string; sha256: string }>;
    analyzeFile: (filePath: string, content: string) => Promise<FileAnalysisCacheData>;
  }): Promise<IncrementalScanSummary> {
    const startTime = performance.now();
    const { graph, delta, currentFiles, analyzeFile } = params;

    const filesToAnalyze = new Set([...delta.added, ...delta.modified]);
    const updatedDataList: FileAnalysisCacheData[] = [];

    let filesScanned = 0;
    let filesSkipped = 0;

    for (const filePath of filesToAnalyze) {
      const fileInfo = currentFiles.get(filePath);
      if (!fileInfo) continue;

      const cached = this.cache.get(filePath, fileInfo.sha256);
      if (cached) {
        updatedDataList.push(cached);
        filesSkipped++;
      } else {
        const analyzed = await analyzeFile(filePath, fileInfo.content);
        this.cache.set(filePath, fileInfo.sha256, analyzed);
        updatedDataList.push(analyzed);
        filesScanned++;
      }
    }

    this.incrementalEngine.applyFileDelta(graph, delta, updatedDataList);

    const durationMs = performance.now() - startTime;
    const stats = this.cache.getStats();

    return {
      filesScanned,
      filesSkipped,
      cacheHitRate: stats.hitRatePercentage,
      durationMs,
      delta,
    };
  }
}
