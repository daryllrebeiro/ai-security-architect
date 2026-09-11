import type { Asset, Relationship, Finding, Evidence } from '@ai-security-architect/core';

export interface CacheEntry<T> {
  key: string;
  contentSha256: string;
  data: T;
  cachedAt: string;
  hitCount: number;
}

export interface CacheStats {
  hits: number;
  misses: number;
  l1Hits: number;
  l2Hits: number;
  entryCount: number;
  hitRatePercentage: number;
}

export interface AstContentCacheOptions {
  maxMemoryEntries?: number;
  maxMemoryBytes?: number;
  diskCacheDir?: string;
  enableDiskCache?: boolean;
}

export interface FileAnalysisCacheData {
  filePath: string;
  assets: Asset[];
  relationships: Relationship[];
  findings: Finding[];
  evidence: Evidence[];
}

export interface FileDelta {
  added: string[];
  modified: string[];
  deleted: string[];
}

export interface IncrementalUpdateResult {
  affectedAssetsCount: number;
  affectedEdgesCount: number;
  durationMs: number;
}

export interface IncrementalScanSummary {
  filesScanned: number;
  filesSkipped: number;
  cacheHitRate: number;
  durationMs: number;
  delta: FileDelta;
}
