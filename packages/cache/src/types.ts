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
  entryCount: number;
  hitRatePercentage: number;
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
