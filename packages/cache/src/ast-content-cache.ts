import * as crypto from 'node:crypto';
import type { CacheEntry, CacheStats, FileAnalysisCacheData } from './types.js';

export class AstContentCache {
  private readonly entries = new Map<string, CacheEntry<FileAnalysisCacheData>>();
  private hits = 0;
  private misses = 0;

  public computeSha256(content: string): string {
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  }

  public get(filePath: string, currentContentSha256: string): FileAnalysisCacheData | undefined {
    const entry = this.entries.get(filePath);

    if (entry && entry.contentSha256 === currentContentSha256) {
      this.hits++;
      entry.hitCount++;
      return entry.data;
    }

    this.misses++;
    return undefined;
  }

  public set(
    filePath: string,
    contentSha256: string,
    data: FileAnalysisCacheData
  ): void {
    this.entries.set(filePath, {
      key: filePath,
      contentSha256,
      data,
      cachedAt: new Date().toISOString(),
      hitCount: 0,
    });
  }

  public invalidate(filePath: string): boolean {
    return this.entries.delete(filePath);
  }

  public clear(): void {
    this.entries.clear();
    this.hits = 0;
    this.misses = 0;
  }

  public getStats(): CacheStats {
    const totalRequests = this.hits + this.misses;
    const hitRatePercentage = totalRequests > 0
      ? Math.round((this.hits / totalRequests) * 100)
      : 0;

    return {
      hits: this.hits,
      misses: this.misses,
      entryCount: this.entries.size,
      hitRatePercentage,
    };
  }
}
