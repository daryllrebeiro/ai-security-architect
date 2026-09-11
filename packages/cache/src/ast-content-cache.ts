import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import LRUCachePkg from 'lru-cache';
import type {
  CacheEntry,
  CacheStats,
  FileAnalysisCacheData,
  AstContentCacheOptions,
} from './types.js';

const LRUConstructor: any = (LRUCachePkg as any).LRUCache || LRUCachePkg;

export class AstContentCache {
  private readonly l1Cache: any;
  private readonly diskCacheDir?: string;
  private readonly enableDiskCache: boolean;
  private hits = 0;
  private misses = 0;
  private l1Hits = 0;
  private l2Hits = 0;

  constructor(options: AstContentCacheOptions = {}) {
    const maxEntries = options.maxMemoryEntries ?? 5000;

    this.l1Cache = new LRUConstructor({
      max: maxEntries,
      maxAge: 1000 * 60 * 60 * 24,
    });

    this.diskCacheDir = options.diskCacheDir;
    this.enableDiskCache = options.enableDiskCache ?? Boolean(options.diskCacheDir);

    if (this.enableDiskCache && this.diskCacheDir) {
      try {
        fs.mkdirSync(this.diskCacheDir, { recursive: true });
      } catch {}
    }
  }

  public computeSha256(content: string): string {
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  }

  private getDiskKey(filePath: string, contentSha256: string): string {
    const hash = crypto
      .createHash('sha256')
      .update(`${filePath}:${contentSha256}`)
      .digest('hex');
    return path.join(this.diskCacheDir!, `${hash}.json`);
  }

  public get(filePath: string, currentContentSha256: string): FileAnalysisCacheData | undefined {
    // 1. Check L1 Memory LRU
    const entry = this.l1Cache.get(filePath);
    if (entry && entry.contentSha256 === currentContentSha256) {
      this.hits++;
      this.l1Hits++;
      entry.hitCount++;
      return entry.data;
    }

    // 2. Check L2 Disk Cache
    if (this.enableDiskCache && this.diskCacheDir) {
      const diskPath = this.getDiskKey(filePath, currentContentSha256);
      if (fs.existsSync(diskPath)) {
        try {
          const raw = fs.readFileSync(diskPath, 'utf8');
          const diskEntry = JSON.parse(raw) as CacheEntry<FileAnalysisCacheData>;
          if (diskEntry.contentSha256 === currentContentSha256) {
            this.hits++;
            this.l2Hits++;
            diskEntry.hitCount++;
            // Promote to L1
            this.l1Cache.set(filePath, diskEntry);
            return diskEntry.data;
          }
        } catch {
          // If disk file corrupt, ignore
        }
      }
    }

    this.misses++;
    return undefined;
  }

  public set(
    filePath: string,
    contentSha256: string,
    data: FileAnalysisCacheData
  ): void {
    const entry: CacheEntry<FileAnalysisCacheData> = {
      key: filePath,
      contentSha256,
      data,
      cachedAt: new Date().toISOString(),
      hitCount: 0,
    };

    // 1. Write to L1 Memory LRU
    this.l1Cache.set(filePath, entry);

    // 2. Write to L2 Disk Cache
    if (this.enableDiskCache && this.diskCacheDir) {
      try {
        const diskPath = this.getDiskKey(filePath, contentSha256);
        fs.writeFileSync(diskPath, JSON.stringify(entry), 'utf8');
      } catch {}
    }
  }

  public invalidate(filePath: string): boolean {
    const l1: any = this.l1Cache;
    let inL1 = false;
    if (typeof l1.delete === 'function') {
      inL1 = l1.delete(filePath);
    } else if (typeof l1.del === 'function') {
      inL1 = l1.has(filePath);
      l1.del(filePath);
    }
    return inL1;
  }

  public clear(): void {
    const l1: any = this.l1Cache;
    if (typeof l1.clear === 'function') {
      l1.clear();
    } else if (typeof l1.reset === 'function') {
      l1.reset();
    }
    this.hits = 0;
    this.misses = 0;
    this.l1Hits = 0;
    this.l2Hits = 0;

    if (this.enableDiskCache && this.diskCacheDir && fs.existsSync(this.diskCacheDir)) {
      try {
        const files = fs.readdirSync(this.diskCacheDir);
        for (const file of files) {
          if (file.endsWith('.json')) {
            fs.unlinkSync(path.join(this.diskCacheDir, file));
          }
        }
      } catch {}
    }
  }

  public getStats(): CacheStats {
    const totalRequests = this.hits + this.misses;
    const hitRatePercentage = totalRequests > 0
      ? Math.round((this.hits / totalRequests) * 100)
      : 0;

    const l1: any = this.l1Cache;
    const count = l1.size ?? l1.itemCount ?? 0;

    return {
      hits: this.hits,
      misses: this.misses,
      l1Hits: this.l1Hits,
      l2Hits: this.l2Hits,
      entryCount: count,
      hitRatePercentage,
    };
  }
}
