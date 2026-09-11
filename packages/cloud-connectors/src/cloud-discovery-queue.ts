import * as fs from 'node:fs';
import * as path from 'node:path';
import type { LiveCloudDiscoveryResult, CloudDiscoveryQueueOptions } from './types.js';
import { AwsConnector } from './aws/aws-connector.js';

export class CloudDiscoveryQueue {
  private readonly ttlMs: number;
  private readonly cacheFilePath: string;
  private inFlightPromise: Promise<LiveCloudDiscoveryResult> | null = null;

  constructor(options: CloudDiscoveryQueueOptions = {}) {
    const ttlMinutes = options.ttlMinutes ?? 15;
    this.ttlMs = ttlMinutes * 60 * 1000;
    this.cacheFilePath = options.cacheFilePath ?? path.resolve(process.cwd(), '.sec-arch/cache/cloud-live.json');
  }

  /**
   * Retrieves live cloud snapshot from cache if still fresh, otherwise triggers discovery.
   */
  public async getLiveSnapshot(
    connector: AwsConnector,
    tenantId: string = 'default-tenant',
    forceRefresh: boolean = false
  ): Promise<LiveCloudDiscoveryResult> {
    if (!forceRefresh) {
      const cached = this.readCache();
      if (cached && this.isFresh(cached)) {
        return cached;
      }
    }

    // Coalesce concurrent requests
    if (this.inFlightPromise) {
      return this.inFlightPromise;
    }

    this.inFlightPromise = (async () => {
      try {
        const liveData = await connector.fetchLiveState(tenantId);
        this.writeCache(liveData);
        return liveData;
      } finally {
        this.inFlightPromise = null;
      }
    })();

    return this.inFlightPromise;
  }

  public clearCache(): void {
    try {
      if (fs.existsSync(this.cacheFilePath)) {
        fs.unlinkSync(this.cacheFilePath);
      }
    } catch {
      // Ignored
    }
  }

  private readCache(): LiveCloudDiscoveryResult | null {
    try {
      if (!fs.existsSync(this.cacheFilePath)) return null;
      const content = fs.readFileSync(this.cacheFilePath, 'utf-8');
      const parsed = JSON.parse(content) as LiveCloudDiscoveryResult;
      return parsed;
    } catch {
      return null;
    }
  }

  private writeCache(result: LiveCloudDiscoveryResult): void {
    try {
      const dir = path.dirname(this.cacheFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(this.cacheFilePath, JSON.stringify(result, null, 2), 'utf-8');
    } catch (err) {
      // Disk write error shouldn't crash the scanner
    }
  }

  private isFresh(result: LiveCloudDiscoveryResult): boolean {
    if (!result.readTimestamp) return false;
    const age = Date.now() - new Date(result.readTimestamp).getTime();
    return age < this.ttlMs;
  }
}
