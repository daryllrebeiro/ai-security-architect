import type {
  CisaKevEntry,
  EpssEntry,
  ThreatIntelCacheData,
  ThreatIntelConfig,
} from './types.js';

export class ThreatIntelClient {
  private cache: ThreatIntelCacheData;
  private readonly stalenessThresholdDays: number;

  constructor(
    initialCache?: Partial<ThreatIntelCacheData>,
    config: ThreatIntelConfig = {}
  ) {
    this.stalenessThresholdDays = config.stalenessThresholdDays ?? 7;
    this.cache = {
      lastFetchedAt: initialCache?.lastFetchedAt ?? new Date().toISOString(),
      kevCatalog: initialCache?.kevCatalog ?? {},
      epssScores: initialCache?.epssScores ?? {},
    };
  }

  public getCacheData(): ThreatIntelCacheData {
    return this.cache;
  }

  public updateCache(data: Partial<ThreatIntelCacheData>): void {
    this.cache = {
      lastFetchedAt: data.lastFetchedAt ?? new Date().toISOString(),
      kevCatalog: data.kevCatalog ?? this.cache.kevCatalog,
      epssScores: data.epssScores ?? this.cache.epssScores,
    };
  }

  public checkStaleness(now: Date = new Date()): {
    isStale: boolean;
    cacheAgeDays: number;
    lastFetchedAt: string;
    warning?: string;
  } {
    const fetchedTime = new Date(this.cache.lastFetchedAt).getTime();
    const currentTime = now.getTime();
    const ageMs = Math.max(0, currentTime - fetchedTime);
    const cacheAgeDays = Number((ageMs / (1000 * 60 * 60 * 24)).toFixed(1));

    const isStale = cacheAgeDays > this.stalenessThresholdDays;
    let warning: string | undefined = undefined;

    if (isStale) {
      warning = `[WARNING] Threat intelligence cache is ${cacheAgeDays} days old (configured staleness threshold: ${this.stalenessThresholdDays} days). Active exploit catalog may be out of date.`;
    }

    return {
      isStale,
      cacheAgeDays,
      lastFetchedAt: this.cache.lastFetchedAt,
      warning,
    };
  }

  public lookupKev(cve: string): CisaKevEntry | undefined {
    const cleanCve = cve.trim().toUpperCase();
    return this.cache.kevCatalog[cleanCve];
  }

  public lookupEpss(cve: string): EpssEntry | undefined {
    const cleanCve = cve.trim().toUpperCase();
    return this.cache.epssScores[cleanCve];
  }
}
