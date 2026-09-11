import type { Finding } from '@ai-security-architect/core';

export interface CisaKevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: 'Known' | 'Unknown';
  notes?: string;
}

export interface EpssEntry {
  cve: string;
  epss: number; // 0.0 to 1.0
  percentile: number; // 0.0 to 1.0
  date?: string;
}

export interface ThreatIntelCacheData {
  lastFetchedAt: string; // ISO timestamp
  kevCatalog: Record<string, CisaKevEntry>;
  epssScores: Record<string, EpssEntry>;
}

export interface ThreatIntelConfig {
  cacheFilePath?: string;
  stalenessThresholdDays?: number; // default: 7
  customKevFeedUrl?: string;
  customEpssFeedUrl?: string;
}

export interface EnrichedFinding extends Finding {
  threatIntel: {
    isKevExploited: boolean;
    cisaKevDetails?: CisaKevEntry;
    epssScore?: number;
    epssPercentile?: number;
    prioritizationOverride: boolean;
    adjustedRankScore: number;
    explanation?: string;
  };
}

export interface ThreatIntelEnrichmentResult {
  enrichedFindings: EnrichedFinding[];
  prioritizedKevCount: number;
  highEpssCount: number;
  cacheMetadata: {
    lastFetchedAt: string;
    isStale: boolean;
    cacheAgeDays: number;
    warning?: string;
  };
}
