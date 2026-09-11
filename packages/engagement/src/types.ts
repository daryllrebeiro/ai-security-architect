export interface PathClosureEvent {
  pathId: string;
  findingId?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  closureReason: 'remediated' | 'asset-removed' | 'suppressed';
  introducedAt: string; // ISO string
  closedAt: string;     // ISO string
  teamId: string;
  authorId?: string;
}

export interface ChampionScoreEntry {
  entityId: string; // teamId or authorId
  entityType: 'TEAM' | 'INDIVIDUAL';
  totalPoints: number;
  validRemediationsCount: number;
  gamingExcludedCount: number;
  assetRemovedCount: number;
  breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  tierBadge: string;
}

export interface ChampionLeaderboard {
  generatedAt: string;
  attributionLevel: 'TEAM' | 'INDIVIDUAL';
  totalPointsAwarded: number;
  totalGamingDetections: number;
  rankings: ChampionScoreEntry[];
}
