import {
  PathClosureEvent,
  ChampionScoreEntry,
  ChampionLeaderboard,
} from './types.js';

export interface ChampionScoringOptions {
  allowIndividualAttribution?: boolean; // default: false (team-level default)
  minRemediationDurationMinutes?: number; // default: 60 minutes for trivial/low findings
  weights?: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
}

export class ChampionScoringEngine {
  private allowIndividual: boolean;
  private minDurationMinutes: number;
  private weights: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };

  constructor(options: ChampionScoringOptions = {}) {
    this.allowIndividual = options.allowIndividualAttribution ?? false;
    this.minDurationMinutes = options.minRemediationDurationMinutes ?? 60;
    this.weights = options.weights ?? {
      CRITICAL: 100,
      HIGH: 50,
      MEDIUM: 20,
      LOW: 5,
    };
  }

  /**
   * Evaluates closure events, detects gaming vectors, and produces an engagement leaderboard
   */
  generateLeaderboard(events: PathClosureEvent[]): ChampionLeaderboard {
    const scoresMap = new Map<string, ChampionScoreEntry>();
    let totalPointsAwarded = 0;
    let totalGamingDetections = 0;

    for (const ev of events) {
      const entityId = this.allowIndividual && ev.authorId ? ev.authorId : ev.teamId;
      const entityType = this.allowIndividual && ev.authorId ? 'INDIVIDUAL' : 'TEAM';

      if (!scoresMap.has(entityId)) {
        scoresMap.set(entityId, {
          entityId,
          entityType,
          totalPoints: 0,
          validRemediationsCount: 0,
          gamingExcludedCount: 0,
          assetRemovedCount: 0,
          breakdown: { critical: 0, high: 0, medium: 0, low: 0 },
          tierBadge: 'Contributor',
        });
      }

      const entry = scoresMap.get(entityId)!;

      // 1. Guardrail: asset-removed or suppressed closures NEVER award points
      if (ev.closureReason !== 'remediated') {
        if (ev.closureReason === 'asset-removed') {
          entry.assetRemovedCount += 1;
        }
        continue;
      }

      // 2. Anti-Gaming Guardrail: Detect rapid introduce-then-close cycle on trivial/low findings
      const introTime = new Date(ev.introducedAt).getTime();
      const closeTime = new Date(ev.closedAt).getTime();
      const durationMinutes = Math.max(0, (closeTime - introTime) / (1000 * 60));

      if (ev.severity === 'LOW' && durationMinutes < this.minDurationMinutes) {
        // Suspicious churn / gaming pattern detected!
        entry.gamingExcludedCount += 1;
        totalGamingDetections += 1;
        continue;
      }

      // 3. Award genuine severity-weighted points
      const points = this.weights[ev.severity] ?? 0;
      entry.totalPoints += points;
      entry.validRemediationsCount += 1;
      totalPointsAwarded += points;

      if (ev.severity === 'CRITICAL') entry.breakdown.critical += 1;
      else if (ev.severity === 'HIGH') entry.breakdown.high += 1;
      else if (ev.severity === 'MEDIUM') entry.breakdown.medium += 1;
      else if (ev.severity === 'LOW') entry.breakdown.low += 1;
    }

    // Assign Tier Badges based on total points
    const rankings = Array.from(scoresMap.values()).map((entry) => {
      let tierBadge = 'Contributor';
      if (entry.totalPoints >= 300) tierBadge = 'Grandmaster Security Champion';
      else if (entry.totalPoints >= 150) tierBadge = 'Master Security Champion';
      else if (entry.totalPoints >= 50) tierBadge = 'Rising Security Champion';

      return {
        ...entry,
        tierBadge,
      };
    });

    // Sort descending by total points
    rankings.sort((a, b) => b.totalPoints - a.totalPoints);

    return {
      generatedAt: new Date().toISOString(),
      attributionLevel: this.allowIndividual ? 'INDIVIDUAL' : 'TEAM',
      totalPointsAwarded,
      totalGamingDetections,
      rankings,
    };
  }
}
