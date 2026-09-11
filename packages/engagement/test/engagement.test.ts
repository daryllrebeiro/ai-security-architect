import { describe, it, expect } from 'vitest';
import {
  ChampionScoringEngine,
  PathClosureEvent,
} from '../src/index.js';

describe('Task I.2: Security Champion Gamification & Engagement Program', () => {
  it('awards points for genuine severity-weighted remediations and zero for asset-removed closures', () => {
    const engine = new ChampionScoringEngine({ allowIndividualAttribution: false });

    const events: PathClosureEvent[] = [
      // 1. Critical remediation (100 pts)
      {
        pathId: 'path-crit-001',
        severity: 'CRITICAL',
        closureReason: 'remediated',
        introducedAt: '2026-08-01T10:00:00Z',
        closedAt: '2026-08-05T15:30:00Z',
        teamId: 'checkout-team',
      },
      // 2. High remediation (50 pts)
      {
        pathId: 'path-high-002',
        severity: 'HIGH',
        closureReason: 'remediated',
        introducedAt: '2026-08-02T10:00:00Z',
        closedAt: '2026-08-04T12:00:00Z',
        teamId: 'checkout-team',
      },
      // 3. Asset removed closure (0 pts)
      {
        pathId: 'path-med-removed',
        severity: 'MEDIUM',
        closureReason: 'asset-removed',
        introducedAt: '2026-08-01T10:00:00Z',
        closedAt: '2026-08-10T10:00:00Z',
        teamId: 'checkout-team',
      },
    ];

    const leaderboard = engine.generateLeaderboard(events);

    expect(leaderboard.attributionLevel).toBe('TEAM');
    expect(leaderboard.rankings.length).toBe(1);

    const checkoutRank = leaderboard.rankings[0];
    expect(checkoutRank.entityId).toBe('checkout-team');
    expect(checkoutRank.totalPoints).toBe(150); // 100 + 50
    expect(checkoutRank.validRemediationsCount).toBe(2);
    expect(checkoutRank.assetRemovedCount).toBe(1);
    expect(checkoutRank.tierBadge).toBe('Master Security Champion');
  });

  it('detects and excludes rapid introduce-then-close gaming pattern on trivial findings', () => {
    const engine = new ChampionScoringEngine();

    const events: PathClosureEvent[] = [
      // Normal remediation (Medium, 2 days: 20 pts)
      {
        pathId: 'path-valid-med',
        severity: 'MEDIUM',
        closureReason: 'remediated',
        introducedAt: '2026-08-01T10:00:00Z',
        closedAt: '2026-08-03T10:00:00Z',
        teamId: 'growth-team',
      },
      // Gaming attempt: Low severity introduced and closed in 5 minutes!
      {
        pathId: 'path-gaming-low-1',
        severity: 'LOW',
        closureReason: 'remediated',
        introducedAt: '2026-08-03T10:00:00Z',
        closedAt: '2026-08-03T10:05:00Z',
        teamId: 'growth-team',
      },
      // Gaming attempt: Another low severity closed in 12 minutes!
      {
        pathId: 'path-gaming-low-2',
        severity: 'LOW',
        closureReason: 'remediated',
        introducedAt: '2026-08-03T11:00:00Z',
        closedAt: '2026-08-03T11:12:00Z',
        teamId: 'growth-team',
      },
    ];

    const leaderboard = engine.generateLeaderboard(events);

    expect(leaderboard.totalGamingDetections).toBe(2);
    const growthRank = leaderboard.rankings[0];
    expect(growthRank.gamingExcludedCount).toBe(2);
    expect(growthRank.validRemediationsCount).toBe(1);
    expect(growthRank.totalPoints).toBe(20); // Only valid medium counted! Gaming lows awarded 0.
  });

  it('defaults to team-level attribution and enables individual attribution only when opt-in is configured', () => {
    const events: PathClosureEvent[] = [
      {
        pathId: 'path-1',
        severity: 'HIGH',
        closureReason: 'remediated',
        introducedAt: '2026-08-01T10:00:00Z',
        closedAt: '2026-08-02T10:00:00Z',
        teamId: 'platform-team',
        authorId: 'alice@corp.internal',
      },
      {
        pathId: 'path-2',
        severity: 'HIGH',
        closureReason: 'remediated',
        introducedAt: '2026-08-01T10:00:00Z',
        closedAt: '2026-08-02T10:00:00Z',
        teamId: 'platform-team',
        authorId: 'bob@corp.internal',
      },
    ];

    // Default: Team level
    const teamEngine = new ChampionScoringEngine();
    const teamBoard = teamEngine.generateLeaderboard(events);
    expect(teamBoard.attributionLevel).toBe('TEAM');
    expect(teamBoard.rankings.length).toBe(1);
    expect(teamBoard.rankings[0].entityId).toBe('platform-team');
    expect(teamBoard.rankings[0].totalPoints).toBe(100);

    // Opt-in: Individual level
    const indEngine = new ChampionScoringEngine({ allowIndividualAttribution: true });
    const indBoard = indEngine.generateLeaderboard(events);
    expect(indBoard.attributionLevel).toBe('INDIVIDUAL');
    expect(indBoard.rankings.length).toBe(2);
    expect(indBoard.rankings.map((r) => r.entityId)).toEqual(['alice@corp.internal', 'bob@corp.internal']);
    expect(indBoard.rankings[0].totalPoints).toBe(50);
  });
});
