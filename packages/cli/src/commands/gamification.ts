import { ChampionScoringEngine, PathClosureEvent } from '@ai-security-architect/engagement';

export async function executeGamification(options: {
  allowIndividual?: boolean;
}): Promise<void> {
  const engine = new ChampionScoringEngine({ allowIndividualAttribution: options.allowIndividual });
  const sampleEvents: PathClosureEvent[] = [
    {
      pathId: 'path-001',
      severity: 'CRITICAL',
      closureReason: 'remediated',
      introducedAt: '2026-08-01T10:00:00Z',
      closedAt: '2026-08-05T12:00:00Z',
      teamId: 'core-platform',
      authorId: 'eng-1@corp.internal',
    },
    {
      pathId: 'path-002',
      severity: 'HIGH',
      closureReason: 'remediated',
      introducedAt: '2026-08-02T10:00:00Z',
      closedAt: '2026-08-04T12:00:00Z',
      teamId: 'core-platform',
      authorId: 'eng-2@corp.internal',
    },
  ];

  const board = engine.generateLeaderboard(sampleEvents);
  console.log('\n=== Security Champion Engagement Leaderboard ===');
  console.log(`Attribution Level: ${board.attributionLevel}`);
  console.log(`Total Points Awarded: ${board.totalPointsAwarded}`);
  for (const r of board.rankings) {
    console.log(`- [${r.tierBadge}] ${r.entityId} — ${r.totalPoints} pts (${r.validRemediationsCount} fixes)`);
  }
}
