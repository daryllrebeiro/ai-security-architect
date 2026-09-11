import type { ChatMessageResponse, ChatOpsScanSummaryPayload } from '../types.js';

export class ChatOpsSummaryPoster {
  public static formatScanSummary(payload: ChatOpsScanSummaryPayload): ChatMessageResponse {
    const isCritical = payload.topRiskScore >= 8.5;
    const headerEmoji = isCritical ? '🚨' : '🛡️';

    const text = [
      `${headerEmoji} *Scan Completed: ${payload.repository}*`,
      `• *Commit*: \`${payload.commitSha.substring(0, 7)}\` (${payload.branch})`,
      `• *Attack Paths Detected*: ${payload.attackPathsCount}`,
      `• *Top Risk Score*: ${payload.topRiskScore.toFixed(1)} / 10.0`,
      `• *Target Assets at Risk*: ${payload.criticalAssetsAtRisk.join(', ') || 'None'}`,
      payload.recommendedChokePoint
        ? `• *Recommended Choke Point*: ${payload.recommendedChokePoint}`
        : '',
      '',
      `_Tenant ID: ${payload.tenantId} | Timestamp: ${payload.timestamp}_`,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      text,
    };
  }
}
