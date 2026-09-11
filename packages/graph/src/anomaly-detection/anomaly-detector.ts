import type { AssetBaselineStore } from './asset-baseline-store.js';
import type {
  AnomalyDetectorConfig,
  AnomalyEvaluationResult,
  CurrentAssetChange,
} from './types.js';

export class AnomalyDetector {
  private baselineStore: AssetBaselineStore;
  private config: Required<AnomalyDetectorConfig>;

  constructor(baselineStore: AssetBaselineStore, config: AnomalyDetectorConfig = {}) {
    this.baselineStore = baselineStore;
    this.config = {
      minScansThreshold: config.minScansThreshold ?? 3,
      zScoreThreshold: config.zScoreThreshold ?? 2.0,
      wildcardAnomalyScore: config.wildcardAnomalyScore ?? 8.5,
    };
  }

  public evaluateChange(change: CurrentAssetChange): AnomalyEvaluationResult {
    const assetId = change.asset.id;
    const assetName = change.asset.name;
    const baseline = this.baselineStore.getBaseline(assetId);

    const currentMagnitude = change.newPermissions.length + change.removedPermissions.length;
    const hasWildcard = change.newPermissions.some((p) => p.endsWith(':*') || p === '*');

    // 1. Cold start guardrail
    const scansObserved = baseline?.totalScansObserved ?? 0;
    if (!baseline || scansObserved < this.config.minScansThreshold) {
      return {
        assetId,
        assetName,
        status: 'INSUFFICIENT_HISTORY',
        anomalyScore: 0.0,
        explanation: `Insufficient scan history to evaluate baseline (${scansObserved} scan(s) observed, minimum required: ${this.config.minScansThreshold}). Anomaly evaluation suppressed to prevent false alerts.`,
        baselineSummary: {
          scansObserved,
          changeFrequencyPercentage: 0,
          typicalChangeMagnitude: 0,
        },
      };
    }

    const changeFreqPct = Math.round(baseline.changeFrequency * 100);
    const mean = baseline.meanPermissionsChanged;
    const stdDev = baseline.stdDevPermissionsChanged;

    const baselineSummary = {
      scansObserved: baseline.totalScansObserved,
      changeFrequencyPercentage: changeFreqPct,
      typicalChangeMagnitude: mean,
    };

    // 2. Zero changes
    if (currentMagnitude === 0 && !change.exposureChanged && change.newRelationshipsCount === 0) {
      return {
        assetId,
        assetName,
        status: 'NORMAL',
        anomalyScore: 0.0,
        explanation: `No configuration or permission changes detected for asset '${assetName}'.`,
        baselineSummary,
      };
    }

    // 3. Check for Anomalies
    // A: Sudden spike on historically stable asset (0 or near 0 changes in history)
    const isHistoricallyStable = baseline.totalChangeEventsCount === 0 || baseline.changeFrequency <= 0.15;
    if (isHistoricallyStable && currentMagnitude > 0) {
      const wildcardNote = hasWildcard ? " including wildcard grant ('*')" : '';
      const anomalyScore = hasWildcard ? this.config.wildcardAnomalyScore : 7.5;
      const severity = hasWildcard ? 'CRITICAL' : 'HIGH';

      return {
        assetId,
        assetName,
        status: 'ANOMALY_DETECTED',
        anomalyScore,
        severity,
        explanation: `Asset '${assetName}' has had 0 permission changes in ${baseline.totalScansObserved} previous scans; this scan introduces ${change.newPermissions.length} new permission(s)${wildcardNote}. Anomaly: sudden permission spike on historically stable asset.`,
        baselineSummary,
      };
    }

    // B: Wildcard grant on asset that never had wildcard grants
    if (hasWildcard && !baseline.hasHistoricalWildcardGrant) {
      return {
        assetId,
        assetName,
        status: 'ANOMALY_DETECTED',
        anomalyScore: this.config.wildcardAnomalyScore,
        severity: 'CRITICAL',
        explanation: `Asset '${assetName}' introduces a broad wildcard permission (${change.newPermissions
          .filter((p) => p.endsWith(':*') || p === '*')
          .join(', ')}). No wildcard permissions have ever been observed across ${baseline.totalScansObserved} historical scans.`,
        baselineSummary,
      };
    }

    // C: Statistical magnitude anomaly (Z-Score > threshold)
    if (stdDev > 0) {
      const zScore = (currentMagnitude - mean) / stdDev;
      if (zScore >= this.config.zScoreThreshold) {
        return {
          assetId,
          assetName,
          status: 'ANOMALY_DETECTED',
          anomalyScore: Math.min(9.5, Number((5.0 + zScore * 1.5).toFixed(1))),
          severity: 'HIGH',
          explanation: `Asset '${assetName}' changed ${currentMagnitude} permissions in this scan (historical average: ${mean} ± ${stdDev}, z-score: ${zScore.toFixed(
            1
          )}). Anomaly: change magnitude exceeds statistical baseline threshold (${this.config.zScoreThreshold}σ).`,
          baselineSummary,
        };
      }
    }

    // D: Regular established churn pattern
    return {
      assetId,
      assetName,
      status: 'NORMAL',
      anomalyScore: 1.5,
      explanation: `Asset '${assetName}' changed ${currentMagnitude} permissions. This conforms to its established churn pattern (observed in ${changeFreqPct}% of scans, historical mean: ${mean}).`,
      baselineSummary,
    };
  }
}
