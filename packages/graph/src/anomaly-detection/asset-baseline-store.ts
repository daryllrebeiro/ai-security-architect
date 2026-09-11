import type {
  AssetBaseline,
  AssetHistoricalChangeRecord,
} from './types.js';

export class AssetBaselineStore {
  private baselines = new Map<string, AssetBaseline>();

  public recordScanEvent(
    assetId: string,
    changeRecord?: AssetHistoricalChangeRecord
  ): void {
    const existing = this.baselines.get(assetId) ?? {
      assetId,
      totalScansObserved: 0,
      totalChangeEventsCount: 0,
      changeFrequency: 0,
      meanPermissionsChanged: 0,
      stdDevPermissionsChanged: 0,
      hasHistoricalWildcardGrant: false,
      changeHistory: [],
    };

    existing.totalScansObserved += 1;

    if (changeRecord) {
      existing.totalChangeEventsCount += 1;
      existing.changeHistory.push(changeRecord);
      if (changeRecord.hasWildcardGrant) {
        existing.hasHistoricalWildcardGrant = true;
      }
    }

    // Recompute statistics
    existing.changeFrequency =
      existing.totalScansObserved > 0
        ? Number((existing.totalChangeEventsCount / existing.totalScansObserved).toFixed(2))
        : 0;

    const magnitudes = existing.changeHistory.map(
      (c) => c.permissionsAddedCount + c.permissionsRemovedCount
    );

    if (magnitudes.length > 0) {
      const sum = magnitudes.reduce((a, b) => a + b, 0);
      const mean = sum / magnitudes.length;
      existing.meanPermissionsChanged = Number(mean.toFixed(2));

      const variance =
        magnitudes.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / magnitudes.length;
      existing.stdDevPermissionsChanged = Number(Math.sqrt(variance).toFixed(2));
    }

    this.baselines.set(assetId, existing);
  }

  public getBaseline(assetId: string): AssetBaseline | undefined {
    return this.baselines.get(assetId);
  }

  public setBaseline(baseline: AssetBaseline): void {
    this.baselines.set(baseline.assetId, baseline);
  }
}
