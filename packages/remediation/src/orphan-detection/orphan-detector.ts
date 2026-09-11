import { Asset, Relationship, Finding, createEvidence } from '@ai-security-architect/core';
import {
  OrphanDetectionOptions,
  OrphanedAssetSummary,
  ORPHAN_OBSERVATION_DISCLAIMER,
} from './types.js';

export class OrphanDetector {
  private dormancyWindowDays: number;
  private costTable: Record<string, number>;

  constructor(options: OrphanDetectionOptions = {}) {
    this.dormancyWindowDays = options.dormancyWindowDays ?? 90;
    this.costTable = {
      LOAD_BALANCER: 25,
      DATABASE: 75,
      BUCKET: 15,
      CONTAINER: 30,
      IAM_ROLE: 0,
      SERVICE_ACCOUNT: 0,
      ...options.estimatedMonthlyCostTable,
    };
  }

  /**
   * Identifies orphaned cloud resources and dormant IAM access grants.
   * Emits findings with dual security attack surface and FinOps cost framing.
   */
  detectOrphans(
    assets: Asset[],
    relationships: Relationship[],
    now: Date = new Date()
  ): { findings: Finding[]; summaries: OrphanedAssetSummary[] } {
    const findings: Finding[] = [];
    const summaries: OrphanedAssetSummary[] = [];

    // Collect all asset IDs that have active operational relationships
    const activeAssetIds = new Set<string>();
    const operationalTypes = new Set([
      'ROUTES_TO',
      'CALLS',
      'READS_FROM',
      'WRITES_TO',
      'ASSUMES_ROLE',
      'RUNS_AS',
      'DEPLOYED_TO',
      'AUTHENTICATES_TO',
      'CAN_READ',
      'CAN_WRITE',
      'DATA_FLOW',
    ]);

    for (const rel of relationships) {
      if (operationalTypes.has(rel.type)) {
        activeAssetIds.add(rel.sourceAssetId);
        activeAssetIds.add(rel.targetAssetId);
      }
    }

    const msPerDay = 1000 * 60 * 60 * 24;

    for (const asset of assets) {
      // Exclude internet, repositories, or external vendor assets
      if (asset.type === 'INTERNET' || asset.type === 'REPOSITORY' || asset.type === 'VENDOR') {
        continue;
      }

      const meta = asset.metadata || {};
      const lastActivityStr =
        typeof meta.lastActivityDate === 'string'
          ? meta.lastActivityDate
          : typeof meta.lastUsedDate === 'string'
          ? meta.lastUsedDate
          : undefined;

      const creationDateStr = typeof meta.createdDate === 'string' ? meta.createdDate : undefined;

      let isDormant = false;
      let daysDormant = 0;

      if (lastActivityStr) {
        const lastAct = new Date(lastActivityStr);
        daysDormant = Math.max(0, Math.floor((now.getTime() - lastAct.getTime()) / msPerDay));
        // If activity was observed within the dormancy window, suppress flag!
        if (daysDormant > this.dormancyWindowDays) {
          isDormant = true;
        }
      } else {
        // No explicit last activity date recorded
        // If it has active operational relationships in the graph, it is NOT dormant
        if (!activeAssetIds.has(asset.id)) {
          // If creation date is known and older than window, or assumed dormant
          if (creationDateStr) {
            const created = new Date(creationDateStr);
            daysDormant = Math.max(0, Math.floor((now.getTime() - created.getTime()) / msPerDay));
            if (daysDormant > this.dormancyWindowDays) {
              isDormant = true;
            }
          } else {
            // Unattached in graph and unobserved
            daysDormant = this.dormancyWindowDays + 1;
            isDormant = true;
          }
        }
      }

      if (isDormant) {
        const monthlyWaste = this.costTable[asset.type] ?? 0;
        let riskDesc = `Dormant ${asset.type} with zero observed operational traffic in visibility window.`;
        if (asset.type === 'IAM_ROLE' || asset.type === 'SERVICE_ACCOUNT') {
          riskDesc = 'Unused privileged identity expands attack surface and presents an unmonitored lateral movement target.';
        } else if (asset.type === 'DATABASE' || asset.type === 'BUCKET') {
          riskDesc = 'Unreferenced persistent data store incurs ongoing storage costs and risks becoming unmonitored shadow data.';
        } else if (asset.type === 'LOAD_BALANCER') {
          riskDesc = 'Idle load balancer with no backend targets incurs monthly infrastructure costs and exposes orphan DNS entry.';
        }

        const summary: OrphanedAssetSummary = {
          assetId: asset.id,
          name: asset.name,
          type: asset.type,
          daysDormant,
          lastActivityDate: lastActivityStr,
          estimatedMonthlyWasteUsd: monthlyWaste,
          securityRiskDescription: riskDesc,
          observationDisclaimer: ORPHAN_OBSERVATION_DISCLAIMER,
        };
        summaries.push(summary);

        findings.push({
          id: `finding-orphan-${asset.id}`,
          tenantId: asset.tenantId,
          assetId: asset.id,
          category: 'ORPHANED_RESOURCE',
          ruleId: 'ORPHAN-CLEANUP-001',
          title: `Orphaned / Stale Resource: ${asset.name} (${daysDormant} days dormant)`,
          description: `${riskDesc} ${ORPHAN_OBSERVATION_DISCLAIMER}. Estimated FinOps monthly idle waste: $${monthlyWaste} USD.`,
          severity: asset.type === 'IAM_ROLE' || asset.criticality === 'CRITICAL' ? 'HIGH' : 'MEDIUM',
          confidence: 'MEDIUM', // Observation-based heuristic
          scanner: 'orphan-detector',
          evidence: createEvidence({
            id: `ev-orphan-${asset.id}`,
            tenantId: asset.tenantId,
            sourceType: 'CLOUD_API',
            repository: 'infrastructure/stale-resources',
            filePath: `cloud://${asset.id}`,
            lineStart: 1,
            lineEnd: 1,
            snippet: `Resource ${asset.name} (${asset.id}) has no observed traffic. Days dormant: ${daysDormant}. Estimated waste: $${monthlyWaste}/mo.`,
            scanner: 'orphan-detector',
          }),
          remediationRecommendation: `Review with resource owner. If truly defunct, decommission ${asset.name} to eliminate attack surface and save ~$${monthlyWaste}/month.`,
          metadata: {
            daysDormant,
            estimatedMonthlyWasteUsd: monthlyWaste,
            observationDisclaimer: ORPHAN_OBSERVATION_DISCLAIMER,
          },
        });
      }
    }

    return { findings, summaries };
  }
}
