import { Asset, Finding, createEvidence } from '@ai-security-architect/core';
import { BreachCorrelationClient, BreachCorrelationConfig } from './breach-correlation-client.js';

export interface SecretLifecycleRecord {
  assetId: string;
  firstObservedAt: string; // ISO string
  lastObservedAt: string;  // ISO string
  lastRotatedAt?: string;  // ISO string
  observationCount: number;
  rotationCount: number;
  isCompromised?: boolean;
}

export interface SecretLifecycleOptions {
  maxAgeDays?: number; // default: 90 days
  breachCorrelation?: BreachCorrelationConfig;
  customFetch?: typeof fetch;
}

export interface SecretLifecycleSummary {
  assetId: string;
  name: string;
  ageDays: number;
  daysSinceLastRotation: number;
  isOverdue: boolean;
  isCompromised: boolean;
  sourceType: 'cloud-managed' | 'inferred-history';
}

export class SecretLifecycleTracker {
  private history: Map<string, SecretLifecycleRecord> = new Map();
  private maxAgeDays: number;
  private breachClient?: BreachCorrelationClient;

  constructor(options: SecretLifecycleOptions = {}) {
    this.maxAgeDays = options.maxAgeDays ?? 90;
    if (options.breachCorrelation?.enabled) {
      this.breachClient = new BreachCorrelationClient(
        options.breachCorrelation,
        options.customFetch
      );
    }
  }

  /**
   * Seed or restore historical observation records from SQLite store or previous state
   */
  seedHistory(records: SecretLifecycleRecord[]): void {
    for (const record of records) {
      this.history.set(record.assetId, { ...record });
    }
  }

  /**
   * Export internal historical records for SQLite persistence
   */
  exportHistory(): SecretLifecycleRecord[] {
    return Array.from(this.history.values());
  }

  /**
   * Evaluate secret-bearing assets across scan history, flag rotation overdue & breach status
   */
  async evaluateSecrets(
    assets: Asset[],
    scanTimestamp: Date = new Date()
  ): Promise<{ findings: Finding[]; summaries: SecretLifecycleSummary[] }> {
    const findings: Finding[] = [];
    const summaries: SecretLifecycleSummary[] = [];
    const scanIso = scanTimestamp.toISOString();

    const secretAssets = assets.filter(
      (a) => a.type === 'SECRET' || a.tags.includes('secret') || a.tags.includes('credential')
    );

    for (const asset of secretAssets) {
      // 1. Determine authoritative dates from cloud metadata if present, else fallback to scan history
      const meta = asset.metadata || {};
      const cloudCreatedDate = typeof meta.createdDate === 'string' ? new Date(meta.createdDate) : undefined;
      const cloudRotatedDate = typeof meta.lastRotatedDate === 'string' ? new Date(meta.lastRotatedDate) : undefined;

      let historyRecord = this.history.get(asset.id);
      if (!historyRecord) {
        historyRecord = {
          assetId: asset.id,
          firstObservedAt: cloudCreatedDate ? cloudCreatedDate.toISOString() : scanIso,
          lastObservedAt: scanIso,
          lastRotatedAt: cloudRotatedDate ? cloudRotatedDate.toISOString() : undefined,
          observationCount: 1,
          rotationCount: cloudRotatedDate ? 1 : 0,
        };
      } else {
        historyRecord.lastObservedAt = scanIso;
        historyRecord.observationCount += 1;
        if (cloudRotatedDate && (!historyRecord.lastRotatedAt || new Date(cloudRotatedDate) > new Date(historyRecord.lastRotatedAt))) {
          historyRecord.lastRotatedAt = cloudRotatedDate.toISOString();
          historyRecord.rotationCount += 1;
        }
      }
      this.history.set(asset.id, historyRecord);

      // Compute age and time since last rotation
      const baselineDate = cloudCreatedDate || new Date(historyRecord.firstObservedAt);
      const effectiveRotationDate = cloudRotatedDate || (historyRecord.lastRotatedAt ? new Date(historyRecord.lastRotatedAt) : baselineDate);

      const msPerDay = 1000 * 60 * 60 * 24;
      const ageDays = Math.max(0, Math.floor((scanTimestamp.getTime() - baselineDate.getTime()) / msPerDay));
      const daysSinceLastRotation = Math.max(
        0,
        Math.floor((scanTimestamp.getTime() - effectiveRotationDate.getTime()) / msPerDay)
      );

      const isOverdue = daysSinceLastRotation > this.maxAgeDays;
      let isCompromised = false;

      // 2. Check for rotation overdue
      if (isOverdue) {
        findings.push({
          id: `finding-rot-overdue-${asset.id}`,
          tenantId: asset.tenantId,
          assetId: asset.id,
          category: 'CREDENTIAL_ROTATION_OVERDUE',
          ruleId: 'SEC-LIFECYCLE-001',
          title: `Credential Rotation Overdue: ${asset.name} (${daysSinceLastRotation} days old)`,
          description: `Credential has been active for ${daysSinceLastRotation} days without rotation, exceeding the configured threshold of ${this.maxAgeDays} days. Note: This identifies an unrotated persistent credential, distinct from a fresh static secret exposure.`,
          severity: daysSinceLastRotation > this.maxAgeDays * 2 ? 'CRITICAL' : 'HIGH',
          confidence: cloudRotatedDate || cloudCreatedDate ? 'CERTAIN' : 'HIGH',
          scanner: 'secrets-lifecycle-tracker',
          evidence: createEvidence({
            id: `ev-rot-overdue-${asset.id}`,
            tenantId: asset.tenantId,
            sourceType: 'CLOUD_API',
            repository: 'infrastructure/secrets',
            filePath: `secrets://${asset.id}`,
            lineStart: 1,
            lineEnd: 1,
            snippet: `Asset ${asset.name} (${asset.id}) last rotated on ${effectiveRotationDate.toISOString()}; age: ${daysSinceLastRotation} days.`,
            scanner: 'secrets-lifecycle-tracker',
          }),
          remediationRecommendation: `Rotate the credential for ${asset.name} and update consuming workloads to use modern short-lived credentials or automated rotation.`,
          metadata: {
            daysSinceLastRotation,
            maxAgeDays: this.maxAgeDays,
            sourceType: cloudRotatedDate ? 'cloud-managed' : 'inferred-history',
          },
        });
      }

      // 3. Optional opt-in breach correlation
      const rawSecretValue = typeof meta.secretValue === 'string' ? meta.secretValue : undefined;
      if (this.breachClient && rawSecretValue) {
        try {
          const breachResult = await this.breachClient.checkSecret(rawSecretValue);
          if (breachResult.isCompromised) {
            isCompromised = true;
            historyRecord.isCompromised = true;
            findings.push({
              id: `finding-breach-${asset.id}`,
              tenantId: asset.tenantId,
              assetId: asset.id,
              category: 'COMPROMISED_CREDENTIAL',
              ruleId: 'SEC-LIFECYCLE-002',
              title: `Compromised Credential Detected: ${asset.name}`,
              description: `This credential matches a known publicly leaked credential in public breach databases (observed ${breachResult.occurrences} times). ${breachResult.sourceLabel}. Immediate revocation required.`,
              severity: 'CRITICAL',
              confidence: 'CERTAIN',
              scanner: 'breach-correlation-client',
              evidence: createEvidence({
                id: `ev-breach-${asset.id}`,
                tenantId: asset.tenantId,
                sourceType: 'SECRET_SCAN',
                repository: 'infrastructure/secrets',
                filePath: `breach-db://${breachResult.serviceQueried}`,
                lineStart: 1,
                lineEnd: 1,
                snippet: `K-Anonymity prefix ${breachResult.hashPrefixUsed} matched compromised credential database. Raw secret was never transmitted.`,
                scanner: 'breach-correlation-client',
              }),
              remediationRecommendation: `Immediately revoke ${asset.name} and investigate access logs for unauthorized utilization.`,
              metadata: {
                occurrences: breachResult.occurrences,
                hashPrefixUsed: breachResult.hashPrefixUsed,
                sourceLabel: breachResult.sourceLabel,
              },
            });
          }
        } catch {
          // Fail-safe: breach query failure does not block scanning
        }
      }

      summaries.push({
        assetId: asset.id,
        name: asset.name,
        ageDays,
        daysSinceLastRotation,
        isOverdue,
        isCompromised,
        sourceType: cloudCreatedDate || cloudRotatedDate ? 'cloud-managed' : 'inferred-history',
      });
    }

    return { findings, summaries };
  }
}
