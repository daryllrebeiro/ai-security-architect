import type { Finding, CloudAsset } from '@ai-security-architect/core';
import { createEvidence } from '@ai-security-architect/core';
import type { SecurityGraphEngine, CloudDriftResult } from '@ai-security-architect/graph';

export interface DriftDetectionOutput {
  driftResult: CloudDriftResult;
  findings: Finding[];
}

export class DriftDetector {
  public detectDrift(
    declaredGraph: SecurityGraphEngine,
    liveGraph: SecurityGraphEngine
  ): DriftDetectionOutput {
    // 1. Calculate structural and attribute drift
    // SecurityGraphEngine.diffCloudDrift is a static method
    const diffFn = (declaredGraph.constructor as typeof SecurityGraphEngine).diffCloudDrift;
    const driftResult = diffFn(declaredGraph, liveGraph);
    const findings: Finding[] = [];

    // 2. Synthesize findings for shadow resources (onlyInLive)
    for (const rawShadowAsset of driftResult.onlyInLive) {
      const shadowAsset = rawShadowAsset as Partial<CloudAsset>;
      const isCritical =
        shadowAsset.isSensitiveData ||
        shadowAsset.criticality === 'CRITICAL' ||
        (shadowAsset.isPublic && shadowAsset.type === 'BUCKET');

      const findingId = `drift-shadow-${shadowAsset.id}`;
      findings.push({
        id: findingId,
        tenantId: shadowAsset.tenantId ?? 'default-tenant',
        assetId: shadowAsset.id ?? 'unknown-asset',
        category: 'SHADOW_RESOURCE',
        ruleId: 'CLOUD-SHADOW-001',
        title: `Shadow Cloud Resource Detected: ${shadowAsset.name}`,
        description: `Resource '${shadowAsset.name}' of type '${shadowAsset.type}' exists in live AWS account (${shadowAsset.cloudArnOrId || shadowAsset.id}) but has no corresponding declaration in infrastructure-as-code.`,
        severity: isCritical ? 'CRITICAL' : 'HIGH',
        confidence: 'CERTAIN',
        scanner: 'cloud-drift-detector',
        evidence: createEvidence({
          id: `ev-${findingId}`,
          tenantId: shadowAsset.tenantId ?? 'default-tenant',
          sourceType: 'CLOUD_API',
          repository: 'live-cloud',
          filePath: shadowAsset.cloudArnOrId || shadowAsset.id || 'unknown',
          lineStart: 1,
          lineEnd: 1,
          snippet: `Live asset: ${shadowAsset.name} (${shadowAsset.type}) [Provider: ${shadowAsset.cloudProvider || 'AWS'}]`,
          scanner: 'cloud-drift-detector',
        }),
        remediationRecommendation: `Import '${shadowAsset.name}' into your Terraform or CloudFormation codebase, or terminate the untracked resource if obsolete.`,
        metadata: {
          assetType: shadowAsset.type,
          cloudArnOrId: shadowAsset.cloudArnOrId,
          region: shadowAsset.region,
          source: shadowAsset.source,
        },
      });
    }

    // 3. Synthesize findings for configuration drift
    for (const configItem of driftResult.configDrift) {
      const publicExposureDrift = configItem.differences.some(
        (d) => d.property === 'isPublic' && d.liveValue === true
      );

      const findingId = `drift-config-${configItem.assetId}`;
      const diffSummary = configItem.differences
        .map((d) => `• ${d.property}: declared=${JSON.stringify(d.declaredValue)} vs live=${JSON.stringify(d.liveValue)}`)
        .join('\n');

      findings.push({
        id: findingId,
        tenantId: configItem.liveAsset.tenantId,
        assetId: configItem.assetId,
        category: 'CLOUD_DRIFT',
        ruleId: 'CLOUD-DRIFT-001',
        title: `Security Configuration Drift: ${configItem.declaredAsset.name}`,
        description: `Live cloud configuration diverges from declared IaC for '${configItem.declaredAsset.name}':\n${diffSummary}`,
        severity: publicExposureDrift ? 'CRITICAL' : 'HIGH',
        confidence: 'CERTAIN',
        scanner: 'cloud-drift-detector',
        evidence: createEvidence({
          id: `ev-${findingId}`,
          tenantId: configItem.liveAsset.tenantId,
          sourceType: 'CLOUD_API',
          repository: 'live-cloud',
          filePath: (configItem.liveAsset as Partial<CloudAsset>).cloudArnOrId || configItem.assetId,
          lineStart: 1,
          lineEnd: 1,
          snippet: diffSummary,
          scanner: 'cloud-drift-detector',
        }),
        remediationRecommendation: publicExposureDrift
          ? `CRITICAL: The resource '${configItem.declaredAsset.name}' is publicly accessible in live AWS but declared private in IaC. Enable AWS S3 Public Access Block immediately.`
          : `Reconcile the configuration drift by applying updated IaC or updating live configuration.`,
        metadata: {
          differences: configItem.differences,
          declaredAsset: configItem.declaredAsset,
          liveAsset: configItem.liveAsset,
        },
      });
    }

    // 4. Attach findings to liveGraph so attack-path engine can traverse them
    for (const finding of findings) {
      if (liveGraph.hasNode(finding.assetId)) {
        liveGraph.attachFinding(finding);
      }
    }

    return {
      driftResult,
      findings,
    };
  }
}
