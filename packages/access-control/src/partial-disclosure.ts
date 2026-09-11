import type { Asset, AttackPath, AttackStep } from '@ai-security-architect/core';
import type { ScopedPathRedactionResult, UserScope } from './types.js';

export class PartialDisclosurePolicy {
  public static canAccessAsset(scope: UserScope, asset: Asset): boolean {
    // 1. Tenant boundary enforcement
    if (asset.tenantId !== scope.tenantId) {
      return false;
    }

    // 2. Full Admin access within tenant
    if (scope.role === 'ADMIN') {
      return true;
    }

    // 3. Environment restriction
    if (
      scope.allowedEnvironments &&
      scope.allowedEnvironments.length > 0 &&
      !scope.allowedEnvironments.includes(asset.environment)
    ) {
      return false;
    }

    // 4. Specific Asset ID whitelist
    if (scope.allowedAssetIds && scope.allowedAssetIds.includes(asset.id)) {
      return true;
    }

    // 5. Team / Ownership boundary restriction
    if (scope.allowedTeams && scope.allowedTeams.length > 0) {
      const assetTeamTag = asset.tags.find((t) =>
        scope.allowedTeams!.some((team) => t === team || t === `team:${team}`)
      );
      const assetMetadataTeam =
        typeof asset.metadata?.team === 'string' &&
        scope.allowedTeams.includes(asset.metadata.team as string);

      if (!assetTeamTag && !assetMetadataTeam) {
        return false;
      }
    }

    return true;
  }

  public static redactCrossBoundaryAttackPath(
    scope: UserScope,
    path: AttackPath,
    getAsset: (id: string) => Asset | undefined
  ): ScopedPathRedactionResult {
    // Check if the user has legitimate access to ANY asset along this path
    const assetsAlongPath = new Set<string>();
    for (const step of path.steps) {
      assetsAlongPath.add(step.sourceAssetId);
      assetsAlongPath.add(step.targetAssetId);
    }

    let touchesUserScope = false;
    for (const assetId of assetsAlongPath) {
      const asset = getAsset(assetId);
      if (asset && this.canAccessAsset(scope, asset)) {
        touchesUserScope = true;
        break;
      }
    }

    // If no part of the attack path touches the user's scope, complete denial
    if (!touchesUserScope) {
      return {
        path: null,
        hasRedactions: false,
        redactedStepIndices: [],
      };
    }

    // Path touches user's perimeter: apply partial disclosure redactions to foreign steps
    const redactedStepIndices: number[] = [];
    const sanitizedSteps: AttackStep[] = [];

    for (let i = 0; i < path.steps.length; i++) {
      const step = path.steps[i];
      const sourceAsset = getAsset(step.sourceAssetId);
      const targetAsset = getAsset(step.targetAssetId);

      const canAccessSource = sourceAsset ? this.canAccessAsset(scope, sourceAsset) : false;
      const canAccessTarget = targetAsset ? this.canAccessAsset(scope, targetAsset) : false;

      if (canAccessSource && canAccessTarget) {
        // Both nodes inside user's scope: full detail
        sanitizedSteps.push({ ...step });
      } else {
        // Cross-boundary hop: redact foreign details
        redactedStepIndices.push(i);

        let redactedScope = 'EXTERNAL_RESOURCE';
        if (
          (sourceAsset && sourceAsset.tenantId !== scope.tenantId) ||
          (targetAsset && targetAsset.tenantId !== scope.tenantId)
        ) {
          redactedScope = 'EXTERNAL_TENANT';
        } else if (
          (sourceAsset && scope.allowedEnvironments && !scope.allowedEnvironments.includes(sourceAsset.environment)) ||
          (targetAsset && scope.allowedEnvironments && !scope.allowedEnvironments.includes(targetAsset.environment))
        ) {
          redactedScope = 'EXTERNAL_ENVIRONMENT';
        }

        const sourceId = canAccessSource ? step.sourceAssetId : '[REDACTED_CROSS_BOUNDARY_ASSET]';
        const targetId = canAccessTarget ? step.targetAssetId : '[REDACTED_CROSS_BOUNDARY_ASSET]';

        sanitizedSteps.push({
          ...step,
          sourceAssetId: sourceId,
          targetAssetId: targetId,
          explanation: '[CROSS_BOUNDARY_REDACTED] Redacted external hop traversing outside user security scope',
          isCrossBoundaryRedacted: true,
          redactedScope,
          findingId: undefined,
          evidenceRef: undefined,
        });
      }
    }

    const entryAsset = getAsset(path.entryAssetId);
    const targetAsset = getAsset(path.targetAssetId);

    const redactedPath: AttackPath = {
      ...path,
      entryAssetId: entryAsset && this.canAccessAsset(scope, entryAsset)
        ? path.entryAssetId
        : '[REDACTED_CROSS_BOUNDARY_ENTRY]',
      targetAssetId: targetAsset && this.canAccessAsset(scope, targetAsset)
        ? path.targetAssetId
        : '[REDACTED_CROSS_BOUNDARY_TARGET]',
      steps: sanitizedSteps,
    };

    return {
      path: redactedPath,
      hasRedactions: redactedStepIndices.length > 0,
      redactedStepIndices,
    };
  }
}
