import type {
  PermissionInferenceResult,
  PolicyRightSizingOptions,
  PolicyRightSizingRecommendation,
} from './types.js';

export class PolicyRightSizer {
  public static recommend(
    options: PolicyRightSizingOptions,
    inference: PermissionInferenceResult
  ): PolicyRightSizingRecommendation {
    const minConfidence = options.minConfidenceThreshold ?? 0.7;
    const confidenceScore = inference.observability.observabilityScore;

    // 1. Check confidence / dynamic dispatch safety guardrail
    if (confidenceScore < minConfidence || (inference.observability.hasDynamicDispatch && confidenceScore < 0.8)) {
      return {
        policyId: options.policyId,
        status: 'DECLINED_LOW_CONFIDENCE',
        confidenceScore,
        grantedActionsCount: options.grantedActions.length,
        exercisedActionsCount: inference.exercisedActions.length,
        retainedActions: [...options.grantedActions],
        removedActions: [],
        explanation: `Right-sizing recommendation declined due to low observability confidence (${Math.round(
          confidenceScore * 100
        )}% < ${Math.round(
          minConfidence * 100
        )}%). ${inference.observability.dynamicPatternsDetectedCount} dynamic dispatch / reflection patterns detected in workload code. Inferred permissions may be incomplete, risking runtime breakage if scoped automatically.`,
        isProvisional: true,
      };
    }

    // 2. Identify retained vs unexercised actions
    const exercisedSet = new Set(inference.exercisedActions.map((a) => a.toLowerCase()));
    const retainedActions: string[] = [];
    const removedActions: string[] = [];

    for (const granted of options.grantedActions) {
      if (exercisedSet.has(granted.toLowerCase())) {
        retainedActions.push(granted);
      } else {
        removedActions.push(granted);
      }
    }

    if (removedActions.length === 0) {
      return {
        policyId: options.policyId,
        status: 'ALREADY_LEAST_PRIVILEGE',
        confidenceScore,
        grantedActionsCount: options.grantedActions.length,
        exercisedActionsCount: inference.exercisedActions.length,
        retainedActions,
        removedActions: [],
        explanation: 'All granted actions are statically exercised by workload code. Policy is already least-privilege.',
        isProvisional: true,
      };
    }

    // 3. Generate unified diff
    const unifiedDiff = this.generatePolicyDiff(
      options.policyFilePath,
      options.policyDocument,
      options.grantedActions,
      retainedActions
    );

    return {
      policyId: options.policyId,
      status: 'RECOMMENDED',
      confidenceScore,
      grantedActionsCount: options.grantedActions.length,
      exercisedActionsCount: inference.exercisedActions.length,
      retainedActions,
      removedActions,
      unifiedDiff,
      explanation: `Proposed scoping down policy '${options.policyId}' from ${options.grantedActions.length} to ${retainedActions.length} actions (removing ${removedActions.length} unexercised actions: ${removedActions.join(', ')}). High observability confidence (${Math.round(
        confidenceScore * 100
      )}%).`,
      isProvisional: true,
    };
  }

  private static generatePolicyDiff(
    filePath: string,
    originalDoc: string,
    grantedActions: string[],
    retainedActions: string[]
  ): string {
    const originalLines = originalDoc.split('\n');
    const newLines: string[] = [];

    // Replace occurrences of unexercised actions
    const retainedSet = new Set(retainedActions);
    for (const line of originalLines) {
      let isRemovedLine = false;
      for (const granted of grantedActions) {
        if (!retainedSet.has(granted) && line.includes(granted)) {
          isRemovedLine = true;
          break;
        }
      }
      if (!isRemovedLine) {
        newLines.push(line);
      }
    }

    const modifiedDoc = newLines.join('\n');

    return [
      `--- a/${filePath}`,
      `+++ b/${filePath}`,
      `@@ -1,${originalLines.length} +1,${newLines.length} @@`,
      ...originalLines.map((l) => {
        const isRemoved = grantedActions.some((g) => !retainedSet.has(g) && l.includes(g));
        return isRemoved ? `-${l}` : ` ${l}`;
      }),
    ].join('\n');
  }
}
