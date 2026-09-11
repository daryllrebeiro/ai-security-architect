export interface InferredPermissionUsage {
  action: string;
  service: string;
  callSignature: string;
  sourceFile: string;
  lineNumber: number;
}

export interface WorkloadObservabilityAnalysis {
  staticallyAnalyzedCallsCount: number;
  dynamicPatternsDetectedCount: number;
  observabilityScore: number; // 0.0 to 1.0
  hasDynamicDispatch: boolean;
  dynamicPatternExplanations: string[];
}

export interface PermissionInferenceResult {
  exercisedActions: string[];
  usageDetails: InferredPermissionUsage[];
  observability: WorkloadObservabilityAnalysis;
}

export interface PolicyRightSizingOptions {
  policyId: string;
  policyDocument: string; // e.g. Terraform HCL or JSON IAM policy
  policyFilePath: string;
  grantedActions: string[];
  minConfidenceThreshold?: number; // default 0.7
}

export interface PolicyRightSizingRecommendation {
  policyId: string;
  status: 'RECOMMENDED' | 'DECLINED_LOW_CONFIDENCE' | 'ALREADY_LEAST_PRIVILEGE';
  confidenceScore: number;
  grantedActionsCount: number;
  exercisedActionsCount: number;
  retainedActions: string[];
  removedActions: string[];
  unifiedDiff?: string;
  explanation: string;
  isProvisional: true; // Hardcoded true: always requires human review
}
