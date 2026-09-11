export type ActionType = 'CLI_COMMAND' | 'IAC_PATCH' | 'POLICY_UPDATE' | 'MANUAL_STEP';

export type RemediationCategory = 'auto-patchable' | 'requires-runbook';

export interface RunbookStep {
  stepNumber: number;
  title: string;
  actionType: ActionType;
  commandOrSnippet: string;
  description: string;
}

export interface ChokePointDetail {
  edgeId: string;
  relationshipType: string;
  sourceAssetId: string;
  sourceAssetName: string;
  targetAssetId: string;
  targetAssetName: string;
  actionDescription: string;
}

export interface VerificationChecklistItem {
  fingerprint: string;
  description: string;
  verificationCommand: string;
}

export interface RemediationPlaybook {
  id: string;
  title: string;
  attackPathId: string;
  fingerprint?: string;
  severity: string;
  riskScore: number;
  category: RemediationCategory;
  owningTeam: string;
  chokePoint: ChokePointDetail;
  preFlightChecks: string[];
  executionSteps: RunbookStep[];
  rollbackSteps: string[];
  postVerificationQuery: string;
  verificationChecklist: VerificationChecklistItem[];
  disclaimer: string;
}

export interface PlaybookClassificationSummary {
  autoPatchable: string[];
  requiresRunbook: string[];
}
