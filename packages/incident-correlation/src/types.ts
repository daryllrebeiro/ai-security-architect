import { Asset } from '@ai-security-architect/core';

export interface InboundSecurityAlert {
  alertId: string;
  sourceSystem: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  assetIdentifier: string; // ARN, instance-id, or exact name
  timestamp: string;
  description: string;
}

export const LIVE_INCIDENT_CONTEXT_LABEL =
  '(LIVE INCIDENT RESPONSE CONTEXT: Generated from real-time alert trigger, not a static scan finding)';

export interface BlastRadiusNode {
  assetId: string;
  name: string;
  type: string;
  isSensitive: boolean;
  criticality: string;
  hopsFromCompromise: number;
}

export interface LiveIncidentContext {
  alertId: string;
  sourceSystem: string;
  compromisedAssetId: string;
  compromisedAssetName: string;
  incidentTimestamp: string;
  ingressHops: number;
  ingressPaths: string[][];
  blastRadiusNodes: BlastRadiusNode[];
  criticalAssetsAtRisk: string[];
  recommendedChokePoints: Array<{
    sourceAssetId: string;
    targetAssetId: string;
    action: string;
  }>;
  contextLabel: string;
}

export interface IncidentResolutionSuccess {
  resolved: true;
  matchedAsset: Asset;
  incidentContext: LiveIncidentContext;
}

export interface IncidentResolutionFailure {
  resolved: false;
  status: 'REJECTED_AMBIGUOUS' | 'NOT_FOUND';
  reason: string;
}

export type IncidentCorrelationResult = IncidentResolutionSuccess | IncidentResolutionFailure;
