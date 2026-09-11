export type ChatPlatform = 'SLACK' | 'TEAMS';

export interface ChatMessageEvent {
  platform: ChatPlatform;
  channelId: string;
  userId: string;
  userEmail?: string;
  text: string;
  threadId?: string;
}

export interface ChatActionEvent {
  platform: ChatPlatform;
  actionId: 'approve_patch' | 'reject_patch';
  patchId: string;
  userId: string;
  userEmail?: string;
  channelId: string;
  triggerId?: string;
}

export interface ChatOpsConfig {
  tenantId: string;
  platform: ChatPlatform;
  defaultChannelId?: string;
  authorizedApprovers: string[]; // List of authorized userIds / emails
  signingSecret?: string;
}

export interface ChatMessageResponse {
  text: string;
  blocks?: unknown[];
  threadId?: string;
  ephemeral?: boolean;
}

export interface PatchApprovalResult {
  patchId: string;
  status: 'APPROVED' | 'REJECTED' | 'UNAUTHORIZED';
  actingUserId: string;
  timestamp: string;
  message: string;
}

export interface ChatOpsScanSummaryPayload {
  tenantId: string;
  repository: string;
  commitSha: string;
  branch: string;
  attackPathsCount: number;
  topRiskScore: number;
  criticalAssetsAtRisk: string[];
  recommendedChokePoint?: string;
  timestamp: string;
}

