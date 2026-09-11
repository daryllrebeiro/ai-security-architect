import { z } from 'zod';

export const UserRoleSchema = z.enum([
  'SECURITY_ADMIN',
  'SECURITY_ENGINEER',
  'APP_ENGINEER',
  'AUDITOR',
  'READ_ONLY',
]);

export type UserRole = z.infer<typeof UserRoleSchema>;

export const PermissionSchema = z.enum([
  'scan:create',
  'scan:read',
  'scan:cancel',
  'graph:read',
  'remediation:propose',
  'remediation:apply',
  'audit:read',
  'audit:verify',
  'tenant:manage',
]);

export type Permission = z.infer<typeof PermissionSchema>;

export const SecurityContextSchema = z.object({
  tenantId: z.string().min(1),
  userId: z.string().min(1),
  userRole: UserRoleSchema,
  permissions: z.array(PermissionSchema).default([]),
  scopes: z.array(z.string()).default([]),
});

export type SecurityContext = z.infer<typeof SecurityContextSchema>;

export const AuditEntrySchema = z.object({
  id: z.string().min(1),
  tenantId: z.string().min(1),
  userId: z.string().min(1),
  action: z.string().min(1),
  resourceId: z.string().min(1),
  timestamp: z.string().datetime(),
  details: z.record(z.unknown()).default({}),
  previousHash: z.string(),
  hash: z.string(),
});

export type AuditEntry = z.infer<typeof AuditEntrySchema>;

export interface AuditStorageProvider {
  append(entry: AuditEntry): void;
  getLastEntry(tenantId: string): AuditEntry | null;
  query(tenantId: string, limit?: number, offset?: number): AuditEntry[];
  getAll(): AuditEntry[];
  close?(): void;
}

export const WebhookDestinationTypeSchema = z.enum([
  'SLACK',
  'TEAMS',
  'JIRA',
  'GENERIC_SIEM',
  'GITHUB_PR_COMMENT',
  'GITLAB_PR_COMMENT',
]);
export type WebhookDestinationType = z.infer<typeof WebhookDestinationTypeSchema>;

export const WebhookDestinationSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  type: WebhookDestinationTypeSchema,
  url: z.string().url(),
  authToken: z.string().optional(),
  headers: z.record(z.string()).optional(),
  enabled: z.boolean().default(true),
  minRiskThreshold: z.number().min(0).max(10).default(7.0),
});
export type WebhookDestination = z.infer<typeof WebhookDestinationSchema>;

export interface DispatchPayload {
  tenantId: string;
  repository: string;
  attackPathId: string;
  riskScore: number;
  entryPoint: string;
  targetAsset: string;
  stepsSummary: string[];
  recommendedAction?: string;
  timestamp?: string;
  prCommentBody?: string;
  prNumber?: number;
}

export interface DispatchResult {
  destinationId: string;
  destinationType: WebhookDestinationType;
  success: boolean;
  attempts: number;
  statusCode?: number;
  error?: string;
  timestamp: string;
}
