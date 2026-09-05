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
