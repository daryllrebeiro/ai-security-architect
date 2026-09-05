import type { Permission, SecurityContext } from './types.js';

export class TenantIsolationError extends Error {
  constructor(public readonly userTenantId: string, public readonly targetTenantId: string) {
    super(`[Multi-Tenancy Violation] Access denied: User tenant "${userTenantId}" cannot access resource belonging to tenant "${targetTenantId}"`);
    this.name = 'TenantIsolationError';
  }
}

export class AuthorizationPolicyError extends Error {
  constructor(public readonly action: Permission, public readonly reason: string) {
    super(`[Authorization Policy Violation] Cannot perform "${action}": ${reason}`);
    this.name = 'AuthorizationPolicyError';
  }
}

export interface AuthorizationPolicyRule {
  action: Permission;
  requiresTenantMatch?: boolean;
  allowCrossTenantWithScopes?: string[];
}

export class TenantGuard {
  private readonly policyRules: AuthorizationPolicyRule[] = [
    { action: 'scan:create', requiresTenantMatch: true },
    { action: 'scan:read', requiresTenantMatch: true },
    { action: 'scan:cancel', requiresTenantMatch: true },
    { action: 'graph:read', requiresTenantMatch: true },
    { action: 'remediation:apply', requiresTenantMatch: true, allowCrossTenantWithScopes: ['cross-tenant:admin'] },
    { action: 'audit:read', requiresTenantMatch: true },
    { action: 'audit:verify', requiresTenantMatch: true },
    { action: 'tenant:manage', requiresTenantMatch: true, allowCrossTenantWithScopes: ['cross-tenant:admin'] },
  ];

  public assertTenantAccess(context: SecurityContext, targetTenantId: string): void {
    const isSameTenant = context.tenantId === targetTenantId;
    const hasCrossTenantScope = context.scopes?.includes('cross-tenant:admin') ?? false;

    if (!isSameTenant && !hasCrossTenantScope) {
      throw new TenantIsolationError(context.tenantId, targetTenantId);
    }
  }

  public assertActionAccess(
    context: SecurityContext,
    action: Permission,
    resourceTenantId: string
  ): void {
    const rule = this.policyRules.find((item) => item.action === action);
    if (!rule) {
      throw new AuthorizationPolicyError(action, 'No policy rule registered for this action');
    }

    if (rule.requiresTenantMatch && context.tenantId !== resourceTenantId) {
      const allowedScopes = rule.allowCrossTenantWithScopes ?? [];
      const hasAllowedScope = allowedScopes.some((scope) => context.scopes.includes(scope));
      if (!hasAllowedScope) {
        throw new TenantIsolationError(context.tenantId, resourceTenantId);
      }
    }
  }

  public filterByTenant<T extends { tenantId: string }>(
    context: SecurityContext,
    items: T[]
  ): T[] {
    return items.filter((item) => {
      const isSameTenant = item.tenantId === context.tenantId;
      const hasCrossTenantScope = context.scopes?.includes('cross-tenant:admin') ?? false;
      return isSameTenant || hasCrossTenantScope;
    });
  }

  public enforceTenantScope<T extends { tenantId: string }>(
    context: SecurityContext,
    item: T
  ): T {
    this.assertTenantAccess(context, item.tenantId);
    return item;
  }
}
