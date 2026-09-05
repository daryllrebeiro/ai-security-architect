import type { SecurityContext } from './types.js';

export class TenantIsolationError extends Error {
  constructor(public readonly userTenantId: string, public readonly targetTenantId: string) {
    super(`[Multi-Tenancy Violation] Access denied: User tenant "${userTenantId}" cannot access resource belonging to tenant "${targetTenantId}"`);
    this.name = 'TenantIsolationError';
  }
}

export class TenantGuard {
  public assertTenantAccess(context: SecurityContext, targetTenantId: string): void {
    const isSameTenant = context.tenantId === targetTenantId;
    const hasCrossTenantScope = context.scopes?.includes('cross-tenant:admin') ?? false;

    if (!isSameTenant && !hasCrossTenantScope) {
      throw new TenantIsolationError(context.tenantId, targetTenantId);
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
