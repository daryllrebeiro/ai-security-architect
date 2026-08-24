import type { UserRole, Permission, SecurityContext } from './types.js';

export class RbacAuthorizationError extends Error {
  constructor(public readonly requiredPermission: Permission, public readonly userRole: UserRole) {
    super(`[RBAC Access Denied] Role "${userRole}" lacks required permission: "${requiredPermission}"`);
    this.name = 'RbacAuthorizationError';
  }
}

export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  SECURITY_ADMIN: [
    'scan:create',
    'scan:read',
    'scan:cancel',
    'graph:read',
    'remediation:propose',
    'remediation:apply',
    'audit:read',
    'audit:verify',
    'tenant:manage',
  ],
  SECURITY_ENGINEER: [
    'scan:create',
    'scan:read',
    'scan:cancel',
    'graph:read',
    'remediation:propose',
    'remediation:apply',
    'audit:read',
  ],
  APP_ENGINEER: [
    'scan:read',
    'graph:read',
    'remediation:propose',
    'remediation:apply',
  ],
  AUDITOR: [
    'scan:read',
    'graph:read',
    'audit:read',
    'audit:verify',
  ],
  READ_ONLY: [
    'scan:read',
    'graph:read',
  ],
};

export class RbacManager {
  public getPermissionsForRole(role: UserRole): Permission[] {
    return ROLE_PERMISSIONS[role] || [];
  }

  public hasPermission(role: UserRole, permission: Permission): boolean {
    const permissions = this.getPermissionsForRole(role);
    return permissions.includes(permission);
  }

  public enforcePermission(context: SecurityContext, permission: Permission): void {
    if (!this.hasPermission(context.userRole, permission)) {
      throw new RbacAuthorizationError(permission, context.userRole);
    }
  }

  public createSecurityContext(tenantId: string, userId: string, role: UserRole): SecurityContext {
    return {
      tenantId,
      userId,
      userRole: role,
      permissions: this.getPermissionsForRole(role),
    };
  }
}
