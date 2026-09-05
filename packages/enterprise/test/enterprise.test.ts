import { describe, it, expect } from 'vitest';
import {
  RbacManager,
  RbacAuthorizationError,
  TenantGuard,
  TenantIsolationError,
  WormAuditLogger,
  GENESIS_HASH,
} from '../src/index.js';

describe('Phase 9 - Enterprise Governance, Multi-Tenancy & WORM Audit Logging', () => {
  describe('RBAC Authorization Matrix', () => {
    const rbac = new RbacManager();

    it('grants full operational and administrative permissions to SECURITY_ADMIN', () => {
      const adminCtx = rbac.createSecurityContext('tenant-acme', 'user-admin', 'SECURITY_ADMIN');
      expect(rbac.hasPermission(adminCtx.userRole, 'scan:create')).toBe(true);
      expect(rbac.hasPermission(adminCtx.userRole, 'remediation:apply')).toBe(true);
      expect(rbac.hasPermission(adminCtx.userRole, 'audit:verify')).toBe(true);
      expect(rbac.hasPermission(adminCtx.userRole, 'tenant:manage')).toBe(true);

      expect(() => rbac.enforcePermission(adminCtx, 'tenant:manage')).not.toThrow();
    });

    it('allows AUDITOR to inspect audit logs but blocks triggering scans', () => {
      const auditorCtx = rbac.createSecurityContext('tenant-acme', 'user-auditor', 'AUDITOR');
      expect(rbac.hasPermission(auditorCtx.userRole, 'audit:read')).toBe(true);
      expect(rbac.hasPermission(auditorCtx.userRole, 'audit:verify')).toBe(true);
      expect(rbac.hasPermission(auditorCtx.userRole, 'scan:create')).toBe(false);

      expect(() => rbac.enforcePermission(auditorCtx, 'scan:create')).toThrow(
        RbacAuthorizationError
      );
    });

    it('blocks READ_ONLY users from applying remediations', () => {
      const readOnlyCtx = rbac.createSecurityContext('tenant-acme', 'user-viewer', 'READ_ONLY');
      expect(rbac.hasPermission(readOnlyCtx.userRole, 'graph:read')).toBe(true);
      expect(rbac.hasPermission(readOnlyCtx.userRole, 'remediation:apply')).toBe(false);

      expect(() => rbac.enforcePermission(readOnlyCtx, 'remediation:apply')).toThrow(
        RbacAuthorizationError
      );
    });
  });

  describe('Multi-Tenancy RLS Guard', () => {
    const guard = new TenantGuard();
    const rbac = new RbacManager();
    const tenantACtx = rbac.createSecurityContext('tenant-alpha', 'user-1', 'SECURITY_ENGINEER');

    it('allows access to resources within the same tenant', () => {
      expect(() => guard.assertTenantAccess(tenantACtx, 'tenant-alpha')).not.toThrow();
    });

    it('throws TenantIsolationError when attempting cross-tenant access', () => {
      expect(() => guard.assertTenantAccess(tenantACtx, 'tenant-beta')).toThrow(
        TenantIsolationError
      );
    });

    it('allows explicit cross-tenant access when the policy grants a matching scope', () => {
      const scopedCtx = rbac.createSecurityContext('tenant-alpha', 'user-ops', 'SECURITY_ENGINEER', [
        'cross-tenant:admin',
      ]);

      expect(() => guard.assertTenantAccess(scopedCtx, 'tenant-beta')).not.toThrow();
    });

    it('filters collections to strictly isolate tenant entities', () => {
      const assets = [
        { id: 'asset-1', tenantId: 'tenant-alpha', name: 'Alpha Asset' },
        { id: 'asset-2', tenantId: 'tenant-beta', name: 'Beta Asset' },
        { id: 'asset-3', tenantId: 'tenant-alpha', name: 'Alpha Asset 2' },
      ];

      const filtered = guard.filterByTenant(tenantACtx, assets);
      expect(filtered).toHaveLength(2);
      expect(filtered.every((a) => a.tenantId === 'tenant-alpha')).toBe(true);
    });

    it('enforces action-level tenant policy for privileged resource access', () => {
      const scopedCtx = rbac.createSecurityContext('tenant-alpha', 'user-ops', 'SECURITY_ENGINEER', [
        'cross-tenant:admin',
      ]);

      expect(() => guard.assertActionAccess(scopedCtx, 'remediation:apply', 'tenant-beta')).not.toThrow();
      expect(() => guard.assertActionAccess(tenantACtx, 'remediation:apply', 'tenant-beta')).toThrow(
        TenantIsolationError
      );
    });
  });

  describe('Cryptographic WORM Audit Logger & Hash Chaining', () => {
    const rbac = new RbacManager();
    const ctx = rbac.createSecurityContext('tenant-enterprise-01', 'user-sec-lead', 'SECURITY_ADMIN');

    it('logs chained audit entries with genesis hash and valid SHA-256 signatures', () => {
      const logger = new WormAuditLogger();

      const e1 = logger.log(ctx, 'scan.initiated', 'job-101', { repository: 'org/order-service' });
      expect(e1.previousHash).toBe(GENESIS_HASH);
      expect(e1.hash).toBeDefined();
      expect(e1.hash).toHaveLength(64);

      const e2 = logger.log(ctx, 'finding.detected', 'finding-ssrf-01', { severity: 'CRITICAL' });
      expect(e2.previousHash).toBe(e1.hash);

      const e3 = logger.log(ctx, 'remediation.verified', 'path-001', { riskReduction: 100 });
      expect(e3.previousHash).toBe(e2.hash);

      const entries = logger.getEntries(ctx);
      expect(entries).toHaveLength(3);

      const integrity = logger.verifyChainIntegrity(entries);
      expect(integrity.isValid).toBe(true);
    });

    it('mathematically detects simulated tampering in the audit log', () => {
      const logger = new WormAuditLogger();

      logger.log(ctx, 'scan.initiated', 'job-201');
      logger.log(ctx, 'finding.detected', 'finding-iam-01');
      logger.log(ctx, 'pr.created', 'pr-301');

      const entries = logger.getEntries(ctx);
      expect(logger.verifyChainIntegrity(entries).isValid).toBe(true);

      // Simulate malicious tampering with record #1 details
      entries[1].details = { maliciousInjectedKey: true };

      const tamperedIntegrity = logger.verifyChainIntegrity(entries);
      expect(tamperedIntegrity.isValid).toBe(false);
      expect(tamperedIntegrity.brokenAtIndex).toBe(1);
    });
  });
});
