import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import Database from 'better-sqlite3';
import {
  PersistentWormAuditLogger,
  SqliteAuditStorageProvider,
  GENESIS_HASH,
  type SecurityContext,
} from '../src/index.js';

describe('PersistentWormAuditLogger & SQLite Storage Provider', () => {
  const testDbPath = path.resolve('test-persistent-audit.db');

  const testContext: SecurityContext = {
    tenantId: 'tenant-enterprise-001',
    userId: 'sec-admin-01',
    userRole: 'SECURITY_ADMIN',
    permissions: ['audit:read', 'audit:verify'],
  };

  beforeEach(() => {
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  afterEach(() => {
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
    // Also remove WAL / SHM files if created
    if (fs.existsSync(`${testDbPath}-wal`)) fs.unlinkSync(`${testDbPath}-wal`);
    if (fs.existsSync(`${testDbPath}-shm`)) fs.unlinkSync(`${testDbPath}-shm`);
  });

  it('preserves audit trail and continues hash chain across simulated process restart', () => {
    // Process 1: First session
    const storage1 = new SqliteAuditStorageProvider(testDbPath);
    const logger1 = new PersistentWormAuditLogger(storage1);

    const entry1 = logger1.log(testContext, 'SCAN_TRIGGERED', 'repo-001', { scanner: 'sast' });
    expect(entry1.previousHash).toBe(GENESIS_HASH);

    const entry2 = logger1.log(testContext, 'FINDINGS_DETECTED', 'repo-001', { count: 3 });
    expect(entry2.previousHash).toBe(entry1.hash);

    logger1.close();

    // Process 2: Simulated process restart, reconnecting to the same disk file
    const storage2 = new SqliteAuditStorageProvider(testDbPath);
    const logger2 = new PersistentWormAuditLogger(storage2);

    const entriesBefore = logger2.getEntries(testContext);
    expect(entriesBefore.length).toBe(2);
    expect(entriesBefore[0].id).toBe(entry1.id);
    expect(entriesBefore[1].id).toBe(entry2.id);

    // Append new entry after restart
    const entry3 = logger2.log(testContext, 'REMEDIATION_APPLIED', 'repo-001', { patchId: 'p-01' });
    expect(entry3.previousHash).toBe(entry2.hash);

    // Verify entire chain integrity from disk
    const integrity = logger2.verifyChainIntegrity(testContext.tenantId);
    expect(integrity.isValid).toBe(true);

    logger2.close();
  });

  it('detects tampering when an attacker mutates a record directly in SQLite database', () => {
    const storage = new SqliteAuditStorageProvider(testDbPath);
    const logger = new PersistentWormAuditLogger(storage);

    logger.log(testContext, 'ACTION_1', 'res-1', { status: 'ok' });
    logger.log(testContext, 'ACTION_2', 'res-2', { status: 'sensitive' });
    logger.log(testContext, 'ACTION_3', 'res-3', { status: 'verified' });

    // Verify intact before tampering
    const beforeCheck = logger.verifyChainIntegrity(testContext.tenantId);
    expect(beforeCheck.isValid).toBe(true);

    logger.close();

    // Malicious actor tampers with record 2 directly via SQLite
    const rawDb = new Database(testDbPath);
    rawDb.prepare("UPDATE worm_audit_entries SET action = 'ACTION_TAMPERED' WHERE action = 'ACTION_2'").run();
    rawDb.close();

    // Auditor runs verification
    const auditorStorage = new SqliteAuditStorageProvider(testDbPath);
    const auditorLogger = new PersistentWormAuditLogger(auditorStorage);

    const auditResult = auditorLogger.verifyChainIntegrity(testContext.tenantId);
    expect(auditResult.isValid).toBe(false);
    expect(auditResult.brokenAtIndex).toBe(1);
    expect(auditResult.reason).toContain('Cryptographic payload hash mismatch');

    auditorLogger.close();
  });
});
