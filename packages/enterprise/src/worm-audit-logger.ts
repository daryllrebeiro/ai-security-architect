import * as crypto from 'node:crypto';
import {
  AuditEntrySchema,
  type AuditEntry,
  type SecurityContext,
} from './types.js';

export const GENESIS_HASH = '0'.repeat(64);

export class WormAuditLogger {
  private readonly entries: AuditEntry[] = [];

  public log(
    context: SecurityContext,
    action: string,
    resourceId: string,
    details: Record<string, unknown> = {}
  ): AuditEntry {
    const tenantEntries = this.entries.filter((e) => e.tenantId === context.tenantId);
    const previousHash = tenantEntries.length > 0
      ? tenantEntries[tenantEntries.length - 1].hash
      : GENESIS_HASH;

    const id = `audit-${crypto.randomUUID()}`;
    const timestamp = new Date().toISOString();

    const hash = this.computeEntryHash({
      previousHash,
      tenantId: context.tenantId,
      userId: context.userId,
      action,
      resourceId,
      timestamp,
      details,
    });

    const entry: AuditEntry = {
      id,
      tenantId: context.tenantId,
      userId: context.userId,
      action,
      resourceId,
      timestamp,
      details,
      previousHash,
      hash,
    };

    AuditEntrySchema.parse(entry);
    this.entries.push(entry);
    return entry;
  }

  public getEntries(context: SecurityContext): AuditEntry[] {
    return this.entries.filter((e) => e.tenantId === context.tenantId);
  }

  public getAllEntries(): AuditEntry[] {
    return [...this.entries];
  }

  public computeEntryHash(params: {
    previousHash: string;
    tenantId: string;
    userId: string;
    action: string;
    resourceId: string;
    timestamp: string;
    details: Record<string, unknown>;
  }): string {
    const payload = [
      params.previousHash,
      params.tenantId,
      params.userId,
      params.action,
      params.resourceId,
      params.timestamp,
      JSON.stringify(params.details),
    ].join('|');

    return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
  }

  public verifyChainIntegrity(entries: AuditEntry[]): {
    isValid: boolean;
    brokenAtIndex?: number;
    reason?: string;
  } {
    if (entries.length === 0) {
      return { isValid: true };
    }

    for (let i = 0; i < entries.length; i++) {
      const current = entries[i];
      const expectedPrevHash = i === 0 ? GENESIS_HASH : entries[i - 1].hash;

      // 1. Verify previous hash chaining
      if (current.previousHash !== expectedPrevHash) {
        return {
          isValid: false,
          brokenAtIndex: i,
          reason: `Previous hash mismatch at index ${i}. Expected "${expectedPrevHash}", received "${current.previousHash}"`,
        };
      }

      // 2. Recompute and verify current record hash
      const recomputedHash = this.computeEntryHash({
        previousHash: current.previousHash,
        tenantId: current.tenantId,
        userId: current.userId,
        action: current.action,
        resourceId: current.resourceId,
        timestamp: current.timestamp,
        details: current.details,
      });

      if (current.hash !== recomputedHash) {
        return {
          isValid: false,
          brokenAtIndex: i,
          reason: `Cryptographic payload hash mismatch at index ${i}. Record was modified!`,
        };
      }
    }

    return { isValid: true };
  }
}
