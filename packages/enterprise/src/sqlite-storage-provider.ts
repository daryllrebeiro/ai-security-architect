import Database from 'better-sqlite3';
import type { AuditEntry, AuditStorageProvider } from './types.js';

export class SqliteAuditStorageProvider implements AuditStorageProvider {
  private readonly db: Database.Database;
  private readonly insertStmt: Database.Statement;
  private readonly lastEntryStmt: Database.Statement;
  private readonly queryStmt: Database.Statement;
  private readonly getAllStmt: Database.Statement;

  constructor(dbPath: string = ':memory:') {
    this.db = new Database(dbPath);

    // Enable WAL mode for high concurrency and write-ahead logging durability
    if (dbPath !== ':memory:') {
      this.db.pragma('journal_mode = WAL');
    }

    // Idempotent schema initialization
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS worm_audit_entries (
        id TEXT PRIMARY KEY,
        tenantId TEXT NOT NULL,
        userId TEXT NOT NULL,
        action TEXT NOT NULL,
        resourceId TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        details TEXT NOT NULL,
        previousHash TEXT NOT NULL,
        hash TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON worm_audit_entries (tenantId, timestamp);
    `);

    this.insertStmt = this.db.prepare(`
      INSERT INTO worm_audit_entries (
        id, tenantId, userId, action, resourceId, timestamp, details, previousHash, hash
      ) VALUES (
        @id, @tenantId, @userId, @action, @resourceId, @timestamp, @details, @previousHash, @hash
      )
    `);

    this.lastEntryStmt = this.db.prepare(`
      SELECT * FROM worm_audit_entries WHERE tenantId = ? ORDER BY rowid DESC LIMIT 1
    `);

    this.queryStmt = this.db.prepare(`
      SELECT * FROM worm_audit_entries WHERE tenantId = ? ORDER BY rowid ASC LIMIT ? OFFSET ?
    `);

    this.getAllStmt = this.db.prepare(`
      SELECT * FROM worm_audit_entries ORDER BY rowid ASC
    `);
  }

  public append(entry: AuditEntry): void {
    this.insertStmt.run({
      id: entry.id,
      tenantId: entry.tenantId,
      userId: entry.userId,
      action: entry.action,
      resourceId: entry.resourceId,
      timestamp: entry.timestamp,
      details: JSON.stringify(entry.details || {}),
      previousHash: entry.previousHash,
      hash: entry.hash,
    });
  }

  public getLastEntry(tenantId: string): AuditEntry | null {
    const row = this.lastEntryStmt.get(tenantId) as any;
    if (!row) return null;
    return this.mapRowToEntry(row);
  }

  public query(tenantId: string, limit: number = 1000, offset: number = 0): AuditEntry[] {
    const rows = this.queryStmt.all(tenantId, limit, offset) as any[];
    return rows.map((r) => this.mapRowToEntry(r));
  }

  public getAll(): AuditEntry[] {
    const rows = this.getAllStmt.all() as any[];
    return rows.map((r) => this.mapRowToEntry(r));
  }

  public close(): void {
    this.db.close();
  }

  private mapRowToEntry(row: any): AuditEntry {
    let details: Record<string, unknown> = {};
    try {
      details = JSON.parse(row.details);
    } catch {
      details = {};
    }

    return {
      id: row.id,
      tenantId: row.tenantId,
      userId: row.userId,
      action: row.action,
      resourceId: row.resourceId,
      timestamp: row.timestamp,
      details,
      previousHash: row.previousHash,
      hash: row.hash,
    };
  }
}
