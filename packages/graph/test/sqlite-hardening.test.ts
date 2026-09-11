import { describe, it, expect, afterEach } from 'vitest';
import { SqliteGraphStore } from '../src/stores/sqlite-graph-store.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Milestone 1.1: SQLite Concurrency & Migration Hardening', () => {
  let tempDbPath: string | null = null;

  afterEach(() => {
    if (tempDbPath && fs.existsSync(tempDbPath)) {
      try {
        fs.unlinkSync(tempDbPath);
      } catch {
        // ignore cleanup error
      }
      tempDbPath = null;
    }
  });

  it('creates _schema_migrations tracking table and records initial version', () => {
    const store = new SqliteGraphStore('test-tenant', ':memory:');
    const db = (store as any).db;

    const migrations = db.prepare('SELECT version, name FROM _schema_migrations ORDER BY version ASC').all();
    expect(migrations.length).toBeGreaterThanOrEqual(1);
    expect(migrations[0].version).toBe(1);
    expect(migrations[0].name).toBe('initial_graph_schema_v1');
    store.close();
  });

  it('sets pragma foreign_keys and busy_timeout correctly', () => {
    const store = new SqliteGraphStore('test-tenant', ':memory:');
    const db = (store as any).db;

    const fk = db.pragma('foreign_keys', { simple: true });
    expect(fk).toBe(1);

    const busyTimeout = db.pragma('busy_timeout', { simple: true });
    expect(busyTimeout).toBe(10000);
    store.close();
  });

  it('configures WAL journal mode and normal synchronous mode on file-backed database', () => {
    tempDbPath = path.join(os.tmpdir(), `sec-arch-hardening-test-${Date.now()}.db`);
    const store = new SqliteGraphStore('test-tenant', tempDbPath);
    const db = (store as any).db;

    const journalMode = db.pragma('journal_mode', { simple: true });
    expect(String(journalMode).toLowerCase()).toBe('wal');

    const synchronous = db.pragma('synchronous', { simple: true });
    expect(synchronous).toBe(1); // 1 = NORMAL in SQLite

    store.close();
  });
});
