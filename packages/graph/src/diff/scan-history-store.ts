import Database from 'better-sqlite3';
import type { AttackPath, DiffClosureReason } from '@ai-security-architect/core';
import type { ClosedPathItem } from './path-diff-engine.js';

export interface ScanRecord {
  scanId: string;
  tenantId: string;
  repository: string;
  commitSha: string;
  timestamp: string;
  totalPaths: number;
  criticalPaths: number;
  highPaths: number;
  mediumPaths: number;
  lowPaths: number;
}

export interface AttackPathRecord {
  id: string;
  scanId: string;
  tenantId: string;
  repository: string;
  commitSha: string;
  fingerprint: string;
  severity: string;
  totalRisk: number;
  originAssetId: string;
  terminalAssetId: string;
  pathJson: string;
  timestamp: string;
}

export interface PathClosureRecord {
  fingerprint: string;
  scanId: string;
  repository: string;
  closedAt: string;
  closureReason: DiffClosureReason;
  originAssetId: string;
}

export class ScanHistoryStore {
  private readonly db: Database.Database;

  private readonly insertScanStmt: Database.Statement;
  private readonly insertPathStmt: Database.Statement;
  private readonly insertClosureStmt: Database.Statement;
  private readonly getScanStmt: Database.Statement;
  private readonly getScanPathsStmt: Database.Statement;
  private readonly getPathsByFingerprintStmt: Database.Statement;
  private readonly getAllScansStmt: Database.Statement;
  private readonly getClosuresStmt: Database.Statement;

  constructor(dbPath: string = ':memory:') {
    this.db = new Database(dbPath);
    if (dbPath !== ':memory:') {
      this.db.pragma('journal_mode = WAL');
    }

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scan_history (
        scan_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        repository TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        total_paths INTEGER NOT NULL,
        critical_paths INTEGER NOT NULL,
        high_paths INTEGER NOT NULL,
        medium_paths INTEGER NOT NULL,
        low_paths INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS attack_path_records (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        repository TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        severity TEXT NOT NULL,
        total_risk REAL NOT NULL,
        origin_asset_id TEXT NOT NULL,
        terminal_asset_id TEXT NOT NULL,
        path_json TEXT NOT NULL,
        timestamp TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS path_closures (
        fingerprint TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        repository TEXT NOT NULL,
        closed_at TEXT NOT NULL,
        closure_reason TEXT NOT NULL,
        origin_asset_id TEXT NOT NULL,
        PRIMARY KEY (fingerprint, scan_id)
      );

      CREATE INDEX IF NOT EXISTS idx_path_fingerprint ON attack_path_records (fingerprint);
      CREATE INDEX IF NOT EXISTS idx_scan_repo_time ON scan_history (repository, timestamp);
      CREATE INDEX IF NOT EXISTS idx_closure_repo ON path_closures (repository);
    `);

    this.insertScanStmt = this.db.prepare(`
      INSERT OR REPLACE INTO scan_history (
        scan_id, tenant_id, repository, commit_sha, timestamp,
        total_paths, critical_paths, high_paths, medium_paths, low_paths
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    this.insertPathStmt = this.db.prepare(`
      INSERT OR REPLACE INTO attack_path_records (
        id, scan_id, tenant_id, repository, commit_sha, fingerprint,
        severity, total_risk, origin_asset_id, terminal_asset_id, path_json, timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    this.insertClosureStmt = this.db.prepare(`
      INSERT OR REPLACE INTO path_closures (
        fingerprint, scan_id, repository, closed_at, closure_reason, origin_asset_id
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    this.getScanStmt = this.db.prepare(`SELECT * FROM scan_history WHERE scan_id = ?`);
    this.getScanPathsStmt = this.db.prepare(`SELECT * FROM attack_path_records WHERE scan_id = ?`);
    this.getPathsByFingerprintStmt = this.db.prepare(`SELECT * FROM attack_path_records WHERE fingerprint = ? ORDER BY timestamp ASC`);
    this.getAllScansStmt = this.db.prepare(`SELECT * FROM scan_history WHERE repository = ? ORDER BY timestamp ASC`);
    this.getClosuresStmt = this.db.prepare(`SELECT * FROM path_closures WHERE repository = ?`);
  }

  public recordScan(
    scanId: string,
    tenantId: string,
    repository: string,
    commitSha: string,
    paths: AttackPath[],
    timestamp: string = new Date().toISOString()
  ): void {
    let criticalPaths = 0;
    let highPaths = 0;
    let mediumPaths = 0;
    let lowPaths = 0;

    for (const p of paths) {
      const risk = p.riskScore.totalRisk;
      if (risk >= 9.0) criticalPaths++;
      else if (risk >= 7.0) highPaths++;
      else if (risk >= 4.0) mediumPaths++;
      else lowPaths++;
    }

    const tx = this.db.transaction(() => {
      this.insertScanStmt.run(
        scanId,
        tenantId,
        repository,
        commitSha,
        timestamp,
        paths.length,
        criticalPaths,
        highPaths,
        mediumPaths,
        lowPaths
      );

      for (const p of paths) {
        const severity =
          p.riskScore.totalRisk >= 9.0 ? 'CRITICAL' : p.riskScore.totalRisk >= 7.0 ? 'HIGH' : p.riskScore.totalRisk >= 4.0 ? 'MEDIUM' : 'LOW';
        const fp = p.fingerprint ?? 'unknown-fp';

        this.insertPathStmt.run(
          `${scanId}-${p.id}`,
          scanId,
          tenantId,
          repository,
          commitSha,
          fp,
          severity,
          p.riskScore.totalRisk,
          p.entryAssetId,
          p.targetAssetId,
          JSON.stringify(p),
          timestamp
        );
      }
    });

    tx();
  }

  public getScan(scanId: string): ScanRecord | null {
    const row = this.getScanStmt.get(scanId) as any;
    if (!row) return null;
    return {
      scanId: row.scan_id,
      tenantId: row.tenant_id,
      repository: row.repository,
      commitSha: row.commit_sha,
      timestamp: row.timestamp,
      totalPaths: row.total_paths,
      criticalPaths: row.critical_paths,
      highPaths: row.high_paths,
      mediumPaths: row.medium_paths,
      lowPaths: row.low_paths,
    };
  }

  public getScanPaths(scanId: string): AttackPath[] {
    const rows = this.getScanPathsStmt.all(scanId) as any[];
    return rows.map((r) => JSON.parse(r.path_json) as AttackPath);
  }

  public getPathsByFingerprint(fingerprint: string): AttackPathRecord[] {
    const rows = this.getPathsByFingerprintStmt.all(fingerprint) as any[];
    return rows.map((r) => ({
      id: r.id,
      scanId: r.scan_id,
      tenantId: r.tenant_id,
      repository: r.repository,
      commitSha: r.commit_sha,
      fingerprint: r.fingerprint,
      severity: r.severity,
      totalRisk: r.total_risk,
      originAssetId: r.origin_asset_id,
      terminalAssetId: r.terminal_asset_id,
      pathJson: r.path_json,
      timestamp: r.timestamp,
    }));
  }

  public getAllScans(repository: string): ScanRecord[] {
    const rows = this.getAllScansStmt.all(repository) as any[];
    return rows.map((row) => ({
      scanId: row.scan_id,
      tenantId: row.tenant_id,
      repository: row.repository,
      commitSha: row.commit_sha,
      timestamp: row.timestamp,
      totalPaths: row.total_paths,
      criticalPaths: row.critical_paths,
      highPaths: row.high_paths,
      mediumPaths: row.medium_paths,
      lowPaths: row.low_paths,
    }));
  }

  public recordClosures(
    scanId: string,
    repository: string,
    closures: ClosedPathItem[],
    timestamp: string = new Date().toISOString()
  ): void {
    const tx = this.db.transaction(() => {
      for (const c of closures) {
        this.insertClosureStmt.run(
          c.fingerprint,
          scanId,
          repository,
          timestamp,
          c.closureReason,
          c.originAssetId
        );
      }
    });
    tx();
  }

  public getClosures(repository: string): PathClosureRecord[] {
    const rows = this.getClosuresStmt.all(repository) as any[];
    return rows.map((r) => ({
      fingerprint: r.fingerprint,
      scanId: r.scan_id,
      repository: r.repository,
      closedAt: r.closed_at,
      closureReason: r.closure_reason,
      originAssetId: r.origin_asset_id,
    }));
  }

  public close(): void {
    this.db.close();
  }
}
